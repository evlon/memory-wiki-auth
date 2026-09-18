"""
HiMarket 凭据同步 —— 消除「手工 seed 凭据」这个最大短板

═══════════════════════════════════════════════════════════════════════════════
为什么需要它
═══════════════════════════════════════════════════════════════════════════════

当前 `dim_credential` 是**手工 seed** 的：
    新用户在 HiMarket 注册后，必须有人手工把 (apikey → consumer_id)
    写进 dim_credential，否则他的请求会被 validator 判为"未登记"→ 拒绝。

这是**最大的可用性短板**。

═══════════════════════════════════════════════════════════════════════════════
同步源
═══════════════════════════════════════════════════════════════════════════════

HiMarket 的 MySQL（`portal_db`）里有两张表：

    consumer_credential
      consumer_id | apikey_config (JSON)
      apikey_config 结构：{"credentials":[{"apiKey":"apikey-xxx"}]}

    consumer
      consumer_id | developer_id | name

    developer
      developer_id | username | email
      （username 形如 corp-sso_niukunliang）

⚠️ 本模块**只读** HiMarket 库，不做任何写入。
⚠️ 通过 asyncpg 连不上 MySQL，所以走 Hindsight 侧的 HTTP 接口：
   由管理 API 的 /ext/credentials 接收同步结果，
   而**抓取 HiMarket 的动作**由外部脚本/定时任务完成。

设计取舍：
    · 方案 A：在 Hindsight 进程内直连 HiMarket MySQL
      → 需引入 MySQL 驱动（Hindsight 镜像里没有），且耦合两个库
    · 方案 B（本实现）：提供**导入接口**，由外部把 HiMarket 数据 POST 进来
      → 解耦、可用现有 mysql2（纯 JS）/ mysql 客户端
    · 方案 C：外部脚本直接写 wiki_auth 库（同库不同 schema）

本模块实现方案 B 的**接收端**（解析 + 幂等 upsert），
抓取端见 `k8s/scripts/sync-himarket-creds.sh`。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .store import DimAuthStore

logger = logging.getLogger(__name__)


@dataclass
class CredSyncResult:
    """同步结果（供管理 API 返回）。"""

    received: int = 0
    upserted: int = 0
    skipped: int = 0
    errors: list[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "received": self.received,
            "upserted": self.upserted,
            "skipped": self.skipped,
            "errors": self.errors,
        }


def parse_himarket_apikey(apikey_config: Any) -> str | None:
    """
    从 HiMarket 的 apikey_config JSON 里提取 apiKey。

    ⚠️ 实测结构（portal_db.consumer_credential）：
        {"credentials": [{"apiKey": "apikey-1b83...", ...}], ...}
        {"apiKey": "apikey-xxx"}          ← 兼容单对象写法
        直接是字符串                        ← 兼容

    返回 None 表示结构不认识（跳过，不猜测）。
    """
    if apikey_config is None:
        return None

    if isinstance(apikey_config, str):
        s = apikey_config.strip()
        if s.startswith("apikey-"):
            return s
        return None

    if isinstance(apikey_config, dict):
        # 形式 1：{"credentials": [{"apiKey": ...}]}
        creds = apikey_config.get("credentials")
        if isinstance(creds, list) and creds:
            first = creds[0]
            if isinstance(first, dict):
                for key in ("apiKey", "api_key", "key"):
                    v = first.get(key)
                    if isinstance(v, str) and v.startswith("apikey-"):
                        return v
            elif isinstance(first, str) and first.startswith("apikey-"):
                return first
        # 形式 2：{"apiKey": ...}
        for key in ("apiKey", "api_key", "key", "value"):
            v = apikey_config.get(key)
            if isinstance(v, str) and v.startswith("apikey-"):
                return v
    return None


def parse_is_primary(v: Any) -> bool:
    """
    解析 HiMarket 的 is_primary 标记。

    HiMarket 存的是 tinyint：1 = 主账号（真人），NULL/0 = 系统账号。

    ⚠️ 安全取向：**认不出就当作"非主账号"**。
       宁可少归并（可用性问题，能发现），不可多归并（越权，难发现）。
    """
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v == 1
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes")
    return False


async def sync_credentials(
    store: DimAuthStore,
    rows: list[dict[str, Any]],
    *,
    actor: str = "himarket-sync",
) -> CredSyncResult:
    """
    把 HiMarket 的 consumer 列表同步进 dim_credential。

    期望每行结构（由抓取端提供）：
        {
          "consumer_id": "consumer-a8238936...",
          "developer_id": "dev-9fa771...",     # 可选
          "username": "corp-sso_niukunliang",  # 可选
          "is_primary": 1,                     # ⭐ 可选，是否绑定自然人
          "apikey_config": {...}               # HiMarket 原始 JSON
        }

    ⚠️ `is_primary` 决定该 consumer 是否参与「身份别名归并」：
        1/true  → 与 username 归到同一人（真人账号）
        其他    → 独立成组（系统账号，如 ai-llm）
       **缺省按"非主账号"处理**（宁可少归并，不可多归并 —— 后者会越权）。

    ⚠️ 幂等：同一 apikey 重复同步只更新，不重复插入。
    ⚠️ 认不出的行**跳过并记录**，不猜测（避免写入错误凭据）。
    """
    result = CredSyncResult(received=len(rows))

    for i, row in enumerate(rows):
        try:
            consumer_id = (row.get("consumer_id") or "").strip()
            if not consumer_id.startswith("consumer-"):
                result.skipped += 1
                result.errors.append(f"第{i}行 consumer_id 非法：{consumer_id[:40]}")
                continue

            api_key = parse_himarket_apikey(row.get("apikey_config"))
            if not api_key:
                result.skipped += 1
                result.errors.append(f"第{i}行无法解析 apikey（consumer={consumer_id[:32]}）")
                continue

            await store.upsert_credential(
                api_key=api_key,
                consumer_id=consumer_id,
                developer_id=row.get("developer_id"),
                username=row.get("username"),
                is_primary=parse_is_primary(row.get("is_primary")),
            )
            result.upserted += 1

        except Exception as e:
            result.skipped += 1
            result.errors.append(f"第{i}行异常：{type(e).__name__}: {e}")
            logger.exception("[wiki-auth] 凭据同步单行失败")

    logger.info(
        "[wiki-auth] 凭据同步完成（by %s）：收到=%d 写入=%d 跳过=%d",
        actor, result.received, result.upserted, result.skipped,
    )
    return result

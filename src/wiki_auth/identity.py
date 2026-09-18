"""
身份解析 —— 从请求里认出"这是谁"

⚠️ 安全铁律（本文件是安全关键路径）：

1. **认不出就是认不出** —— 返回 None，绝不"降级为匿名"或"默认放行"。
   调用方（validator）拿到 None 必须拒绝请求。

2. **两种身份来源，优先级明确**：
     ① 可信代理透传的身份头（`x-dim-consumer`，需在
        HINDSIGHT_API_EXTENSION_PASSTHROUGH_HEADERS 里显式开启）
        —— 适用于 HiMarket 直接调用（它知道用户是谁）
     ② apikey → consumer 映射（查 dim_credential 表）
        —— 适用于第三方客户端带 apikey 直连

3. **不做模糊匹配** —— apikey 必须精确命中；不做前缀/正则猜测。

4. **不记完整凭据** —— 日志里只出现脱敏前缀。
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# 透传头名（与 HINDSIGHT_API_EXTENSION_PASSTHROUGH_HEADERS 保持一致）
HEADER_CONSUMER = "x-dim-consumer"
HEADER_USERNAME = "x-dim-username"

# apikey 形状（HiMarket 格式）
_APIKEY_RE = re.compile(r"^apikey-[0-9a-f]{16,64}$", re.IGNORECASE)

# 不记完整凭据：只留前 12 位 + 长度
def mask_secret(s: str | None) -> str:
    if not s:
        return "(空)"
    if len(s) <= 12:
        return f"{s[:4]}***(len={len(s)})"
    return f"{s[:12]}***(len={len(s)})"


@dataclass(frozen=True)
class Identity:
    """已识别的调用方身份。"""

    consumer_id: str
    username: str | None = None
    developer_id: str | None = None
    source: str = "apikey"  # apikey | header

    def __str__(self) -> str:
        return f"{self.consumer_id}({self.username or '-'},via={self.source})"


def extract_api_key(request_context) -> str | None:
    """
    从 RequestContext 提取 apikey。

    RequestContext.api_key 由 Hindsight 的 HTTP 层从 Authorization 头解析
    （"Bearer xxx" 已剥掉前缀）。
    """
    raw = getattr(request_context, "api_key", None)
    if not raw:
        return None
    raw = raw.strip()
    # 兼容调用方把 "Bearer " 一起塞进来的情况
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    return raw or None


async def resolve_identity(request_context, credential_lookup) -> Identity | None:
    """
    解析身份。返回 None 表示**无法识别** —— 调用方必须拒绝。

    Args:
        request_context: Hindsight 的 RequestContext
        credential_lookup: async callable(api_key) -> (consumer_id, username, developer_id) | None

    Returns:
        Identity 或 None（无法识别）
    """
    if request_context is None:
        logger.warning("[wiki-auth] 身份解析失败：RequestContext 为空")
        return None

    # ── 来源 ①：可信代理透传的身份头（优先）──────────────────────────────────
    extra = getattr(request_context, "extra_headers", None) or {}
    hdr_consumer = (extra.get(HEADER_CONSUMER) or "").strip()
    if hdr_consumer:
        if not _valid_consumer_id(hdr_consumer):
            logger.warning("[wiki-auth] 透传头 consumer 格式非法：%s", hdr_consumer[:64])
            return None
        ident = Identity(
            consumer_id=hdr_consumer,
            username=(extra.get(HEADER_USERNAME) or None),
            source="header",
        )
        logger.debug("[wiki-auth] 身份来自透传头：%s", ident)
        return ident

    # ── 来源 ②：apikey → consumer 映射 ───────────────────────────────────────
    api_key = extract_api_key(request_context)
    if not api_key:
        logger.warning("[wiki-auth] 身份解析失败：既无透传头也无 apikey")
        return None

    if not _APIKEY_RE.match(api_key):
        # ⚠️ 形状不对直接拒 —— 不查表（防注入 + 防暴力枚举）
        logger.warning("[wiki-auth] apikey 形状非法：%s", mask_secret(api_key))
        return None

    row = await credential_lookup(api_key)
    if row is None:
        logger.warning("[wiki-auth] apikey 未登记：%s", mask_secret(api_key))
        return None

    consumer_id, username, developer_id = row
    if not _valid_consumer_id(consumer_id):
        logger.warning("[wiki-auth] 登记表中的 consumer_id 非法：%s", consumer_id[:64])
        return None

    ident = Identity(
        consumer_id=consumer_id,
        username=username,
        developer_id=developer_id,
        source="apikey",
    )
    logger.debug("[wiki-auth] 身份来自 apikey：%s", ident)
    return ident


def _valid_consumer_id(cid: str) -> bool:
    """
    consumer_id 形状校验。

    真实格式：consumer-<32位hex>
    ⚠️ 只做形状校验，**存在性由授权表决定**（不在授权表 = 无权限）。
    """
    return bool(re.match(r"^consumer-[0-9a-f]{16,64}$", cid, re.IGNORECASE))


def fingerprint(api_key: str | None) -> str:
    """凭据指纹（用于日志关联，不可逆）。"""
    if not api_key:
        return "-"
    return hashlib.sha256(api_key.encode()).hexdigest()[:12]

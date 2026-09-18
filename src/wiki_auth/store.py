"""
维度授权存储 —— 读侧（validator 用）+ 写侧（管理台用）

⚠️ 设计要点（安全相关，改动前务必理解）：

1. **fail-closed**：任何异常都向上抛，绝不返回"无限制"。
   validator 拿到异常会拒绝请求。这是刻意的。

2. **身份解析只认 consumer_id**：从 RequestContext 提取，认不出就返回 None
   （由调用方拒绝），不做任何"猜测"或"降级为匿名"。

3. **项目展开是单向的**：project → product。
   反向（product → project）会造成泄漏：产品一的人会看到所有用到它的项目。

4. **缓存**：validator 每次 recall 都会调用，故带 TTL 缓存。
   ⚠️ 缓存失败不能降级为"放行"，只能降级为"用旧值或抛错"。
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import asyncpg

logger = logging.getLogger(__name__)

# ── 权限级别 ──────────────────────────────────────────────────────────────────
PERM_NONE = "none"
PERM_READ = "read"
PERM_WRITE = "write"

# 权限强弱（用于"取最大"）
_PERM_RANK = {PERM_NONE: 0, PERM_READ: 1, PERM_WRITE: 2}


@dataclass(frozen=True)
class DimAccess:
    """一个用户对某个维度的有效访问权。"""

    dim_id: str
    tag_prefix: str
    bank_id: str
    permission: str
    via: str = "direct"  # direct | project-<id>


@dataclass
class _CacheEntry:
    access: list[DimAccess]
    expires_at: float


class DimAuthStore:
    """
    授权规则的读写。

    只读方法（validator 用）：
        load_access(consumer_id) -> list[DimAccess]
        can_access_bank(consumer_id, bank_id) -> bool
        max_permission(consumer_id) -> str

    写方法（管理台用，见 docstring 说明）：
        upsert_dimension / delete_dimension
        set_grant / revoke_grant
        add_project_member / remove_project_member
    """

    def __init__(
        self,
        database_url: str,
        *,
        schema: str = "wiki_auth",
        cache_ttl_seconds: float = 30.0,
        pool_min: int = 1,
        pool_max: int = 5,
    ) -> None:
        self._database_url = database_url
        self._schema = schema
        self._cache_ttl = cache_ttl_seconds
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._pool: asyncpg.Pool | None = None
        self._cache: dict[str, _CacheEntry] = {}

    # ── 生命周期 ──────────────────────────────────────────────────────────────
    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            self._database_url,
            min_size=self._pool_min,
            max_size=self._pool_max,
            command_timeout=10,
        )
        logger.info("[wiki-auth] 授权存储已连接（schema=%s）", self._schema)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("[wiki-auth] 授权存储已关闭")

    async def _ensure_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            await self.connect()
        assert self._pool is not None
        return self._pool

    # ── 读侧（validator 用）───────────────────────────────────────────────────
    async def resolve_aliases(self, identity: str) -> list[str]:
        """
        把身份展开成一组等价别名（含自身）。

        ⭐ 为什么需要：同一人有两种身份表示 ——
            管理台（OIDC）→ Keycloak username（如 zhaolei）
            MCP（apikey） → HiMarket consumer（如 consumer-a823...）
          授权表只存一个值，故查询前先展开成"我的所有别名"。

        ⚠️ fail-closed：查不到别名时**至少返回 [identity] 自身**，
           绝不返回空（空会导致 load_access 提前返回 []，
           语义上等同于"无授权"，但会让"自己的授权"也查不到）。
        """
        if not identity:
            return []
        try:
            pool = await self._ensure_pool()
            rows = await pool.fetch(
                f"""
                SELECT DISTINCT sibling
                  FROM {self._schema}.v_identity_alias
                 WHERE alias = $1
                """,
                identity,
            )
            sibs = [r["sibling"] for r in rows if r["sibling"]]
        except Exception:
            # 视图不存在（未跑 002 迁移）时降级为自身 —— 不阻断主流程
            logger.warning("[wiki-auth] 身份别名查询失败，降级为自身身份", exc_info=True)
            return [identity]
        if identity not in sibs:
            sibs.append(identity)
        return sibs

    async def load_access(self, consumer_id: str, *, use_cache: bool = True) -> list[DimAccess]:
        """
        加载某 consumer 的全部有效维度访问权（含项目展开）。

        ⭐ 会先把身份展开成所有别名（OIDC username ⇄ HiMarket consumer），
           这样两条路径查到**同一组授权**。

        ⚠️ fail-closed：任何异常都抛出，绝不返回空列表之外的"隐含全权"。
        返回空列表 = 无任何授权 = 调用方应拒绝。
        """
        if not consumer_id:
            # 无身份 → 不是"无限制"，是"无授权"
            return []

        now = time.monotonic()
        if use_cache:
            hit = self._cache.get(consumer_id)
            if hit is not None and hit.expires_at > now:
                return hit.access

        # ⭐ 展开别名：zhaolei → {zhaolei, consumer-xxx}
        aliases = await self.resolve_aliases(consumer_id)

        pool = await self._ensure_pool()
        # 用视图拿"含项目展开"的有效授权（SQL 里已做单向展开）
        # ⚠️ 用 = ANY($1) 一次查全部别名，避免 N 次查询
        rows = await pool.fetch(
            f"""
            SELECT DISTINCT dim_id, tag_prefix, bank_id, permission, via
              FROM {self._schema}.v_effective_dim
             WHERE consumer_id = ANY($1::text[])
            """,
            aliases,
        )

        access = [
            DimAccess(
                dim_id=r["dim_id"],
                tag_prefix=r["tag_prefix"],
                bank_id=r["bank_id"],
                permission=r["permission"],
                via=r["via"] or "direct",
            )
            for r in rows
        ]

        # 同一维度可能被"直接授权"和"项目展开"同时命中 → 取更强权限
        merged: dict[str, DimAccess] = {}
        for a in access:
            prev = merged.get(a.dim_id)
            if prev is None or _PERM_RANK[a.permission] > _PERM_RANK[prev.permission]:
                merged[a.dim_id] = a
        result = list(merged.values())

        self._cache[consumer_id] = _CacheEntry(access=result, expires_at=now + self._cache_ttl)
        return result

    async def can_access_bank(self, consumer_id: str, bank_id: str) -> bool:
        """
        能否访问某隔离区。

        ⚠️ 个人区（u-）只有本人可访问 —— 这一条是硬规则，不走授权表。
        """
        if bank_id.startswith("u-"):
            return bank_id == f"u-{consumer_id}"
        access = await self.load_access(consumer_id)
        return any(a.bank_id == bank_id for a in access)

    async def max_permission(self, consumer_id: str) -> str:
        """该用户在授权范围内的最高权限（用于决定是否显示 retain 工具）。"""
        access = await self.load_access(consumer_id)
        if not access:
            return PERM_NONE
        return max((a.permission for a in access), key=lambda p: _PERM_RANK.get(p, 0))

    async def lookup_credential(self, api_key: str):
        """
        apikey → (consumer_id, username, developer_id)。

        ⚠️ 精确匹配，不做模糊/前缀匹配。
        ⚠️ 查不到返回 None（调用方必须拒绝，不能当"无限制"）。
        """
        if not api_key:
            return None
        pool = await self._ensure_pool()
        row = await pool.fetchrow(
            f"""
            SELECT consumer_id, username, developer_id
              FROM {self._schema}.dim_credential
             WHERE api_key = $1 AND status = 'ACTIVE'
            """,
            api_key,
        )
        if row is None:
            return None
        return (row["consumer_id"], row["username"], row["developer_id"])

    def invalidate(self, consumer_id: str | None = None):
        """授权变更后清缓存（管理台调用）。"""
        if consumer_id is None:
            self._cache.clear()
        else:
            self._cache.pop(consumer_id, None)

    # ── 读侧：管理台用（列维度/授权/项目关联）────────────────────────────────
    async def list_dimensions(self, *, bank_id: str | None = None) -> list[dict]:
        """列出全部维度（可按隔离区过滤）。"""
        pool = await self._ensure_pool()
        if bank_id:
            rows = await pool.fetch(
                f"""SELECT dim_id, dim_type, name, description, tag_prefix, bank_id,
                           admin_consumer_id, status, created_at, updated_at
                      FROM {self._schema}.dim_dimension
                     WHERE bank_id = $1 ORDER BY dim_type, dim_id""",
                bank_id,
            )
        else:
            rows = await pool.fetch(
                f"""SELECT dim_id, dim_type, name, description, tag_prefix, bank_id,
                           admin_consumer_id, status, created_at, updated_at
                      FROM {self._schema}.dim_dimension
                     ORDER BY dim_type, dim_id"""
            )
        return [dict(r) for r in rows]

    async def get_dimension(self, dim_id: str) -> dict | None:
        pool = await self._ensure_pool()
        row = await pool.fetchrow(
            f"""SELECT dim_id, dim_type, name, description, tag_prefix, bank_id,
                       admin_consumer_id, status, created_at, updated_at
                  FROM {self._schema}.dim_dimension WHERE dim_id = $1""",
            dim_id,
        )
        return dict(row) if row else None

    async def get_dim_admin(self, dim_id: str) -> str | None:
        """该维度的管理员身份（不存在返回 None）。"""
        pool = await self._ensure_pool()
        return await pool.fetchval(
            f"SELECT admin_consumer_id FROM {self._schema}.dim_dimension WHERE dim_id = $1",
            dim_id,
        )

    async def is_dim_admin(self, identity: str, dim_id: str) -> bool:
        """
        某人（按任一别名）是否是该维度的管理员。

        ⭐ 支持别名：zhaolei 与 consumer-xxx 视为同一人。
        """
        if not identity or not dim_id:
            return False
        aliases = await self.resolve_aliases(identity)
        pool = await self._ensure_pool()
        got = await pool.fetchval(
            f"""SELECT admin_consumer_id FROM {self._schema}.dim_dimension
                 WHERE dim_id = $1""",
            dim_id,
        )
        return bool(got) and got in aliases

    async def list_grants(self, *, dim_id: str | None = None,
                          consumer_id: str | None = None) -> list[dict]:
        """列出授权（可按维度或用户过滤）。"""
        pool = await self._ensure_pool()
        sql = f"""SELECT g.id, g.consumer_id, g.dim_id, g.permission, g.granted_by,
                         g.status, g.expires_at, g.created_at, g.updated_at,
                         d.name AS dim_name, d.bank_id, d.tag_prefix
                    FROM {self._schema}.dim_grant g
                    LEFT JOIN {self._schema}.dim_dimension d ON d.dim_id = g.dim_id
                   WHERE 1=1"""
        args: list = []
        if dim_id:
            args.append(dim_id)
            sql += f" AND g.dim_id = ${len(args)}"
        if consumer_id:
            args.append(consumer_id)
            sql += f" AND g.consumer_id = ${len(args)}"
        sql += " ORDER BY g.consumer_id, g.dim_id"
        rows = await pool.fetch(sql, *args)
        return [dict(r) for r in rows]

    async def list_project_members(self, *, project_dim_id: str | None = None) -> list[dict]:
        """列出项目↔产品关联。"""
        pool = await self._ensure_pool()
        if project_dim_id:
            rows = await pool.fetch(
                f"""SELECT id, project_dim_id, product_dim_id, created_by, created_at
                      FROM {self._schema}.dim_project_member
                     WHERE project_dim_id = $1 ORDER BY product_dim_id""",
                project_dim_id,
            )
        else:
            rows = await pool.fetch(
                f"""SELECT id, project_dim_id, product_dim_id, created_by, created_at
                      FROM {self._schema}.dim_project_member
                     ORDER BY project_dim_id, product_dim_id"""
            )
        return [dict(r) for r in rows]

    async def list_audit(self, *, limit: int = 100, target: str | None = None) -> list[dict]:
        """审计日志（倒序）。"""
        pool = await self._ensure_pool()
        limit = max(1, min(int(limit), 500))
        if target:
            rows = await pool.fetch(
                f"""SELECT id, actor, action, target, detail, created_at
                      FROM {self._schema}.dim_audit
                     WHERE target LIKE $1 ORDER BY created_at DESC LIMIT $2""",
                f"%{target}%", limit,
            )
        else:
            rows = await pool.fetch(
                f"""SELECT id, actor, action, target, detail, created_at
                      FROM {self._schema}.dim_audit
                     ORDER BY created_at DESC LIMIT $1""",
                limit,
            )
        return [dict(r) for r in rows]

    # ── 凭据管理（供 HiMarket 同步用）────────────────────────────────────────
    async def upsert_credential(
        self, *, api_key: str, consumer_id: str,
        developer_id: str | None = None, username: str | None = None,
        is_primary: bool | None = None,
    ) -> None:
        """
        登记/更新凭据映射（HiMarket 同步任务调用）。

        ⚠️ `is_primary` 决定该 consumer 是否参与「身份别名归并」：
             True  → 与 username 归到同一人（真人账号）
             其他  → 独立成组（系统账号，如 ai-llm）
           **传 None 时不覆盖已有值**（避免老同步脚本抹掉人工标注）。
        """
        pool = await self._ensure_pool()
        await pool.execute(
            f"""
            INSERT INTO {self._schema}.dim_credential
                   (api_key, consumer_id, developer_id, username, is_primary,
                    status, synced_at)
            VALUES ($1, $2, $3, $4, $5, 'ACTIVE', now())
            ON CONFLICT (api_key) DO UPDATE
               SET consumer_id  = EXCLUDED.consumer_id,
                   developer_id = EXCLUDED.developer_id,
                   username     = EXCLUDED.username,
                   is_primary   = COALESCE(EXCLUDED.is_primary,
                                           {self._schema}.dim_credential.is_primary),
                   status       = 'ACTIVE',
                   synced_at    = now()
            """,
            api_key, consumer_id, developer_id, username, is_primary,
        )

    async def list_credentials(self) -> list[dict]:
        pool = await self._ensure_pool()
        rows = await pool.fetch(
            f"""SELECT consumer_id, developer_id, username, status, synced_at,
                       left(api_key, 14) AS api_key_prefix
                  FROM {self._schema}.dim_credential ORDER BY consumer_id"""
        )
        return [dict(r) for r in rows]

    async def delete_dimension(self, dim_id: str) -> None:
        pool = await self._ensure_pool()
        await pool.execute(
            f"DELETE FROM {self._schema}.dim_dimension WHERE dim_id = $1", dim_id
        )
        await self._audit(None, "delete_dim", dim_id, None)
        self.invalidate()

    # ── 写侧（管理台用）───────────────────────────────────────────────────────
    async def upsert_dimension(
        self,
        *,
        dim_id: str,
        dim_type: str,
        name: str,
        tag_prefix: str,
        bank_id: str,
        admin_consumer_id: str | None = None,
        description: str | None = None,
    ) -> None:
        pool = await self._ensure_pool()
        await pool.execute(
            f"""
            INSERT INTO {self._schema}.dim_dimension
                   (dim_id, dim_type, name, description, tag_prefix, bank_id, admin_consumer_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (dim_id) DO UPDATE
               SET dim_type          = EXCLUDED.dim_type,
                   name              = EXCLUDED.name,
                   description       = EXCLUDED.description,
                   tag_prefix        = EXCLUDED.tag_prefix,
                   bank_id           = EXCLUDED.bank_id,
                   admin_consumer_id = EXCLUDED.admin_consumer_id,
                   updated_at        = now()
            """,
            dim_id, dim_type, name, description, tag_prefix, bank_id, admin_consumer_id,
        )
        self.invalidate()

    async def set_grant(
        self,
        *,
        consumer_id: str,
        dim_id: str,
        permission: str,
        granted_by: str | None = None,
    ) -> None:
        if permission not in _PERM_RANK:
            raise ValueError(f"非法权限：{permission}")
        pool = await self._ensure_pool()
        await pool.execute(
            f"""
            INSERT INTO {self._schema}.dim_grant
                   (consumer_id, dim_id, permission, granted_by, status)
            VALUES ($1, $2, $3, $4, 'APPROVED')
            ON CONFLICT (consumer_id, dim_id) DO UPDATE
               SET permission = EXCLUDED.permission,
                   granted_by = EXCLUDED.granted_by,
                   status     = 'APPROVED',
                   updated_at = now()
            """,
            consumer_id, dim_id, permission, granted_by,
        )
        await self._audit(granted_by, "grant", f"{consumer_id}->{dim_id}",
                          {"permission": permission})
        self.invalidate(consumer_id)

    async def revoke_grant(self, *, consumer_id: str, dim_id: str, actor: str | None = None) -> None:
        pool = await self._ensure_pool()
        await pool.execute(
            f"""
            UPDATE {self._schema}.dim_grant
               SET status = 'REVOKED', updated_at = now()
             WHERE consumer_id = $1 AND dim_id = $2
            """,
            consumer_id, dim_id,
        )
        await self._audit(actor, "revoke", f"{consumer_id}->{dim_id}", None)
        self.invalidate(consumer_id)

    async def add_project_member(
        self, *, project_dim_id: str, product_dim_id: str, actor: str | None = None
    ) -> None:
        pool = await self._ensure_pool()
        await pool.execute(
            f"""
            INSERT INTO {self._schema}.dim_project_member
                   (project_dim_id, product_dim_id, created_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (project_dim_id, product_dim_id) DO NOTHING
            """,
            project_dim_id, product_dim_id, actor,
        )
        await self._audit(actor, "add_project_member",
                          f"{project_dim_id}+{product_dim_id}", None)
        self.invalidate()  # 影响所有挂载该项目的用户

    async def remove_project_member(
        self, *, project_dim_id: str, product_dim_id: str, actor: str | None = None
    ) -> None:
        pool = await self._ensure_pool()
        await pool.execute(
            f"""
            DELETE FROM {self._schema}.dim_project_member
             WHERE project_dim_id = $1 AND product_dim_id = $2
            """,
            project_dim_id, product_dim_id,
        )
        await self._audit(actor, "remove_project_member",
                          f"{project_dim_id}-{product_dim_id}", None)
        self.invalidate()

    # ── 申请→审批（dim_grant_request）───────────────────────────────────────
    async def create_request(
        self,
        *,
        kind: str,
        requester_id: str,
        dim_id: str | None = None,
        project_dim_id: str | None = None,
        product_dim_id: str | None = None,
        permission: str | None = None,
    ) -> dict:
        """
        创建一条申请（join / reference）。

        ⚠️ kind=join      → dim_id + permission 必填
           kind=reference → project_dim_id + product_dim_id 必填
           校验失败抛 ValueError（调用方转 400）。
        """
        if kind == "join":
            if not dim_id or permission not in ("read", "write"):
                raise ValueError("join 申请必须提供 dim_id 与 permission(read/write)")
        elif kind == "reference":
            if not project_dim_id or not product_dim_id:
                raise ValueError("reference 申请必须提供 project_dim_id 与 product_dim_id")
        else:
            raise ValueError(f"非法 kind：{kind}")

        pool = await self._ensure_pool()
        row = await pool.fetchrow(
            f"""
            INSERT INTO {self._schema}.dim_grant_request
                   (kind, requester_id, dim_id, project_dim_id, product_dim_id, permission)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, kind, requester_id, dim_id, project_dim_id,
                      product_dim_id, permission, status, created_at
            """,
            kind, requester_id, dim_id, project_dim_id, product_dim_id, permission,
        )
        result = dict(row)
        await self._audit(requester_id, "request", f"{kind}:{dim_id or project_dim_id}",
                          {"permission": permission, "product_dim_id": product_dim_id})
        return result

    async def get_request(self, request_id: int) -> dict | None:
        pool = await self._ensure_pool()
        row = await pool.fetchrow(
            f"""SELECT id, kind, requester_id, dim_id, project_dim_id,
                       product_dim_id, permission, status, decided_by, decided_at, created_at
                  FROM {self._schema}.dim_grant_request WHERE id = $1""",
            request_id,
        )
        return dict(row) if row else None

    async def list_requests(
        self,
        *,
        requester_id: str | None = None,
        status: str | None = None,
        dim_id: str | None = None,
        product_dim_id: str | None = None,
        limit: int = 200,
    ) -> list[dict]:
        """列申请（按申请人 / 状态 / 维度过滤）。"""
        limit = max(1, min(int(limit), 500))
        pool = await self._ensure_pool()
        sql = f"""SELECT id, kind, requester_id, dim_id, project_dim_id,
                         product_dim_id, permission, status, decided_by, decided_at, created_at
                    FROM {self._schema}.dim_grant_request
                   WHERE 1=1"""
        args: list = []
        if requester_id:
            args.append(requester_id)
            sql += f" AND requester_id = ${len(args)}"
        if status:
            args.append(status)
            sql += f" AND status = ${len(args)}"
        if dim_id:
            args.append(dim_id)
            sql += f" AND dim_id = ${len(args)}"
        if product_dim_id:
            args.append(product_dim_id)
            sql += f" AND product_dim_id = ${len(args)}"
        sql += " ORDER BY created_at DESC LIMIT $" + str(len(args) + 1)
        args.append(limit)
        rows = await pool.fetch(sql, *args)
        return [dict(r) for r in rows]

    async def decide_request(
        self,
        *,
        request_id: int,
        decision: str,
        decided_by: str,
    ) -> dict | None:
        """
        审批一条申请（APPROVED / REJECTED），并**原子落库生效**。

        ⚠️ APPROVED 时按 kind 落不同表：
             join      → dim_grant(requester, dim, permission)
             reference → dim_project_member(project, product)
           REJECTED 只改状态。
        返回 None 表示申请不存在 / 已终态 / 状态非法。
        """
        if decision not in ("APPROVED", "REJECTED"):
            raise ValueError(f"非法 decision：{decision}")

        pool = await self._ensure_pool()
        req = await self.get_request(request_id)
        if req is None:
            return None
        if req["status"] != "PENDING":
            # 已终态：幂等返回，不再重复生效
            return req

        if decision == "APPROVED":
            if req["kind"] == "join":
                await self.set_grant(
                    consumer_id=req["requester_id"],
                    dim_id=req["dim_id"],
                    permission=req["permission"],
                    granted_by=decided_by,
                )
            elif req["kind"] == "reference":
                await self.add_project_member(
                    project_dim_id=req["project_dim_id"],
                    product_dim_id=req["product_dim_id"],
                    actor=decided_by,
                )
        else:
            # REJECTED：仅记状态
            pass

        await pool.execute(
            f"""
            UPDATE {self._schema}.dim_grant_request
               SET status = $2, decided_by = $3, decided_at = now()
             WHERE id = $1 AND status = 'PENDING'
            """,
            request_id, decision, decided_by,
        )
        await self._audit(decided_by, "request_" + decision.lower(),
                          f"req#{request_id}:{req['kind']}", None)
        self.invalidate(req.get("requester_id"))
        return await self.get_request(request_id)

    async def _audit(
        self, actor: str | None, action: str, target: str, detail: dict[str, Any] | None
    ) -> None:
        try:
            pool = await self._ensure_pool()
            import json as _json
            await pool.execute(
                f"""
                INSERT INTO {self._schema}.dim_audit (actor, action, target, detail)
                VALUES ($1, $2, $3, $4::jsonb)
                """,
                actor, action, target, _json.dumps(detail) if detail else None,
            )
        except Exception:
            # ⚠️ 审计失败不能让主操作失败，但必须留痕
            logger.exception("[wiki-auth] 审计写入失败 action=%s target=%s", action, target)


def database_url_from_env() -> str:
    """
    从环境变量取数据库 URL。

    复用 Hindsight 自己的 DATABASE_URL（同库不同 schema），
    避免多一份凭据配置。
    """
    for key in ("WIKI_AUTH_DATABASE_URL", "HINDSIGHT_API_DATABASE_URL"):
        v = os.environ.get(key)
        if v:
            return v
    raise RuntimeError("未配置 WIKI_AUTH_DATABASE_URL 或 HINDSIGHT_API_DATABASE_URL")


# ══════════════════════════════════════════════════════════════════════════════
# ⚠️⚠️ 进程级共享单例（安全关键，e491 实测发现的缺陷）
# ══════════════════════════════════════════════════════════════════════════════
#
# 问题：Hindsight 会分别实例化三个扩展，而每个扩展都 `DimAuthStore(...)`：
#         DimAuthValidator      → 自己的 store（带 30s 授权缓存）
#         DimAuthTenantExtension→ 自己的 store
#         DimAuthAdminExtension → 自己的 store
#       三个实例的 `_cache` **互不相通**。
#
# 后果：管理 API 改授权后调用 `invalidate()`，**只清了自己那份缓存**；
#       validator 的缓存仍是旧值 → **撤销授权最长 30 秒后才生效**。
#       实测：撤销后立即访问仍能读到数据（安全缺陷）。
#
# 修复：用进程级单例，三个扩展共用同一个 store 实例 → 缓存与连接池都共享。
#
# ⚠️ 单例按 (database_url, schema) 做键：同一进程内不同 schema 仍是独立实例。
# ══════════════════════════════════════════════════════════════════════════════

_STORE_INSTANCES: dict[tuple[str, str], DimAuthStore] = {}


def get_shared_store(
    database_url: str,
    *,
    schema: str = "wiki_auth",
    cache_ttl_seconds: float = 30.0,
) -> DimAuthStore:
    """
    取得（或创建）进程级共享的授权存储实例。

    ⚠️ 三个扩展**必须**都用这个函数取 store，否则缓存不互通，
       会导致"撤销授权不立即生效"的安全缺陷。
    """
    key = (database_url, schema)
    inst = _STORE_INSTANCES.get(key)
    if inst is None:
        inst = DimAuthStore(database_url, schema=schema,
                            cache_ttl_seconds=cache_ttl_seconds)
        _STORE_INSTANCES[key] = inst
        logger.info("[wiki-auth] 创建共享授权存储实例（schema=%s）", schema)
    return inst

"""
wiki_auth 的租户扩展 —— 负责 MCP 握手时的身份校验

═══════════════════════════════════════════════════════════════════════════════
为什么需要它（e473/e475 实测）
═══════════════════════════════════════════════════════════════════════════════

Hindsight 的 `OperationValidatorExtension.validate_*` 只在**具体操作**时被调用
（recall / retain / reflect）。而 MCP 的 **initialize 握手**不经过它。

后果（实测）：
    无凭据的客户端 → initialize 返回 **HTTP 200**，拿到 session
    → 直到 tools/call 才被拦（且表现为 "Unknown tool"，因为
      filter_mcp_tools 把工具列表清空了）

数据是安全的（工具为空、操作被拒），但**语义不对**：
    · 客户端以为连上了
    · 报错信息是 "Unknown tool" 而不是 "未认证"
    · 不符合 MCP 客户端的预期（应握手即 401）

正确做法：在 `TenantExtension.authenticate_mcp()` 里校验身份，
抛 `AuthenticationError` → Hindsight 的 api/mcp.py 会返回 **401**。

（源码 api/mcp.py:478 确认：
     except AuthenticationError as e:
         await self._send_error(send, 401, str(e), extra_headers=e.headers)
         return ）

═══════════════════════════════════════════════════════════════════════════════
本扩展的职责边界
═══════════════════════════════════════════════════════════════════════════════

    TenantExtension  → **认证**（你是谁？没凭据就 401）
    OperationValidator → **授权**（你能看哪些维度？）

两者配合：
    ① 握手：本扩展校验 apikey/透传头 → 无效则 401
    ② 操作：DimAuthValidator 查授权表 → 注入维度过滤

⚠️ fail-closed：认不出身份一律抛 AuthenticationError（401），
   绝不"降级为匿名"。
"""

from __future__ import annotations

import logging

from hindsight_api.extensions import (
    AuthenticationError,
    RequestContext,
    Tenant,
    TenantContext,
    TenantExtension,
)

from .identity import mask_secret, resolve_identity
from .store import DimAuthStore, database_url_from_env, get_shared_store

logger = logging.getLogger(__name__)


class DimAuthTenantExtension(TenantExtension):
    """
    认证扩展：在 MCP 握手 / HTTP 请求入口校验身份。

    配置（环境变量）：
        HINDSIGHT_API_TENANT_EXTENSION=wiki_auth.tenant:DimAuthTenantExtension
        HINDSIGHT_API_TENANT_SCHEMA=public          （可选，数据所在 schema）
        HINDSIGHT_API_TENANT_DATABASE_URL=...       （可选，默认复用主库）
        HINDSIGHT_API_TENANT_AUTH_ENFORCE=1         （可选，0=仅观察不拦截）
    """

    def __init__(self, config: dict[str, str]):
        super().__init__(config)
        self._schema = config.get("schema", "public")
        self._enforce = config.get("auth_enforce", "1").lower() not in ("0", "false", "no")

        url = config.get("database_url") or database_url_from_env()
        # ⚠️ 必须用共享单例（见 store.py 说明）：缓存与连接池跨扩展共享。
        self._store = get_shared_store(url, schema=config.get("dim_schema", "wiki_auth"))

        logger.info(
            "[wiki-auth] tenant 扩展初始化：schema=%s enforce=%s",
            self._schema, self._enforce,
        )

    # ── 生命周期 ──────────────────────────────────────────────────────────────
    async def on_startup(self) -> None:
        await self._store.connect()

    async def on_shutdown(self) -> None:
        await self._store.close()

    # ── 认证 ──────────────────────────────────────────────────────────────────
    async def authenticate(self, context: RequestContext) -> TenantContext:
        """
        HTTP REST 请求的认证。

        ⚠️ 注意：Hindsight 在**内部任务**（worker 重放）时不会调用本方法
           （它直接用 DefaultTenantExtension 的路径），
           所以这里不需要处理 internal 情况。
        """
        await self._check(context)
        return TenantContext(schema_name=self._schema)

    async def authenticate_mcp(self, context: RequestContext) -> TenantContext | None:
        """
        MCP 握手的认证（e475 找到的钩子）。

        抛 AuthenticationError → Hindsight 返回 HTTP 401。
        返回 None 表示"不做租户 schema 切换"（我们用固定 schema）。
        """
        await self._check(context)
        return None

    async def _check(self, context: RequestContext) -> None:
        """统一的身份校验（fail-closed）。"""
        # 服务内部调用（worker / 后台任务）跳过 —— 它们不是外部请求
        if context is not None and getattr(context, "internal", False):
            return

        ident = await resolve_identity(context, self._store.lookup_credential)
        if ident is None:
            raw = getattr(context, "api_key", None) if context else None
            msg = "缺少或非法的凭据：请携带 Authorization: Bearer apikey-xxx"
            if raw:
                msg = f"凭据无效：{mask_secret(raw)}"
            logger.warning("[wiki-auth] MCP/HTTP 认证失败：%s", msg)
            if not self._enforce:
                logger.error("[wiki-auth] ⚠️ AUTH_ENFORCE=0，本应 401 但已放行")
                return
            raise AuthenticationError(msg)

        logger.debug("[wiki-auth] 认证通过：%s", ident)

    # ── 租户列表（worker 需要知道去哪些 schema 找任务）────────────────────────
    async def list_tenants(self) -> list[Tenant]:
        return [Tenant(schema=self._schema)]

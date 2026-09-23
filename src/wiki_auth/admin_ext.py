"""
HttpExtension 实现 —— 把管理 API 挂到 Hindsight 的 /ext/ 下

═══════════════════════════════════════════════════════════════════════════════
为什么用 HttpExtension（而不是新建独立服务）
═══════════════════════════════════════════════════════════════════════════════

Hindsight 官方扩展点 `HttpExtension.get_router()` 允许在**同一进程内**
挂载自定义 FastAPI 路由（前缀 `/ext`）。

好处：
    · 不用新建服务、不用新镜像、不用新部署
    · 复用 Hindsight 的数据库连接池
    · 与 validator/tenant 扩展同生共死（生命周期一致）

代价：
    ⚠️ `/ext/` 路由**没有框架级认证**（源码 http.py:4124 挂载时无依赖）
       → 必须在每个端点上显式依赖 AdminAuth（已做）

═══════════════════════════════════════════════════════════════════════════════
启用方式
═══════════════════════════════════════════════════════════════════════════════

    HINDSIGHT_API_HTTP_EXTENSION=wiki_auth.admin_ext:DimAuthAdminExtension
    WIKI_AUTH_ADMIN_TOKEN=<平台管理员令牌>

挂载后：
    GET  http://<host>:8888/ext/whoami
    GET  http://<host>:8888/ext/dims
    ...
"""

from __future__ import annotations

import logging

from fastapi import APIRouter
from hindsight_api.extensions import HttpExtension

from .admin_api import build_admin_router
from .oidc import OidcClient
from .store import DimAuthStore, database_url_from_env, get_shared_store

logger = logging.getLogger(__name__)


class DimAuthAdminExtension(HttpExtension):
    """
    维度授权管理 API 扩展。

    配置（环境变量）：
        HINDSIGHT_API_HTTP_EXTENSION=wiki_auth.admin_ext:DimAuthAdminExtension
        HINDSIGHT_API_HTTP_DATABASE_URL=...      （可选，默认复用主库）
        HINDSIGHT_API_HTTP_DIM_SCHEMA=wiki_auth   （可选）

        ⭐ OIDC 登录（推荐）：
        WIKI_OIDC_ISSUER=http://auth.example.com/realms/employees
        WIKI_OIDC_CLIENT_ID=wiki-portal
        WIKI_OIDC_CLIENT_SECRET=<secret>
        WIKI_OIDC_REDIRECT_URI=http://wiki.example.com/ext/oauth/callback
        WIKI_OIDC_SESSION_KEY=<签名会话 cookie 的密钥>
        WIKI_ADMIN_USERS=niukunliang,xxx          （平台管理员名单）

        令牌方式（兼容脚本/CLI）：
        WIKI_AUTH_ADMIN_TOKEN=<令牌>
    """

    def __init__(self, config: dict[str, str]):
        super().__init__(config)
        self._dim_schema = config.get("dim_schema", "wiki_auth")
        url = config.get("database_url") or database_url_from_env()
        # ⚠️ 必须用共享单例：这样管理 API 的 invalidate() 能清到
        #    validator 的缓存，撤销授权立即生效（见 store.py 说明）。
        self._store = get_shared_store(url, schema=self._dim_schema)

        # ⭐ OIDC 客户端（用 Keycloak 登录，替代自造令牌）
        self._oidc = OidcClient(config)

        logger.info("[wiki-auth] 管理 API 扩展初始化：dim_schema=%s oidc=%s",
                    self._dim_schema, "启用" if self._oidc.enabled else "未启用")

    async def on_startup(self) -> None:
        await self._store.connect()
        if self._oidc.enabled:
            try:
                d = await self._oidc.discovery()
                logger.info("[wiki-auth] OIDC discovery OK：issuer=%s", d.get("issuer"))
            except Exception:
                logger.exception("[wiki-auth] ⚠️ OIDC discovery 失败（登录可能不可用）")
        logger.info("[wiki-auth] 管理 API 已就绪（挂在 /ext/）")

    async def on_shutdown(self) -> None:
        await self._store.close()

    def get_router(self, memory) -> APIRouter:
        """
        返回管理路由。

        ⚠️ Hindsight 会把它挂到 `/ext` 前缀下，
           且**不施加任何认证** —— 认证由 build_admin_router 内部依赖完成。
        """
        router = build_admin_router(self._store, oidc=self._oidc)
        logger.info("[wiki-auth] 管理 API 路由已构造")
        return router

    def get_root_router(self, memory) -> APIRouter:
        """
        根路径路由（挂在**应用根**，不是 /ext）—— Hindsight 官方扩展点。

        ══════════════════════════════════════════════════════════════════════
        为什么需要它
        ══════════════════════════════════════════════════════════════════════

        用户期望**输入的网址尽可能短**：

            http://wiki.ai.ict.cmcc/          ← 想访问的（短）
            http://wiki.ai.ict.cmcc/ext/      ← 管理台真实路径（长）

        而「后台调用的接口放子目录」是合理直觉 —— `/ext/*` 正是那些 API。
        所以这里只做一件事：把根路径 **302 到 /ext/**，
        让用户少打字符，同时 API 仍留在 /ext 子目录下。

        ══════════════════════════════════════════════════════════════════════
        ⚠️ 边界（重要）
        ══════════════════════════════════════════════════════════════════════

        · 这里**只做重定向**，不暴露任何管理端点。
          所有认证/授权逻辑仍在 /ext 下（build_admin_router）。
        · 不在这里返回管理界面 HTML —— 否则界面里的**相对路径** fetch
          （admin_ui.html 用 `fetch('whoami')`）会解析到 `/whoami` 而非
          `/ext/whoami`，接口全 404。重定向后浏览器停在 /ext/，相对路径才正确。
        """
        from fastapi import Response
        from fastapi.responses import RedirectResponse

        router = APIRouter()

        @router.get("/", include_in_schema=False)
        async def root_to_console():
            """根路径 → 管理台（短网址入口）。"""
            return RedirectResponse(url="/ext/", status_code=302)

        @router.get("/favicon.ico", include_in_schema=False)
        async def favicon():
            """浏览器默认请求图标；返回 204，避免落到 Hindsight 的 404。"""
            return Response(status_code=204)

        logger.info("[wiki-auth] 根路由已构造（/ → 302 /ext/）")
        return router

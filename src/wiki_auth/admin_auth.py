"""
管理 API 的认证与鉴权

═══════════════════════════════════════════════════════════════════════════════
⚠️ 安全前提（e487 实测）
═══════════════════════════════════════════════════════════════════════════════

Hindsight 把 HttpExtension 的路由挂在 `/ext/` 时：

    app.include_router(extension_router, prefix="/ext", tags=["Extension"])

**没有任何认证依赖** —— 也就是说 `/ext/*` 是**完全公开**的。
（对比：业务路由走 TenantExtension 认证，而 /ext/ 绕过了它。）

所以**管理 API 必须自己做认证**，否则任何人都能改授权。

═══════════════════════════════════════════════════════════════════════════════
本模块的认证设计
═══════════════════════════════════════════════════════════════════════════════

两级身份：

    ① 平台管理员（PLATFORM ADMIN）
       持有 WIKI_AUTH_ADMIN_TOKEN（环境变量）
       → 可做任何操作（建维度、指定管理员、兜底）

    ② 维度管理员（DIMENSION ADMIN）
       持有普通 HiMarket apikey
       → 只能管自己负责的维度（dim_dimension.admin_consumer_id = 自己）

⚠️ fail-closed：认不出身份一律 401；无权操作一律 403。
⚠️ 令牌比较用恒定时间（防时序侧信道）。
"""

from __future__ import annotations

import hmac
import logging
import os

from fastapi import Cookie, Header, HTTPException, status

from .identity import Identity, mask_secret, resolve_identity
from .store import DimAuthStore

logger = logging.getLogger(__name__)


class AdminAuth:
    """
    管理 API 的认证器。

    用法（FastAPI 依赖）：
        auth = AdminAuth(store)
        @router.get("/dims")
        async def list_dims(ident: Identity = Depends(auth.require_admin)):
            ...
    """

    def __init__(self, store: DimAuthStore, admin_token: str | None = None,
                 oidc: "OidcClient | None" = None,
                 admin_users: str | None = None):
        self._store = store
        self._oidc = oidc
        # ⚠️ 未配置则管理 API 整体禁用（fail-closed），不是放行
        self._admin_token = admin_token if admin_token is not None \
            else (os.environ.get("WIKI_AUTH_ADMIN_TOKEN") or "")
        # 平台管理员用户名列表（Keycloak username，逗号分隔）
        # ⚠️ 显式传参优先（包括空串）—— 避免测试/多实例间互相干扰
        raw_users = admin_users if admin_users is not None \
            else (os.environ.get("WIKI_ADMIN_USERS") or "")
        self._admin_users = {u.strip() for u in raw_users.split(",") if u.strip()}
        if not self._admin_token:
            logger.warning(
                "[wiki-auth] ⚠️ 未配置 WIKI_AUTH_ADMIN_TOKEN —— 令牌方式将不可用"
            )
        if self._oidc and self._oidc.enabled:
            logger.info("[wiki-auth] 平台管理员（Keycloak 用户名）: %s",
                        sorted(self._admin_users) or "（未配置）")

    # ── 内部工具 ──────────────────────────────────────────────────────────────
    @staticmethod
    def _extract_bearer(authorization: str | None) -> str | None:
        if not authorization:
            return None
        v = authorization.strip()
        if v.lower().startswith("bearer "):
            v = v[7:].strip()
        return v or None

    def _is_platform_admin(self, token: str | None) -> bool:
        """
        恒定时间比较平台管理员令牌。

        ⚠️ 未配置令牌时**永远返回 False**（fail-closed），
           不能让"没配令牌"变成"人人都是管理员"。
        """
        if not self._admin_token or not token:
            return False
        return hmac.compare_digest(token, self._admin_token)

    def _is_admin_user(self, username: str | None, roles: list[str] | None = None) -> bool:
        """
        判断用户是否为 Wiki 管理员。

        ⭐ 主判定：Keycloak 角色 `wiki-admin`（标准角色授权，取代名单）。
        ⚠️ 兼容回退：若未携带角色（旧令牌/无 realm_access.roles），
           则回退到 WIKI_ADMIN_USERS 名单（逐步废弃）。
        """
        if roles:
            if "wiki-admin" in roles:
                return True
        if not username:
            return False
        return username.strip().lower() in {u.lower() for u in self._admin_users}

    def identity_from_session(self, user) -> tuple[Identity, bool]:
        """
        把 OIDC 会话用户转成 Identity。

        ⚠️ 关键：`consumer_id` 用 **Keycloak username**（如 niukunliang），
           而不是 HiMarket 的 consumer-xxx —— 因为 OIDC 路径拿不到 consumer。
           授权表（dim_dimension.admin_consumer_id / dim_grant.consumer_id）
           需相应支持 username。
        """
        ident = Identity(
            consumer_id=user.username,
            username=user.username,
            source="oidc",
        )
        roles = getattr(user, "roles", None) or []
        return ident, self._is_admin_user(user.username, roles)

    async def _resolve(self, authorization: str | None) -> tuple[Identity | None, bool]:
        """
        返回 (身份, 是否平台管理员)。

        ⚠️ 平台管理员令牌**不是** apikey，不会走 dim_credential 查表。
        """
        token = self._extract_bearer(authorization)

        # ① 平台管理员
        if self._is_platform_admin(token):
            return Identity(consumer_id="platform-admin", username="platform-admin",
                            source="admin-token"), True

        # ② 普通用户（维度管理员候选）—— 用 apikey 解析
        if not token:
            return None, False

        class _Ctx:
            api_key = token
            extra_headers: dict[str, str] = {}
            internal = False

        ident = await resolve_identity(_Ctx(), self._store.lookup_credential)
        return ident, False

    # ── FastAPI 依赖 ──────────────────────────────────────────────────────────
    async def _identity_from_gateway(self, authorization: str | None,
                                     x_fwd_access_token: str | None,
                                     ) -> tuple[Identity, bool] | None:
        """
        从 Higress oidc 插件注入的头解析身份（统一认证层主路径）。

        Higress oidc 插件（标准 OIDC）认证后注入：
          · Authorization: Bearer <IDToken>          （pass_authorization_header）
          · X-Forwarded-Access-Token: <access token> （pass_access_token）

        ⭐ 角色在 access token（realm_access.roles），故优先读
           X-Forwarded-Access-Token；无则回退 Authorization 里的 IDToken。

        ⚠️ 必须验签：网关注入的头**不是信任边界**，任何直连后端的人都能伪造。
           故用 OidcClient.verify_access_token / verify_id_token 验签。
        """
        if not (self._oidc and self._oidc.enabled):
            return None
        try:
            if x_fwd_access_token:
                user = await self._oidc.verify_access_token(x_fwd_access_token)
                return self.identity_from_session(user)
            bearer = self._extract_bearer(authorization)
            if bearer:
                user = await self._oidc.verify_id_token(bearer)
                return self.identity_from_session(user)
        except Exception as e:
            logger.warning("[wiki-auth] 网关令牌验签失败：%s", e)
            return None
        return None

    async def require_identity(
        self,
        authorization: str | None = Header(default=None),
        wiki_session: str | None = Cookie(default=None),
        x_forwarded_access_token: str | None = Header(default=None, alias="X-Forwarded-Access-Token"),
    ) -> tuple[Identity, bool]:
        """
        要求已认证。

        ⭐ 三种身份来源（优先级）：
          ① 网关 oidc 插件注入的令牌（X-Forwarded-Access-Token / Authorization）
             —— 统一认证层主路径（标准 OIDC）
          ② OIDC 会话 cookie（应用层 OIDC，兼容旧路径）
          ③ Authorization: Bearer <apikey 或管理令牌>（脚本/CLI）
        """
        # ① 网关注入的令牌（统一认证层）
        gw = await self._identity_from_gateway(authorization, x_forwarded_access_token)
        if gw is not None:
            return gw

        # ② OIDC 会话 cookie
        if self._oidc and self._oidc.enabled and wiki_session:
            user = self._oidc.read_session(wiki_session)
            if user is not None:
                return self.identity_from_session(user)

        # ③ 退回 Bearer
        ident, is_admin = await self._resolve(authorization)
        if ident is None:
            logger.warning("[wiki-auth] 管理 API 认证失败：%s", mask_secret(
                self._extract_bearer(authorization)))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="未认证：请登录，或携带 Authorization: Bearer <apikey 或管理令牌>",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return ident, is_admin

    async def require_platform_admin(
        self,
        authorization: str | None = Header(default=None),
        wiki_session: str | None = Cookie(default=None),
        x_forwarded_access_token: str | None = Header(default=None, alias="X-Forwarded-Access-Token"),
    ) -> Identity:
        """要求平台管理员（建维度、指定管理员等）。"""
        # ① 网关注入的令牌（统一认证层）
        gw = await self._identity_from_gateway(authorization, x_forwarded_access_token)
        if gw is not None:
            ident, is_admin = gw
            if not is_admin:
                raise HTTPException(status_code=403,
                                    detail=f"需要 wiki-admin 角色。当前用户 {ident.username} 无管理员权限")
            return ident

        # ② OIDC 会话
        if self._oidc and self._oidc.enabled and wiki_session:
            user = self._oidc.read_session(wiki_session)
            if user is not None:
                ident, is_admin = self.identity_from_session(user)
                if not is_admin:
                    logger.warning("[wiki-auth] 平台级操作被拒：%s（Keycloak 用户）非管理员", ident)
                    raise HTTPException(
                        status_code=403,
                        detail=(f"需要 wiki-admin 角色。当前用户 {user.username} 无管理员权限"
                                f"（角色：{getattr(user, 'roles', []) or []}）"),
                    )
                return ident

        # ③ Bearer
        ident, is_admin = await self._resolve(authorization)
        if not is_admin:
            if ident is None:
                raise HTTPException(status_code=401, detail="未认证",
                                    headers={"WWW-Authenticate": "Bearer"})
            logger.warning("[wiki-auth] 平台级操作被拒：%s 非平台管理员", ident)
            raise HTTPException(status_code=403, detail="需要平台管理员权限")
        return ident

    # ── 维度级鉴权（业务规则）──────────────────────────────────────────────────
    async def assert_can_manage_dim(self, ident: Identity, is_admin: bool, dim_id: str) -> None:
        """
        断言该身份能管理某维度。

        规则：
          · 平台管理员 → 可管任何维度
          · 维度管理员 → 只能管 admin_consumer_id 是自己（或自己的别名）的维度
          · 其他 → 403

        ⭐ 支持身份别名：管理台（OIDC username）与 MCP（HiMarket consumer）
           视为同一人，避免"用 A 授权、用 B 登录"就对不上。
        """
        if is_admin:
            return

        owner = await self._store.get_dim_admin(dim_id)
        if owner is None:
            raise HTTPException(status_code=404, detail=f"维度不存在：{dim_id}")

        # 别名匹配：zhaolei ⇄ consumer-xxx
        if await self._store.is_dim_admin(ident.consumer_id, dim_id):
            return

        logger.warning(
            "[wiki-auth] 维度管理被拒：%s 不是 %s 的管理员（管理员=%s）",
            ident, dim_id, owner,
        )
        raise HTTPException(
            status_code=403,
            detail=f"你不是维度 {dim_id} 的管理员（无权操作）",
        )

    async def assert_can_manage_project(self, ident: Identity, is_admin: bool,
                                        project_dim_id: str) -> None:
        """项目↔产品关联由项目维度的管理员维护。"""
        await self.assert_can_manage_dim(ident, is_admin, project_dim_id)

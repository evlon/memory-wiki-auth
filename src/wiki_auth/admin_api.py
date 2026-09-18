"""
管理 API —— 挂在 Hindsight 的 /ext/ 下（HttpExtension）

═══════════════════════════════════════════════════════════════════════════════
⚠️ 安全：/ext/ 路由【没有】框架级认证（e487 实测）
   必须在每个端点上显式依赖 AdminAuth。
═══════════════════════════════════════════════════════════════════════════════

端点设计（遵循 RESTful，全部返回 JSON）：

    维度管理
      GET    /ext/dims                     列维度（需认证）
      GET    /ext/dims/{dim_id}            维度详情
      POST   /ext/dims                     建/改维度（平台管理员）
      DELETE /ext/dims/{dim_id}            删维度（平台管理员）

    授权管理
      GET    /ext/grants                   列授权（可按 dim/consumer 过滤）
      PUT    /ext/grants                   设置授权（维度管理员或平台管理员）
      DELETE /ext/grants                   撤销授权

    项目↔产品
      GET    /ext/projects/{dim_id}/members      列项目集成的产品
      POST   /ext/projects/{dim_id}/members      加产品（项目管理员）
      DELETE /ext/projects/{dim_id}/members/{pid} 移除产品

    身份与自省
      GET    /ext/whoami                   我是谁、能管哪些维度
      GET    /ext/effective                某人的有效维度（含项目展开，调试用）

    审计
      GET    /ext/audit                    审计日志

    凭据（HiMarket 同步）
      GET    /ext/credentials              列凭据（脱敏）
      POST   /ext/credentials              登记/更新凭据（平台管理员）
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from .admin_auth import AdminAuth
from .store import PERM_READ, PERM_WRITE, DimAuthStore

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 请求/响应模型
# ══════════════════════════════════════════════════════════════════════════════

class DimensionIn(BaseModel):
    dim_id: str = Field(..., description="维度 ID，如 product-p1")
    dim_type: str = Field(..., description="product / project / platform / tech")
    name: str = Field(..., description="显示名，如 产品一")
    tag_prefix: str | None = Field(None, description="检索标签，默认同 dim_id")
    bank_id: str = Field(..., description="所属隔离区，如 team-knowledge")
    admin_consumer_id: str | None = Field(None, description="维度管理员 consumer_id")
    description: str | None = None


class GrantIn(BaseModel):
    consumer_id: str = Field(..., description="被授权者（HiMarket consumer_id）")
    dim_id: str = Field(..., description="维度 ID")
    permission: str = Field(..., description="none / read / write")


class GrantDeleteIn(BaseModel):
    consumer_id: str
    dim_id: str


class ProjectMemberIn(BaseModel):
    product_dim_id: str = Field(..., description="要加入的产品维度 ID")


class CredentialIn(BaseModel):
    api_key: str
    consumer_id: str
    developer_id: str | None = None
    username: str | None = None


class CredSyncIn(BaseModel):
    """HiMarket 凭据批量同步入参。"""
    rows: list[dict[str, Any]] = Field(
        ..., description="每行：{consumer_id, developer_id?, username?, apikey_config}"
    )


class GrantRequestIn(BaseModel):
    """申请挂载维度 / 引用产品。"""
    kind: str = Field(..., description="join=申请挂载维度；reference=项目引用产品")
    dim_id: str | None = Field(None, description="kind=join：目标维度")
    permission: str | None = Field(None, description="kind=join：期望 read/write")
    project_dim_id: str | None = Field(None, description="kind=reference：发起方项目")
    product_dim_id: str | None = Field(None, description="kind=reference：被引用产品")


class RequestDecideIn(BaseModel):
    """审批一条申请。"""
    decision: str = Field(..., description="APPROVED / REJECTED")


# ══════════════════════════════════════════════════════════════════════════════
# 路由
# ══════════════════════════════════════════════════════════════════════════════

def build_admin_router(store: DimAuthStore, oidc=None) -> APIRouter:
    """
    构造管理路由。

    ⚠️ 每个端点都显式依赖 auth.require_*（/ext/ 无框架级认证）。

    Args:
        store: 授权存储
        oidc:  OidcClient 实例（None = 未启用 OIDC，退回令牌方式）
    """
    from fastapi.responses import HTMLResponse, RedirectResponse

    from .oidc import SESSION_COOKIE, STATE_COOKIE

    router = APIRouter()
    auth = AdminAuth(store, oidc=oidc)

    # ── ⭐ OIDC 登录（用 Keycloak，符合浏览器常识）────────────────────────────
    @router.get("/oauth/login", summary="跳转 Keycloak 登录", include_in_schema=False)
    async def oauth_login():
        """未登录用户从这里进入 Keycloak。"""
        if not (oidc and oidc.enabled):
            raise HTTPException(
                status_code=503,
                detail="OIDC 未启用（缺 WIKI_OIDC_ISSUER / CLIENT_ID / SESSION_KEY）",
            )
        url, state, state_cookie = await oidc.build_login_url()
        resp = RedirectResponse(url=url, status_code=302)
        resp.set_cookie(
            STATE_COOKIE, state_cookie,
            max_age=600, httponly=True, samesite="lax", path="/ext",
        )
        logger.info("[wiki-auth] 跳转 Keycloak 登录（state=%s…）", state[:8])
        return resp

    @router.get("/oauth/callback", summary="Keycloak 回调", include_in_schema=False)
    async def oauth_callback(code: str | None = None, state: str | None = None,
                             error: str | None = None,
                             wiki_oauth_state: str | None = Cookie(default=None)):
        """Keycloak 授权后回调：校验 state → 换 token → 建会话。"""
        if error:
            raise HTTPException(status_code=401, detail=f"Keycloak 返回错误：{error}")
        if not (oidc and oidc.enabled):
            raise HTTPException(status_code=503, detail="OIDC 未启用")
        if not code or not state:
            raise HTTPException(status_code=400, detail="缺少 code 或 state")

        # ⚠️ 校验 state（防 CSRF）
        st = oidc.read_state(wiki_oauth_state)
        if not st or st.get("s") != state:
            logger.warning("[wiki-auth] OIDC state 校验失败")
            raise HTTPException(status_code=401, detail="state 校验失败（可能被 CSRF）")

        try:
            user = await oidc.exchange_code(code, st.get("v") or "")
        except Exception as e:
            logger.exception("[wiki-auth] OIDC 换取 token 失败")
            raise HTTPException(status_code=401, detail=f"登录失败：{type(e).__name__}")

        logger.info("[wiki-auth] 登录成功：%s（%s）", user.username, user.name)

        resp = RedirectResponse(url="/ext/", status_code=302)
        resp.set_cookie(
            SESSION_COOKIE, oidc.make_session(user),
            max_age=8 * 3600, httponly=True, samesite="lax", path="/ext",
        )
        resp.delete_cookie(STATE_COOKIE, path="/ext")
        return resp

    @router.get("/oauth/logout", summary="登出", include_in_schema=False)
    async def oauth_logout():
        """清会话并跳 Keycloak 登出。"""
        url = None
        if oidc and oidc.enabled:
            url = await oidc.logout_url()
        resp = RedirectResponse(url=url or "/ext/", status_code=302)
        resp.delete_cookie(SESSION_COOKIE, path="/ext")
        return resp

    @router.get("/oauth/me", summary="当前登录用户")
    async def oauth_me(wiki_session: str | None = Cookie(default=None)) -> dict[str, Any]:
        """返回当前会话用户（未登录则 authenticated=false）。"""
        if not (oidc and oidc.enabled):
            return {"authenticated": False, "oidc_enabled": False}
        user = oidc.read_session(wiki_session)
        if user is None:
            return {"authenticated": False, "oidc_enabled": True}
        return {
            "authenticated": True,
            "oidc_enabled": True,
            "user": user.to_dict(),
            "is_platform_admin": auth._is_admin_user(user.username, getattr(user, "roles", None)),
        }

    # ── 管理界面（单页 HTML，无需构建工具）────────────────────────────────────
    @router.get("/", summary="管理界面", include_in_schema=False)
    async def admin_ui(wiki_session: str | None = Cookie(default=None)):
        """
        返回内置管理界面。

        ⭐ OIDC 已启用且未登录 → 302 跳 Keycloak（符合浏览器常识）。
           OIDC 未启用 → 返回页面（页面里用令牌登录，兼容旧方式）。
        """
        if oidc and oidc.enabled:
            if oidc.read_session(wiki_session) is None:
                return RedirectResponse(url="/ext/oauth/login", status_code=302)

        ui_path = Path(__file__).with_name("admin_ui.html")
        if not ui_path.exists():
            return HTMLResponse(
                "<h1>管理界面缺失</h1><p>admin_ui.html 未随包部署。</p>",
                status_code=500,
            )
        return HTMLResponse(ui_path.read_text(encoding="utf-8"))

    # ── 自省 ──────────────────────────────────────────────────────────────────
    @router.get("/whoami", summary="我是谁、能管哪些维度")
    async def whoami(ident_isadmin=Depends(auth.require_identity)) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        dims = await store.list_dimensions()
        if is_admin:
            managed = [d["dim_id"] for d in dims]
        else:
            managed = [d["dim_id"] for d in dims
                       if d.get("admin_consumer_id") == ident.consumer_id]
        access = await store.load_access(ident.consumer_id)
        return {
            "consumer_id": ident.consumer_id,
            "username": ident.username,
            "source": ident.source,
            "is_platform_admin": is_admin,
            "managed_dims": managed,
            "granted_dims": [
                {"dim_id": a.dim_id, "permission": a.permission, "via": a.via}
                for a in access
            ],
        }

    @router.get("/effective", summary="某人的有效维度（含项目展开）")
    async def effective(
        consumer_id: str = Query(..., description="要查询的 consumer_id"),
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        # ⚠️ 非管理员只能查自己
        if not is_admin and consumer_id != ident.consumer_id:
            raise HTTPException(status_code=403, detail="只能查询自己的有效维度")
        access = await store.load_access(consumer_id)
        return {
            "consumer_id": consumer_id,
            "count": len(access),
            "dims": [
                {"dim_id": a.dim_id, "tag_prefix": a.tag_prefix,
                 "bank_id": a.bank_id, "permission": a.permission, "via": a.via}
                for a in access
            ],
        }

    # ── 维度 ──────────────────────────────────────────────────────────────────
    @router.get("/dims", summary="列维度")
    async def list_dims(
        bank_id: str | None = Query(None),
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        dims = await store.list_dimensions(bank_id=bank_id)
        return {"count": len(dims), "dims": dims}

    @router.get("/dims/{dim_id}", summary="维度详情")
    async def get_dim(
        dim_id: str,
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        d = await store.get_dimension(dim_id)
        if d is None:
            raise HTTPException(status_code=404, detail=f"维度不存在：{dim_id}")
        d["members"] = await store.list_project_members(project_dim_id=dim_id)
        return d

    @router.post("/dims", summary="建/改维度（平台管理员，或自建并自任管理员）")
    async def upsert_dim(
        body: DimensionIn,
        authorization: str | None = Header(default=None),
        wiki_session: str | None = Cookie(default=None),
        x_forwarded_access_token: str | None = Header(default=None, alias="X-Forwarded-Access-Token"),
    ) -> dict[str, Any]:
        if body.dim_type not in ("product", "project", "platform", "tech"):
            raise HTTPException(
                status_code=400,
                detail="dim_type 必须是 product/project/platform/tech 之一",
            )
        # ⭐ 自助建维度：登录用户可自建（自任管理员）；平台管理员可建任意维度。
        #    普通登录用户建维度时，强制 admin_consumer_id = 自己（不能指定别人）。
        ident, is_admin = await auth.require_identity(
            authorization=authorization, wiki_session=wiki_session,
            x_forwarded_access_token=x_forwarded_access_token,
        )
        admin_id = body.admin_consumer_id
        if not is_admin:
            if admin_id and admin_id != ident.consumer_id:
                raise HTTPException(
                    status_code=403,
                    detail="非平台管理员只能自建维度并自任管理员，不能指定他人为管理员",
                )
            admin_id = ident.consumer_id
        await store.upsert_dimension(
            dim_id=body.dim_id,
            dim_type=body.dim_type,
            name=body.name,
            tag_prefix=body.tag_prefix or body.dim_id,
            bank_id=body.bank_id,
            admin_consumer_id=admin_id,
            description=body.description,
        )
        logger.info("[wiki-auth] 维度已保存：%s（by %s）", body.dim_id, ident)
        return {"ok": True, "dim_id": body.dim_id, "admin_consumer_id": admin_id}

    @router.delete("/dims/{dim_id}", summary="删维度（平台管理员）")
    async def delete_dim(
        dim_id: str,
        ident=Depends(auth.require_platform_admin),
    ) -> dict[str, Any]:
        await store.delete_dimension(dim_id)
        logger.warning("[wiki-auth] 维度已删除：%s（by %s）", dim_id, ident)
        return {"ok": True, "dim_id": dim_id}

    # ── 授权 ──────────────────────────────────────────────────────────────────
    @router.get("/grants", summary="列授权")
    async def list_grants(
        dim_id: str | None = Query(None),
        consumer_id: str | None = Query(None),
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        # ⚠️ 非管理员只能看与自己相关维度的授权
        if not is_admin:
            if consumer_id and consumer_id != ident.consumer_id:
                raise HTTPException(status_code=403, detail="只能查询自己的授权")
            dims = await store.list_dimensions()
            mine = {d["dim_id"] for d in dims
                    if d.get("admin_consumer_id") == ident.consumer_id}
            if dim_id and dim_id not in mine:
                raise HTTPException(status_code=403, detail=f"你不是 {dim_id} 的管理员")
            if not dim_id:
                consumer_id = ident.consumer_id
        grants = await store.list_grants(dim_id=dim_id, consumer_id=consumer_id)
        return {"count": len(grants), "grants": grants}

    @router.put("/grants", summary="设置授权（维度管理员或平台管理员）")
    async def set_grant(
        body: GrantIn,
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        if body.permission not in ("none", PERM_READ, PERM_WRITE):
            raise HTTPException(status_code=400, detail="permission 必须是 none/read/write")
        await auth.assert_can_manage_dim(ident, is_admin, body.dim_id)

        if body.permission == "none":
            await store.revoke_grant(consumer_id=body.consumer_id,
                                     dim_id=body.dim_id, actor=ident.consumer_id)
        else:
            await store.set_grant(consumer_id=body.consumer_id, dim_id=body.dim_id,
                                  permission=body.permission,
                                  granted_by=ident.consumer_id)
        logger.info("[wiki-auth] 授权 %s → %s = %s（by %s）",
                    body.consumer_id, body.dim_id, body.permission, ident)
        return {"ok": True}

    @router.delete("/grants", summary="撤销授权")
    async def delete_grant(
        body: GrantDeleteIn,
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        await auth.assert_can_manage_dim(ident, is_admin, body.dim_id)
        await store.revoke_grant(consumer_id=body.consumer_id,
                                 dim_id=body.dim_id, actor=ident.consumer_id)
        logger.info("[wiki-auth] 撤销 %s ← %s（by %s）",
                    body.consumer_id, body.dim_id, ident)
        return {"ok": True}

    # ── 项目 ↔ 产品 ───────────────────────────────────────────────────────────
    @router.get("/projects/{project_dim_id}/members", summary="列项目集成的产品")
    async def list_members(
        project_dim_id: str,
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        members = await store.list_project_members(project_dim_id=project_dim_id)
        return {"project_dim_id": project_dim_id, "count": len(members),
                "members": members}

    @router.post("/projects/{project_dim_id}/members", summary="加产品到项目（引用他人产品走审批）")
    async def add_member(
        project_dim_id: str,
        body: ProjectMemberIn,
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        await auth.assert_can_manage_project(ident, is_admin, project_dim_id)

        proj = await store.get_dimension(project_dim_id)
        if proj is None or proj["dim_type"] != "project":
            raise HTTPException(status_code=400,
                                detail=f"{project_dim_id} 不是项目维度")
        prod = await store.get_dimension(body.product_dim_id)
        if prod is None or prod["dim_type"] != "product":
            raise HTTPException(status_code=400,
                                detail=f"{body.product_dim_id} 不是产品维度")

        # ⚠️ 同 bank 约束：跨 bank 的产品检索不到（Hindsight recall 单 bank）
        if prod["bank_id"] != proj["bank_id"]:
            logger.warning(
                "[wiki-auth] ⚠️ 跨 bank 关联：项目 %s(%s) ← 产品 %s(%s)。"
                "Hindsight 的 recall 是单 bank 的，该项目成员将【检索不到】此产品知识。",
                project_dim_id, proj["bank_id"], body.product_dim_id, prod["bank_id"],
            )
            raise HTTPException(
                status_code=400,
                detail=(f"不能跨隔离区关联：项目在 {proj['bank_id']}，"
                        f"产品在 {prod['bank_id']}。"
                        f"Hindsight 的检索是单隔离区的，跨区关联会导致查不到。"),
            )

        # ⭐ 引用他人产品 → 走审批（对方产品管理员同意后才生效）
        product_admin = prod.get("admin_consumer_id")
        if not is_admin and product_admin and not await store.is_dim_admin(
                ident.consumer_id, body.product_dim_id):
            req = await store.create_request(
                kind="reference",
                requester_id=ident.consumer_id,
                project_dim_id=project_dim_id,
                product_dim_id=body.product_dim_id,
            )
            logger.info("[wiki-auth] 引用他人产品 → 已发申请：项目 %s ← 产品 %s（by %s）",
                        project_dim_id, body.product_dim_id, ident)
            return {"ok": True, "pending": True, "request": req}

        await store.add_project_member(project_dim_id=project_dim_id,
                                       product_dim_id=body.product_dim_id,
                                       actor=ident.consumer_id)
        logger.info("[wiki-auth] 项目 %s += 产品 %s（by %s）",
                    project_dim_id, body.product_dim_id, ident)
        return {"ok": True, "pending": False}

    @router.delete("/projects/{project_dim_id}/members/{product_dim_id}",
                   summary="从项目移除产品")
    async def remove_member(
        project_dim_id: str,
        product_dim_id: str,
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        await auth.assert_can_manage_project(ident, is_admin, project_dim_id)
        await store.remove_project_member(project_dim_id=project_dim_id,
                                          product_dim_id=product_dim_id,
                                          actor=ident.consumer_id)
        return {"ok": True}

    # ── 申请 → 审批（跨团队协作流转）─────────────────────────────────────────
    @router.get("/requests", summary="我的申请 / 待我审批")
    async def list_requests(
        scope: str = Query("mine", description="mine=我的申请；pending=待我审批"),
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        if scope == "mine":
            rows = await store.list_requests(requester_id=ident.consumer_id)
            return {"count": len(rows), "requests": rows}
        if scope == "pending":
            if is_admin:
                # 平台管理员：待审批 = 全部 PENDING
                rows = await store.list_requests(status="PENDING")
            else:
                # 维度管理员：待审批 = 目标维度/被引用产品是「我管」的 PENDING
                dims = await store.list_dimensions()
                mine = {d["dim_id"] for d in dims
                        if d.get("admin_consumer_id") == ident.consumer_id}
                all_pending = await store.list_requests(status="PENDING")
                rows = [
                    r for r in all_pending
                    if r.get("dim_id") in mine or r.get("product_dim_id") in mine
                ]
            return {"count": len(rows), "requests": rows}
        raise HTTPException(status_code=400, detail="scope 必须是 mine 或 pending")

    @router.post("/requests", summary="提交申请（挂载维度 / 引用产品）")
    async def create_request(
        body: GrantRequestIn,
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        try:
            req = await store.create_request(
                kind=body.kind,
                requester_id=ident.consumer_id,
                dim_id=body.dim_id,
                project_dim_id=body.project_dim_id,
                product_dim_id=body.product_dim_id,
                permission=body.permission,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        logger.info("[wiki-auth] 申请已提交：%s（by %s）",
                    req.get("kind"), ident)
        return {"ok": True, "request": req}

    @router.post("/requests/{request_id}/decide", summary="审批申请（目标维度/项目管理员）")
    async def decide_request(
        request_id: int,
        body: RequestDecideIn,
        ident_isadmin=Depends(auth.require_identity),
    ) -> dict[str, Any]:
        ident, is_admin = ident_isadmin
        req = await store.get_request(request_id)
        if req is None:
            raise HTTPException(status_code=404, detail=f"申请不存在：{request_id}")
        if req["status"] != "PENDING":
            raise HTTPException(status_code=400, detail=f"申请已终态：{req['status']}")

        # ⭐ 鉴权：审批者必须是目标对象的管理员
        if not is_admin:
            if req["kind"] == "join":
                target = req.get("dim_id")
            elif req["kind"] == "reference":
                # 引用：由「被引用产品」的管理员审批（对方同意）
                target = req.get("product_dim_id")
            else:
                target = None
            if not target:
                raise HTTPException(status_code=400, detail="申请缺目标对象")
            if not await store.is_dim_admin(ident.consumer_id, target):
                raise HTTPException(
                    status_code=403,
                    detail=f"你不是 {target} 的管理员，无权审批此申请",
                )

        updated = await store.decide_request(
            request_id=request_id,
            decision=body.decision,
            decided_by=ident.consumer_id,
        )
        logger.info("[wiki-auth] 审批完成：req#%s = %s（by %s）",
                    request_id, body.decision, ident)
        return {"ok": True, "request": updated}

    # ── 审计 ──────────────────────────────────────────────────────────────────
    @router.get("/audit", summary="审计日志")
    async def audit(
        limit: int = Query(100, ge=1, le=500),
        target: str | None = Query(None),
        ident=Depends(auth.require_platform_admin),
    ) -> dict[str, Any]:
        rows = await store.list_audit(limit=limit, target=target)
        return {"count": len(rows), "items": rows}

    # ── 凭据（HiMarket 同步）──────────────────────────────────────────────────
    @router.get("/credentials", summary="列凭据（脱敏）")
    async def list_creds(ident=Depends(auth.require_platform_admin)) -> dict[str, Any]:
        rows = await store.list_credentials()
        return {"count": len(rows), "credentials": rows}

    @router.post("/credentials", summary="登记/更新凭据（平台管理员）")
    async def upsert_cred(
        body: CredentialIn,
        ident=Depends(auth.require_platform_admin),
    ) -> dict[str, Any]:
        await store.upsert_credential(
            api_key=body.api_key, consumer_id=body.consumer_id,
            developer_id=body.developer_id, username=body.username,
        )
        logger.info("[wiki-auth] 凭据已登记：%s → %s（by %s）",
                    body.consumer_id, body.username, ident)
        return {"ok": True}

    # ── ⭐ HiMarket 凭据批量同步（消除手工 seed 短板）─────────────────────────
    @router.post("/credentials/sync", summary="批量同步 HiMarket 凭据")
    async def sync_creds(
        body: CredSyncIn,
        ident=Depends(auth.require_platform_admin),
    ) -> dict[str, Any]:
        """
        接收 HiMarket 的 consumer 列表并幂等写入。

        由外部脚本（`k8s/scripts/sync-himarket-creds.sh`）从 HiMarket 的
        MySQL 读取后 POST 进来。设计成"接收端"而不是让 Hindsight 直连
        HiMarket 的 MySQL，是为了：
          · 不在 Hindsight 镜像里引入 MySQL 驱动
          · 两个库解耦（HiMarket 挂了不影响记忆系统）
        """
        from .cred_sync import sync_credentials

        result = await sync_credentials(store, body.rows, actor=ident.consumer_id)
        return result.to_dict()

    return router

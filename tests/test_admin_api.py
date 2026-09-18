"""
管理 API 测试

⚠️ 安全重点（对应 e487 发现）：
   Hindsight 挂载 /ext/ 时**没有框架级认证**，
   所以本套测试的核心是验证「认证与鉴权边界」：
     · 无令牌 → 401
     · 普通用户 → 只能管自己的维度（403 越权）
     · 平台管理员 → 全权
     · 未配置管理员令牌 → 平台级操作全拒（fail-closed）
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from wiki_auth.admin_api import build_admin_router
from wiki_auth.admin_auth import AdminAuth
from wiki_auth.store import PERM_READ, PERM_WRITE, DimAccess

# 复用主测试的 FakeStore（同构的内存实现）
from test_validator import CONSUMER_A, CONSUMER_B, KEY_A, KEY_B, FakeStore

ADMIN_TOKEN = "test-admin-token-1234567890"


# ══════════════════════════════════════════════════════════════════════════════
# 测试用 Store（在 FakeStore 基础上补齐管理 API 需要的方法）
# ══════════════════════════════════════════════════════════════════════════════

class AdminFakeStore(FakeStore):
    """补上管理 API 需要但 FakeStore 没有的方法。"""

    def __init__(self):
        super().__init__()
        self.dims: dict[str, dict] = {}
        self.audit_log: list[dict] = []
        # 身份别名：{身份 → 等价身份集合}。默认空 = 恒等映射。
        self.aliases: dict[str, set[str]] = {}
        # 凭据的 is_primary 标记（True=真人主账号，False/None=系统账号）
        self.cred_primary: dict[str, bool | None] = {}

    def add_dim(self, dim_id: str, dim_type: str, name: str, bank_id: str,
                admin_consumer_id: str | None = None, tag_prefix: str | None = None):
        self.dims[dim_id] = {
            "dim_id": dim_id, "dim_type": dim_type, "name": name,
            "description": None, "tag_prefix": tag_prefix or dim_id,
            "bank_id": bank_id, "admin_consumer_id": admin_consumer_id,
            "status": "ACTIVE",
        }

    async def list_dimensions(self, *, bank_id=None):
        vals = list(self.dims.values())
        if bank_id:
            vals = [d for d in vals if d["bank_id"] == bank_id]
        return sorted(vals, key=lambda d: (d["dim_type"], d["dim_id"]))

    async def get_dimension(self, dim_id):
        return self.dims.get(dim_id)

    async def get_dim_admin(self, dim_id):
        d = self.dims.get(dim_id)
        return d["admin_consumer_id"] if d else None

    async def is_dim_admin(self, identity, dim_id):
        """
        某人是否是该维度的管理员（支持身份别名）。

        ⚠️ 与真实 store 的语义保持一致：
           真实实现会用 v_identity_alias 把 username 与 consumer_id 归并；
           本 fake 用 self.aliases 模拟（默认恒等映射）。
        """
        if not identity or not dim_id:
            return False
        d = self.dims.get(dim_id)
        if not d:
            return False
        owner = d["admin_consumer_id"]
        aliases = self.aliases.get(identity, {identity})
        return bool(owner) and owner in aliases

    async def list_grants(self, *, dim_id=None, consumer_id=None):
        out = []
        for cid, accs in self.grants.items():
            if consumer_id and cid != consumer_id:
                continue
            for a in accs:
                if dim_id and a.dim_id != dim_id:
                    continue
                out.append({
                    "consumer_id": cid, "dim_id": a.dim_id,
                    "permission": a.permission, "bank_id": a.bank_id,
                    "tag_prefix": a.tag_prefix, "status": "APPROVED",
                })
        return out

    async def list_project_members(self, *, project_dim_id=None):
        out = []
        for proj, prods in self.project_members.items():
            if project_dim_id and proj != project_dim_id:
                continue
            for p in prods:
                out.append({"project_dim_id": proj, "product_dim_id": p})
        return out

    async def list_audit(self, *, limit=100, target=None):
        return self.audit_log[:limit]

    async def list_credentials(self):
        return [{"consumer_id": cid, "username": u, "status": "ACTIVE"}
                for _k, (cid, u, _d) in self.creds.items()]

    async def upsert_credential(self, *, api_key, consumer_id, developer_id=None,
                                username=None, is_primary=None):
        self.creds[api_key] = (consumer_id, username, developer_id)
        # 记录 is_primary（供别名归并相关断言使用）
        self.cred_primary[api_key] = is_primary

    async def upsert_dimension(self, *, dim_id, dim_type, name, tag_prefix,
                               bank_id, admin_consumer_id=None, description=None):
        self.dims[dim_id] = {
            "dim_id": dim_id, "dim_type": dim_type, "name": name,
            "description": description, "tag_prefix": tag_prefix,
            "bank_id": bank_id, "admin_consumer_id": admin_consumer_id,
            "status": "ACTIVE",
        }

    async def delete_dimension(self, dim_id):
        self.dims.pop(dim_id, None)

    async def set_grant(self, *, consumer_id, dim_id, permission, granted_by=None):
        self.grant(consumer_id, dim_id, dim_id, "team-knowledge", permission)

    async def revoke_grant(self, *, consumer_id, dim_id, actor=None):
        if consumer_id in self.grants:
            self.grants[consumer_id] = [
                a for a in self.grants[consumer_id] if a.dim_id != dim_id
            ]

    async def add_project_member(self, *, project_dim_id, product_dim_id, actor=None):
        self.project_members.setdefault(project_dim_id, [])
        if product_dim_id not in self.project_members[project_dim_id]:
            self.project_members[project_dim_id].append(product_dim_id)

    async def remove_project_member(self, *, project_dim_id, product_dim_id, actor=None):
        if project_dim_id in self.project_members:
            self.project_members[project_dim_id] = [
                p for p in self.project_members[project_dim_id] if p != product_dim_id
            ]


def make_client(store: AdminFakeStore, admin_token: str | None = ADMIN_TOKEN) -> TestClient:
    """构造一个挂载了管理 API 的测试应用。"""
    app = FastAPI()
    router = build_admin_router(store)
    app.include_router(router, prefix="/ext")
    # ⚠️ 用 monkeypatch 方式注入令牌（避免污染环境变量）
    import wiki_auth.admin_auth as aa
    orig_init = aa.AdminAuth.__init__

    def patched(self, s, token=None):
        orig_init(self, s, admin_token)

    aa.AdminAuth.__init__ = patched
    try:
        # build_admin_router 内部已构造 AdminAuth，需重建
        app2 = FastAPI()
        app2.include_router(build_admin_router(store), prefix="/ext")
    finally:
        aa.AdminAuth.__init__ = orig_init
    return TestClient(app2)


@pytest.fixture
def store():
    s = AdminFakeStore()
    s.add_cred(KEY_A, CONSUMER_A, "niukunliang")
    s.add_cred(KEY_B, CONSUMER_B, "douyi")
    # 产品一 由 A 管理；产品二 由 B 管理
    s.add_dim("product-p1", "product", "产品一", "team-knowledge", CONSUMER_A)
    s.add_dim("product-p2", "product", "产品二", "team-knowledge", CONSUMER_B)
    s.add_dim("project-prj1", "project", "项目一", "team-knowledge", CONSUMER_A)
    s.add_dim("platform-higress", "platform", "Higress", "team-knowledge", None)
    return s


@pytest.fixture
def client(store, monkeypatch):
    monkeypatch.setenv("WIKI_AUTH_ADMIN_TOKEN", ADMIN_TOKEN)
    app = FastAPI()
    app.include_router(build_admin_router(store), prefix="/ext")
    return TestClient(app)


H_ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
H_A = {"Authorization": f"Bearer {KEY_A}"}
H_B = {"Authorization": f"Bearer {KEY_B}"}


# ══════════════════════════════════════════════════════════════════════════════
# 【1】认证边界 ⭐ 安全关键
# ══════════════════════════════════════════════════════════════════════════════

class TestAdminAuth:

    def test_无令牌_401(self, client):
        r = client.get("/ext/dims")
        assert r.status_code == 401, f"无令牌必须 401，实际 {r.status_code}"

    def test_假令牌_401(self, client):
        r = client.get("/ext/dims", headers={"Authorization": "Bearer garbage"})
        assert r.status_code == 401

    def test_有效apikey_可访问(self, client):
        r = client.get("/ext/dims", headers=H_A)
        assert r.status_code == 200

    def test_平台管理员_可访问(self, client):
        r = client.get("/ext/dims", headers=H_ADMIN)
        assert r.status_code == 200

    def test_未配置管理员令牌时_平台级操作全拒(self, store, monkeypatch):
        """
        ⭐ fail-closed：没配令牌 ≠ 人人都是管理员。

        期望 401（不是 403）：因为 "anything" 不是合法 apikey 形状，
        身份解析阶段就失败了 → 未认证。
        （若用合法形状的 apikey，则会走到 403 —— 见下一个用例。）
        """
        monkeypatch.delenv("WIKI_AUTH_ADMIN_TOKEN", raising=False)
        app = FastAPI()
        app.include_router(build_admin_router(store), prefix="/ext")
        c = TestClient(app)

        r = c.post("/ext/dims", headers={"Authorization": "Bearer anything"},
                   json={"dim_id": "product-p9", "dim_type": "product",
                         "name": "产品九", "bank_id": "team-knowledge"})
        assert r.status_code == 401, f"未配令牌时必须拒绝，实际 {r.status_code}"

    def test_未配置管理员令牌_合法apikey也不能建维度(self, store, monkeypatch):
        """
        ⭐⭐ 关键：即使带着**合法 apikey**（能通过认证），
        未配置管理员令牌时也不能做平台级操作 —— 必须 403。
        """
        monkeypatch.delenv("WIKI_AUTH_ADMIN_TOKEN", raising=False)
        app = FastAPI()
        app.include_router(build_admin_router(store), prefix="/ext")
        c = TestClient(app)

        r = c.post("/ext/dims", headers=H_A,
                   json={"dim_id": "product-p9", "dim_type": "product",
                         "name": "产品九", "bank_id": "team-knowledge"})
        assert r.status_code == 403, \
            f"⭐ 未配管理员令牌时，合法用户也不得建维度，实际 {r.status_code}"


# ══════════════════════════════════════════════════════════════════════════════
# 【2】维度管理权限边界 ⭐
# ══════════════════════════════════════════════════════════════════════════════

class TestDimensionPermissions:

    def test_普通用户不能建维度_403(self, client):
        r = client.post("/ext/dims", headers=H_A,
                        json={"dim_id": "product-p9", "dim_type": "product",
                              "name": "产品九", "bank_id": "team-knowledge"})
        assert r.status_code == 403, "建维度是平台级操作"

    def test_平台管理员可建维度(self, client, store):
        r = client.post("/ext/dims", headers=H_ADMIN,
                        json={"dim_id": "product-p9", "dim_type": "product",
                              "name": "产品九", "bank_id": "team-knowledge"})
        assert r.status_code == 200, r.text
        assert "product-p9" in store.dims

    def test_非法dim_type_400(self, client):
        r = client.post("/ext/dims", headers=H_ADMIN,
                        json={"dim_id": "x", "dim_type": "bogus",
                              "name": "X", "bank_id": "team-knowledge"})
        assert r.status_code == 400

    def test_普通用户不能删维度_403(self, client):
        r = client.delete("/ext/dims/product-p1", headers=H_A)
        assert r.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# 【3】授权管理权限边界 ⭐⭐ 核心
# ══════════════════════════════════════════════════════════════════════════════

class TestGrantPermissions:

    def test_维度管理员可授权自己的维度(self, client, store):
        """A 是 product-p1 的管理员 → 可以授权给别人"""
        r = client.put("/ext/grants", headers=H_A,
                       json={"consumer_id": CONSUMER_B, "dim_id": "product-p1",
                             "permission": "read"})
        assert r.status_code == 200, r.text

    def test_维度管理员不能授权别人的维度_403(self, client):
        """⭐ A 不是 product-p2 的管理员 → 必须 403"""
        r = client.put("/ext/grants", headers=H_A,
                       json={"consumer_id": CONSUMER_B, "dim_id": "product-p2",
                             "permission": "write"})
        assert r.status_code == 403, \
            f"⭐ 越权授权必须被拒，实际 {r.status_code}"

    def test_平台管理员可授权任何维度(self, client):
        r = client.put("/ext/grants", headers=H_ADMIN,
                       json={"consumer_id": CONSUMER_B, "dim_id": "product-p2",
                             "permission": "write"})
        assert r.status_code == 200, r.text

    def test_非法权限值_400(self, client):
        r = client.put("/ext/grants", headers=H_A,
                       json={"consumer_id": CONSUMER_B, "dim_id": "product-p1",
                             "permission": "superuser"})
        assert r.status_code == 400

    def test_权限none等于撤销(self, client, store):
        store.grant(CONSUMER_B, "product-p1", "product-p1", "team-knowledge", PERM_READ)
        r = client.put("/ext/grants", headers=H_A,
                       json={"consumer_id": CONSUMER_B, "dim_id": "product-p1",
                             "permission": "none"})
        assert r.status_code == 200
        left = [a for a in store.grants.get(CONSUMER_B, []) if a.dim_id == "product-p1"]
        assert not left, "permission=none 应撤销授权"

    def test_不存在的维度_404(self, client):
        r = client.put("/ext/grants", headers=H_A,
                       json={"consumer_id": CONSUMER_B, "dim_id": "product-nope",
                             "permission": "read"})
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 【4】项目↔产品（含同 bank 约束）⭐⭐ 业务核心
# ══════════════════════════════════════════════════════════════════════════════

class TestProjectMembers:

    def test_项目管理员可加同bank产品(self, client, store):
        r = client.post("/ext/projects/project-prj1/members", headers=H_A,
                        json={"product_dim_id": "product-p1"})
        assert r.status_code == 200, r.text
        assert "product-p1" in store.project_members.get("project-prj1", [])

    def test_跨bank关联被拒_400(self, client, store):
        """⭐ 同 bank 约束：跨隔离区关联会导致检索不到，必须拒绝"""
        store.add_dim("product-other", "product", "别的产品",
                      "team-other", CONSUMER_A)
        r = client.post("/ext/projects/project-prj1/members", headers=H_A,
                        json={"product_dim_id": "product-other"})
        assert r.status_code == 400, \
            f"⭐ 跨 bank 关联必须拒绝，实际 {r.status_code}"
        assert "隔离区" in r.text or "bank" in r.text.lower()

    def test_非项目管理员不能改关联_403(self, client):
        r = client.post("/ext/projects/project-prj1/members", headers=H_B,
                        json={"product_dim_id": "product-p1"})
        assert r.status_code == 403

    def test_加非产品维度被拒_400(self, client):
        r = client.post("/ext/projects/project-prj1/members", headers=H_A,
                        json={"product_dim_id": "platform-higress"})
        assert r.status_code == 400

    def test_移除产品(self, client, store):
        # ⚠️ AdminFakeStore.add_project_member 是 async（与真实 store 同签名），
        #    这里直接改内部字典，避免在同步测试里 await
        store.project_members.setdefault("project-prj1", [])
        if "product-p1" not in store.project_members["project-prj1"]:
            store.project_members["project-prj1"].append("product-p1")

        r = client.delete("/ext/projects/project-prj1/members/product-p1",
                          headers=H_A)
        assert r.status_code == 200
        assert "product-p1" not in store.project_members.get("project-prj1", [])


# ══════════════════════════════════════════════════════════════════════════════
# 【5】自省与查询
# ══════════════════════════════════════════════════════════════════════════════

class TestIntrospection:

    def test_whoami_普通用户(self, client):
        r = client.get("/ext/whoami", headers=H_A)
        assert r.status_code == 200
        d = r.json()
        assert d["consumer_id"] == CONSUMER_A
        assert d["is_platform_admin"] is False
        assert "product-p1" in d["managed_dims"]
        assert "product-p2" not in d["managed_dims"], "不能管别人的维度"

    def test_whoami_平台管理员(self, client):
        r = client.get("/ext/whoami", headers=H_ADMIN)
        d = r.json()
        assert d["is_platform_admin"] is True
        assert "product-p2" in d["managed_dims"], "平台管理员可管所有维度"

    def test_effective_只能查自己(self, client):
        r = client.get(f"/ext/effective?consumer_id={CONSUMER_B}", headers=H_A)
        assert r.status_code == 403, "普通用户不能查别人的有效维度"

    def test_effective_可查自己(self, client, store):
        store.grant(CONSUMER_A, "product-p1", "product-p1", "team-knowledge", PERM_WRITE)
        r = client.get(f"/ext/effective?consumer_id={CONSUMER_A}", headers=H_A)
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_审计日志需平台管理员(self, client):
        assert client.get("/ext/audit", headers=H_A).status_code == 403
        assert client.get("/ext/audit", headers=H_ADMIN).status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 【6】凭据管理
# ══════════════════════════════════════════════════════════════════════════════

class TestCredentials:

    def test_普通用户不能看凭据_403(self, client):
        assert client.get("/ext/credentials", headers=H_A).status_code == 403

    def test_平台管理员可登记凭据(self, client, store):
        r = client.post("/ext/credentials", headers=H_ADMIN,
                        json={"api_key": "apikey-<your-api-key>",
                              "consumer_id": CONSUMER_B, "username": "douyi"})
        assert r.status_code == 200, r.text

    def test_凭据列表不泄漏完整key(self, client, store):
        r = client.get("/ext/credentials", headers=H_ADMIN)
        body = r.text
        assert KEY_A not in body, "⭐ 凭据列表不得返回完整 apikey"

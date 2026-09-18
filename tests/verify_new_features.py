"""
验证本次新增功能（申请→审批流 + 自助建维度 + 引用走审批）的独立脚本。

用合法假 apikey + 内存 FakeStore，不碰真实 DB，不改动现有测试源文件。
"""
import asyncio
import sys

sys.path.insert(0, r"E:\ai-works\memory-wiki-auth\tests\hindsight_stub")
sys.path.insert(0, r"E:\ai-works\memory-wiki-auth\src")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from wiki_auth.admin_api import build_admin_router

# 复用 test_admin_api 的 FakeStore（同构内存实现）
sys.path.insert(0, r"E:\ai-works\memory-wiki-auth\tests")
from test_admin_api import AdminFakeStore

CONSUMER_A = "consumer-a8238936cb114765be9a1c4efc6eac39"
CONSUMER_B = "consumer-11c463336a154e9fbdd2f80ade49ad0c"
KEY_A = "apikey-a8238936cb114765be9a1c4efc6eac39"  # 合法形状
KEY_B = "apikey-11c463336a154e9fbdd2f80ade49ad0c"  # 合法形状
ADMIN_TOKEN = "test-admin-token-1234567890"

H_A = {"Authorization": f"Bearer {KEY_A}"}
H_B = {"Authorization": f"Bearer {KEY_B}"}
H_ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def make_store():
    s = AdminFakeStore()
    s.add_cred(KEY_A, CONSUMER_A, "niukunliang")
    s.add_cred(KEY_B, CONSUMER_B, "douyi")
    s.add_dim("product-p1", "product", "产品一", "team-knowledge", CONSUMER_A)
    s.add_dim("product-p2", "product", "产品二", "team-knowledge", CONSUMER_B)
    s.add_dim("project-prj1", "project", "项目一", "team-knowledge", CONSUMER_A)

    # 补上审批相关方法（内存实现，镜像真实 store 的语义）
    s._req = {}
    s._req_seq = [0]

    async def create_request(*, kind, requester_id, dim_id=None,
                             project_dim_id=None, product_dim_id=None,
                             permission=None):
        if kind == "join" and (not dim_id or permission not in ("read", "write")):
            raise ValueError("join 申请必须提供 dim_id 与 permission")
        if kind == "reference" and (not project_dim_id or not product_dim_id):
            raise ValueError("reference 申请必须提供 project_dim_id 与 product_dim_id")
        s._req_seq[0] += 1
        rid = s._req_seq[0]
        s._req[rid] = {"id": rid, "kind": kind, "requester_id": requester_id,
                       "dim_id": dim_id, "project_dim_id": project_dim_id,
                       "product_dim_id": product_dim_id, "permission": permission,
                       "status": "PENDING"}
        return s._req[rid]

    async def get_request(request_id):
        return s._req.get(request_id)

    async def list_requests(*, requester_id=None, status=None, dim_id=None,
                            product_dim_id=None, limit=200):
        out = []
        for r in s._req.values():
            if requester_id and r["requester_id"] != requester_id:
                continue
            if status and r["status"] != status:
                continue
            if dim_id and r["dim_id"] != dim_id:
                continue
            if product_dim_id and r["product_dim_id"] != product_dim_id:
                continue
            out.append(r)
        return out

    async def decide_request(*, request_id, decision, decided_by):
        r = s._req.get(request_id)
        if r is None or r["status"] != "PENDING":
            return r
        if decision == "APPROVED":
            if r["kind"] == "join":
                await s.set_grant(consumer_id=r["requester_id"], dim_id=r["dim_id"],
                                  permission=r["permission"], granted_by=decided_by)
            elif r["kind"] == "reference":
                await s.add_project_member(project_dim_id=r["project_dim_id"],
                                           product_dim_id=r["product_dim_id"],
                                           actor=decided_by)
        r["status"] = decision
        r["decided_by"] = decided_by
        return r

    s.create_request = create_request
    s.get_request = get_request
    s.list_requests = list_requests
    s.decide_request = decide_request
    return s


def make_client(store, token=ADMIN_TOKEN):
    import os
    os.environ["WIKI_AUTH_ADMIN_TOKEN"] = token
    app = FastAPI()
    app.include_router(build_admin_router(store), prefix="/ext")
    return TestClient(app)


PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        print(f"  ❌ {name}  {detail}")


print("══ 1. 自助建维度（登录用户自建并自任管理员）══")
s = make_store()
c = make_client(s)
r = c.post("/ext/dims", headers=H_A, json={
    "dim_id": "product-p9", "dim_type": "product",
    "name": "产品九", "bank_id": "team-knowledge"})
check("普通用户可自建维度", r.status_code == 200, f"实际 {r.status_code} {r.text[:120]}")
check("自任管理员", s.dims.get("product-p9", {}).get("admin_consumer_id") == CONSUMER_A,
      f"实际 {s.dims.get('product-p9', {}).get('admin_consumer_id')}")

r = c.post("/ext/dims", headers=H_A, json={
    "dim_id": "product-p10", "dim_type": "product", "name": "产品十",
    "bank_id": "team-knowledge", "admin_consumer_id": CONSUMER_B})
check("非平台管理员不能指定他人为管理员", r.status_code == 403, f"实际 {r.status_code}")

print()
print("══ 2. 申请挂载维度（join）→ 管理员审批 ══")
s = make_store()
c = make_client(s)
# B 申请挂载 product-p1（A 管的），期望 read
r = c.post("/ext/requests", headers=H_B, json={
    "kind": "join", "dim_id": "product-p1", "permission": "read"})
check("B 可提交 join 申请", r.status_code == 200, f"实际 {r.status_code} {r.text[:120]}")
rid = r.json().get("request", {}).get("id")
check("拿到申请 id", rid is not None)

# A 审批（A 是 product-p1 管理员）
r = c.post(f"/ext/requests/{rid}/decide", headers=H_A, json={"decision": "APPROVED"})
check("管理员 A 可审批通过", r.status_code == 200, f"实际 {r.status_code} {r.text[:150]}")
check("审批后 B 获得 product-p1 read",
      any(a.dim_id == "product-p1" and a.permission == "read"
          for a in s.grants.get(CONSUMER_B, [])),
      f"实际 grants={s.grants.get(CONSUMER_B)}")

# 非管理员不能审批
r = c.post("/ext/requests", headers=H_B, json={
    "kind": "join", "dim_id": "product-p1", "permission": "write"})
rid2 = r.json().get("request", {}).get("id")
r = c.post(f"/ext/requests/{rid2}/decide", headers=H_B, json={"decision": "APPROVED"})
check("非管理员 B 不能审批 product-p1 的申请（403）", r.status_code == 403, f"实际 {r.status_code}")

print()
print("══ 3. 项目引用产品（reference）→ 对方管理员审批 ══")
s = make_store()
c = make_client(s)
# A 的项目 project-prj1 引用 B 的产品 product-p2（对方管的）→ 应走审批
r = c.post("/ext/projects/project-prj1/members", headers=H_A,
           json={"product_dim_id": "product-p2"})
check("引用他人产品返回 pending", r.status_code == 200 and r.json().get("pending") is True,
      f"实际 {r.status_code} {r.text[:150]}")
rid = r.json().get("request", {}).get("id")
check("生成 reference 申请", rid is not None)
check("审批前未生效", "product-p2" not in s.project_members.get("project-prj1", []))

# B（product-p2 管理员）审批
r = c.post(f"/ext/requests/{rid}/decide", headers=H_B, json={"decision": "APPROVED"})
check("对方管理员 B 可审批引用", r.status_code == 200, f"实际 {r.status_code} {r.text[:150]}")
check("审批后引用生效", "product-p2" in s.project_members.get("project-prj1", []))

# A 引用自己管的产品 product-p1 → 直接生效（无需审批）
r = c.post("/ext/projects/project-prj1/members", headers=H_A,
           json={"product_dim_id": "product-p1"})
check("引用自己管的产品直接生效", r.status_code == 200 and r.json().get("pending") is False,
      f"实际 {r.status_code} {r.text[:150]}")
check("直接生效已落库", "product-p1" in s.project_members.get("project-prj1", []))

print()
print("══ 4. 查询接口 ══")
s = make_store()
c = make_client(s)
c.post("/ext/requests", headers=H_B, json={
    "kind": "join", "dim_id": "product-p1", "permission": "read"})
r = c.get("/ext/requests?scope=mine", headers=H_B)
check("B 查自己的申请", r.status_code == 200 and r.json().get("count", 0) >= 1, f"{r.status_code}")
r = c.get("/ext/requests?scope=pending", headers=H_A)
check("A 查待我审批", r.status_code == 200 and r.json().get("count", 0) >= 1, f"{r.status_code}")

print()
print(f"\n结果：{PASS} 通过 / {FAIL} 失败")
sys.exit(1 if FAIL else 0)

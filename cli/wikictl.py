#!/usr/bin/env python3
"""
维度管理 CLI —— 知识管理员的命令行工具

═══════════════════════════════════════════════════════════════════════════════
为什么先做 CLI（而不是 Web 前端）
═══════════════════════════════════════════════════════════════════════════════

1. 管理 API（/ext/）已经完整，CLI 只是薄封装 → 一两个小时能交付
2. Web 前端需要额外的前端工程/构建/部署，而**接口还没被真实使用验证过**
3. CLI 用起来快，能立刻让知识管理员自助操作，先解决"要改数据库"的痛点
4. 等接口稳定后，Web 前端只是换一层皮

═══════════════════════════════════════════════════════════════════════════════
用法
═══════════════════════════════════════════════════════════════════════════════

环境变量：
    WIKI_AUTH_BASE_URL   管理 API 地址（默认 http://localhost:8888）
    WIKI_AUTH_TOKEN      平台管理员令牌 或 普通 apikey

示例：
    # 我是谁
    wikictl whoami

    # 维度
    wikictl dim list
    wikictl dim get product-p1
    wikictl dim create --id product-p4 --type product --name 产品四 --bank team-knowledge
    wikictl dim create --id product-p4 --type product --name 产品四 \
        --bank team-knowledge --admin consumer-xxx

    # 授权
    wikictl grant list
    wikictl grant list --dim product-p1
    wikictl grant set --consumer consumer-xxx --dim product-p1 --perm read
    wikictl grant set --consumer consumer-xxx --dim product-p1 --perm none   # = 撤销

    # 项目 ↔ 产品
    wikictl project show project-prj1
    wikictl project add project-prj1 product-p4
    wikictl project remove project-prj1 product-p4

    # 查看某人的有效维度（含项目展开）
    wikictl effective consumer-xxx

    # 凭据同步（从 HiMarket 拉）
    wikictl cred list
    wikictl cred sync --file /tmp/creds.json

    # 审计
    wikictl audit -n 20
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("WIKI_AUTH_BASE_URL", "http://localhost:8888").rstrip("/")
TOKEN = os.environ.get("WIKI_AUTH_TOKEN", "")


# ── HTTP 封装 ─────────────────────────────────────────────────────────────────
def _req(method: str, path: str, body: dict | None = None) -> tuple[int, str]:
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERR {type(e).__name__}: {e}"


def _json(method: str, path: str, body: dict | None = None):
    code, text = _req(method, path, body)
    if code == 0:
        print(f"❌ 连接失败：{text}", file=sys.stderr)
        sys.exit(2)
    try:
        return code, json.loads(text)
    except Exception:
        return code, {"_raw": text}


def _die_if_error(code: int, payload) -> None:
    if code >= 400:
        detail = payload.get("detail") if isinstance(payload, dict) else payload
        print(f"❌ HTTP {code}：{detail}", file=sys.stderr)
        sys.exit(1)


def _table(rows: list[dict], cols: list[tuple[str, str]]) -> None:
    """极简表格打印。"""
    if not rows:
        print("  (空)")
        return
    widths = []
    for key, title in cols:
        w = max(len(title), *(len(str(r.get(key) or "-")) for r in rows))
        widths.append(min(w, 44))
    header = "  ".join(t.ljust(w) for (_, t), w in zip(cols, widths))
    print("  " + header)
    print("  " + "-" * len(header))
    for r in rows:
        cells = []
        for (key, _), w in zip(cols, widths):
            v = str(r.get(key) if r.get(key) is not None else "-")
            cells.append((v[:w - 1] + "…" if len(v) > w else v).ljust(w))
        print("  " + "  ".join(cells))


# ── 命令实现 ──────────────────────────────────────────────────────────────────
def cmd_whoami(args):
    code, d = _json("GET", "/ext/whoami")
    _die_if_error(code, d)
    print(f"  身份      : {d.get('consumer_id')}")
    print(f"  用户名    : {d.get('username') or '-'}")
    print(f"  平台管理员: {'是' if d.get('is_platform_admin') else '否'}")
    print(f"  可管维度  : {', '.join(d.get('managed_dims') or []) or '-'}")
    g = d.get("granted_dims") or []
    print(f"  已获授权  : {len(g)} 个")
    for x in g:
        print(f"    {x['dim_id']:<20} {x['permission']:<6} via={x['via']}")


def cmd_dim_list(args):
    q = f"?bank_id={args.bank}" if args.bank else ""
    code, d = _json("GET", f"/ext/dims{q}")
    _die_if_error(code, d)
    print(f"  共 {d.get('count', 0)} 个维度")
    _table(d.get("dims") or [], [
        ("dim_id", "维度ID"), ("dim_type", "类型"), ("name", "名称"),
        ("bank_id", "隔离区"), ("admin_consumer_id", "管理员"), ("status", "状态"),
    ])


def cmd_dim_get(args):
    code, d = _json("GET", f"/ext/dims/{args.dim_id}")
    _die_if_error(code, d)
    print(json.dumps(d, ensure_ascii=False, indent=2))


def cmd_dim_create(args):
    body = {
        "dim_id": args.id, "dim_type": args.type, "name": args.name,
        "bank_id": args.bank, "admin_consumer_id": args.admin,
        "tag_prefix": args.tag or args.id, "description": args.desc,
    }
    code, d = _json("POST", "/ext/dims", body)
    _die_if_error(code, d)
    print(f"  ✅ 维度已保存：{args.id}")


def cmd_dim_delete(args):
    code, d = _json("DELETE", f"/ext/dims/{args.dim_id}")
    _die_if_error(code, d)
    print(f"  ✅ 维度已删除：{args.dim_id}")


def cmd_grant_list(args):
    qs = []
    if args.dim:
        qs.append(f"dim_id={args.dim}")
    if args.consumer:
        qs.append(f"consumer_id={args.consumer}")
    q = ("?" + "&".join(qs)) if qs else ""
    code, d = _json("GET", f"/ext/grants{q}")
    _die_if_error(code, d)
    print(f"  共 {d.get('count', 0)} 条授权")
    _table(d.get("grants") or [], [
        ("consumer_id", "消费者"), ("dim_id", "维度"),
        ("permission", "权限"), ("status", "状态"), ("granted_by", "授权人"),
    ])


def cmd_grant_set(args):
    code, d = _json("PUT", "/ext/grants", {
        "consumer_id": args.consumer, "dim_id": args.dim, "permission": args.perm,
    })
    _die_if_error(code, d)
    verb = "撤销" if args.perm == "none" else f"设为 {args.perm}"
    print(f"  ✅ 已{verb}：{args.consumer} ← {args.dim}")


def cmd_project_show(args):
    code, d = _json("GET", f"/ext/projects/{args.project_dim_id}/members")
    _die_if_error(code, d)
    print(f"  项目 {args.project_dim_id} 集成了 {d.get('count', 0)} 个产品：")
    for m in d.get("members") or []:
        print(f"    {m.get('product_dim_id')}")


def cmd_project_add(args):
    code, d = _json("POST", f"/ext/projects/{args.project_dim_id}/members",
                    {"product_dim_id": args.product_dim_id})
    _die_if_error(code, d)
    print(f"  ✅ 已加入：{args.product_dim_id} → {args.project_dim_id}")


def cmd_project_remove(args):
    code, d = _json("DELETE",
                    f"/ext/projects/{args.project_dim_id}/members/{args.product_dim_id}")
    _die_if_error(code, d)
    print(f"  ✅ 已移除：{args.product_dim_id} ← {args.project_dim_id}")


def cmd_effective(args):
    code, d = _json("GET", f"/ext/effective?consumer_id={args.consumer}")
    _die_if_error(code, d)
    print(f"  {args.consumer} 的有效维度（{d.get('count', 0)} 个）：")
    _table(d.get("dims") or [], [
        ("dim_id", "维度"), ("tag_prefix", "标签"),
        ("bank_id", "隔离区"), ("permission", "权限"), ("via", "来源"),
    ])


def cmd_cred_list(args):
    code, d = _json("GET", "/ext/credentials")
    _die_if_error(code, d)
    print(f"  已登记凭据 {d.get('count', 0)} 条")
    _table(d.get("credentials") or [], [
        ("consumer_id", "消费者"), ("username", "用户名"),
        ("api_key_prefix", "凭据前缀"), ("status", "状态"),
    ])


def cmd_cred_sync(args):
    try:
        with open(args.file, encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        print(f"❌ 读取文件失败：{e}", file=sys.stderr)
        sys.exit(1)
    rows = payload.get("rows") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        print("❌ 文件格式应为 {rows:[...]} 或 [...]", file=sys.stderr)
        sys.exit(1)
    code, d = _json("POST", "/ext/credentials/sync", {"rows": rows})
    _die_if_error(code, d)
    print(f"  ✅ 同步完成：收到 {d.get('received')} 写入 {d.get('upserted')} "
          f"跳过 {d.get('skipped')}")
    for e in (d.get("errors") or [])[:5]:
        print(f"    ⚠️ {e}")


def cmd_audit(args):
    q = f"?limit={args.n}"
    if args.target:
        q += f"&target={args.target}"
    code, d = _json("GET", f"/ext/audit{q}")
    _die_if_error(code, d)
    print(f"  最近 {d.get('count', 0)} 条审计：")
    _table(d.get("items") or [], [
        ("created_at", "时间"), ("actor", "操作者"),
        ("action", "动作"), ("target", "目标"),
    ])


# ── 申请 → 审批 ────────────────────────────────────────────────────────────────
def cmd_request_list(args):
    q = f"?scope={args.scope}"
    code, d = _json("GET", f"/ext/requests{q}")
    _die_if_error(code, d)
    print(f"  共 {d.get('count', 0)} 条申请（scope={args.scope}）")
    _table(d.get("requests") or [], [
        ("id", "ID"), ("kind", "类型"), ("requester_id", "申请人"),
        ("dim_id", "维度"), ("product_dim_id", "产品"),
        ("permission", "权限"), ("status", "状态"),
    ])


def cmd_request_join(args):
    code, d = _json("POST", "/ext/requests", {
        "kind": "join", "dim_id": args.dim_id, "permission": args.perm,
    })
    _die_if_error(code, d)
    r = (d.get("request") or {})
    print(f"  ✅ 已提交申请：挂载 {args.dim_id}（{args.perm}） id={r.get('id')}")


def cmd_request_reference(args):
    code, d = _json("POST", "/ext/requests", {
        "kind": "reference",
        "project_dim_id": args.project_dim_id,
        "product_dim_id": args.product_dim_id,
    })
    _die_if_error(code, d)
    r = (d.get("request") or {})
    print(f"  ✅ 已提交引用申请：项目 {args.project_dim_id} ← 产品 "
          f"{args.product_dim_id} id={r.get('id')}")


def cmd_request_decide(args):
    code, d = _json("POST", f"/ext/requests/{args.request_id}/decide",
                    {"decision": args.decision})
    _die_if_error(code, d)
    print(f"  ✅ 已审批：申请 #{args.request_id} = {args.decision}")


# ── 参数解析 ──────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wikictl",
        description="维度管理 CLI（多维度知识共享）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="环境变量：WIKI_AUTH_BASE_URL / WIKI_AUTH_TOKEN",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("whoami", help="显示当前身份与权限").set_defaults(func=cmd_whoami)

    d = sub.add_parser("dim", help="维度管理").add_subparsers(dest="sub", required=True)
    dl = d.add_parser("list", help="列维度"); dl.add_argument("--bank")
    dl.set_defaults(func=cmd_dim_list)
    dg = d.add_parser("get", help="维度详情"); dg.add_argument("dim_id")
    dg.set_defaults(func=cmd_dim_get)
    dc = d.add_parser("create", help="建/改维度（平台管理员）")
    dc.add_argument("--id", required=True); dc.add_argument("--type", required=True,
        choices=["product", "project", "platform", "tech"])
    dc.add_argument("--name", required=True); dc.add_argument("--bank", required=True)
    dc.add_argument("--admin", help="维度管理员 consumer_id")
    dc.add_argument("--tag", help="检索标签（默认同 id）")
    dc.add_argument("--desc")
    dc.set_defaults(func=cmd_dim_create)
    dd = d.add_parser("delete", help="删维度（平台管理员）")
    dd.add_argument("dim_id"); dd.set_defaults(func=cmd_dim_delete)

    g = sub.add_parser("grant", help="授权管理").add_subparsers(dest="sub", required=True)
    gl = g.add_parser("list", help="列授权")
    gl.add_argument("--dim"); gl.add_argument("--consumer")
    gl.set_defaults(func=cmd_grant_list)
    gs = g.add_parser("set", help="设置授权（none=撤销）")
    gs.add_argument("--consumer", required=True)
    gs.add_argument("--dim", required=True)
    gs.add_argument("--perm", required=True, choices=["none", "read", "write"])
    gs.set_defaults(func=cmd_grant_set)

    pr = sub.add_parser("project", help="项目↔产品").add_subparsers(dest="sub", required=True)
    ps = pr.add_parser("show", help="列项目集成的产品")
    ps.add_argument("project_dim_id"); ps.set_defaults(func=cmd_project_show)
    pa = pr.add_parser("add", help="加产品到项目")
    pa.add_argument("project_dim_id"); pa.add_argument("product_dim_id")
    pa.set_defaults(func=cmd_project_add)
    prm = pr.add_parser("remove", help="从项目移除产品")
    prm.add_argument("project_dim_id"); prm.add_argument("product_dim_id")
    prm.set_defaults(func=cmd_project_remove)

    ef = sub.add_parser("effective", help="某人的有效维度（含项目展开）")
    ef.add_argument("consumer"); ef.set_defaults(func=cmd_effective)

    c = sub.add_parser("cred", help="凭据管理").add_subparsers(dest="sub", required=True)
    cl = c.add_parser("list", help="列凭据（脱敏）"); cl.set_defaults(func=cmd_cred_list)
    cs = c.add_parser("sync", help="从 HiMarket 同步（需 JSON 文件）")
    cs.add_argument("--file", required=True); cs.set_defaults(func=cmd_cred_sync)

    a = sub.add_parser("audit", help="审计日志（平台管理员）")
    a.add_argument("-n", type=int, default=20); a.add_argument("--target")
    a.set_defaults(func=cmd_audit)

    r = sub.add_parser("request", help="申请→审批（挂载维度/引用产品）").add_subparsers(dest="sub", required=True)
    rl = r.add_parser("list", help="列申请（mine=我的；pending=待我审批）")
    rl.add_argument("--scope", choices=["mine", "pending"], default="mine")
    rl.set_defaults(func=cmd_request_list)
    rj = r.add_parser("join", help="申请挂载维度")
    rj.add_argument("--dim", dest="dim_id", required=True)
    rj.add_argument("--perm", choices=["read", "write"], required=True)
    rj.set_defaults(func=cmd_request_join)
    rr = r.add_parser("reference", help="申请项目引用产品")
    rr.add_argument("--project", dest="project_dim_id", required=True)
    rr.add_argument("--product", dest="product_dim_id", required=True)
    rr.set_defaults(func=cmd_request_reference)
    rd = r.add_parser("decide", help="审批申请")
    rd.add_argument("request_id", type=int)
    rd.add_argument("--decision", choices=["APPROVED", "REJECTED"], required=True)
    rd.set_defaults(func=cmd_request_decide)

    return p


def main():
    if not TOKEN:
        print("⚠️ 未设置 WIKI_AUTH_TOKEN —— 多数命令会返回 401", file=sys.stderr)
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

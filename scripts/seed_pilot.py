"""Seed 试点维度数据（在容器内执行，避免 shell 转义问题）"""

import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"
BANK = "team-knowledge"
NIU = "consumer-a8238936cb114765be9a1c4efc6eac39"
DOUYI = "consumer-11c463336a154e9fbdd2f80ade49ad0c"
AILLM = "consumer-50310ba860004a328cb8f1d38c84af0e"

DIMS = [
    ("product-p1", "product", "产品一", "product-p1", BANK, NIU),
    ("product-p2", "product", "产品二", "product-p2", BANK, NIU),
    ("product-p3", "product", "产品三", "product-p3", BANK, NIU),
    ("project-prj1", "project", "项目一", "project-prj1", BANK, NIU),
    ("platform-higress", "platform", "Higress 网关", "platform-higress", BANK, NIU),
    ("tech-ops", "tech", "运维技术域", "tech-ops", BANK, NIU),
]

GRANTS = [
    (NIU, "product-p1", "write"),
    (NIU, "product-p2", "write"),
    (NIU, "product-p3", "write"),
    (NIU, "platform-higress", "write"),
    (NIU, "tech-ops", "write"),
    (NIU, "project-prj1", "read"),
    # 窦毅：只挂载「项目一」→ 应自动获得三个产品（核心场景）
    (DOUYI, "project-prj1", "read"),
    # 测试台：仅平台维度只读（用于验证隔离）
    (AILLM, "platform-higress", "read"),
]

PROJECT = "project-prj1"
PRODUCTS = ["product-p1", "product-p2", "product-p3"]


async def main():
    c = await asyncpg.connect(PG)

    await c.execute("DELETE FROM wiki_auth.dim_project_member")
    await c.execute("DELETE FROM wiki_auth.dim_grant")
    await c.execute("DELETE FROM wiki_auth.dim_dimension")

    for row in DIMS:
        await c.execute(
            """
            INSERT INTO wiki_auth.dim_dimension
                (dim_id, dim_type, name, tag_prefix, bank_id, admin_consumer_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            *row,
        )

    for cid, dim, perm in GRANTS:
        await c.execute(
            """
            INSERT INTO wiki_auth.dim_grant
                (consumer_id, dim_id, permission, granted_by, status)
            VALUES ($1, $2, $3, 'seed', 'APPROVED')
            """,
            cid, dim, perm,
        )

    for p in PRODUCTS:
        await c.execute(
            """
            INSERT INTO wiki_auth.dim_project_member
                (project_dim_id, product_dim_id, created_by)
            VALUES ($1, $2, 'seed')
            """,
            PROJECT, p,
        )

    print(f"  维度={len(DIMS)} 授权={len(GRANTS)} 项目关联={len(PRODUCTS)}")

    print()
    print("  ── 有效授权（v_effective_dim）──")
    rows = await c.fetch(
        "select consumer_id, dim_id, permission, via "
        "from wiki_auth.v_effective_dim order by consumer_id, dim_id"
    )
    for r in rows:
        print(f"    {r['consumer_id'][:24]}  {r['dim_id']:<18} "
              f"{r['permission']:<6} {r['via']}")

    await c.close()


asyncio.run(main())

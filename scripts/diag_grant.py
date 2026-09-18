"""诊断：撤销后数据库里到底还有没有授权"""
import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"
DOUYI = "consumer-11c463336a154e9fbdd2f80ade49ad0c"


async def main():
    c = await asyncpg.connect(PG)
    print("── dim_grant 里 douyi 的记录 ──")
    rows = await c.fetch("""
        SELECT consumer_id, dim_id, permission, status, updated_at
          FROM wiki_auth.dim_grant WHERE consumer_id = $1
         ORDER BY dim_id
    """, DOUYI)
    for r in rows:
        print(f"  {r['dim_id']:<18} {r['permission']:<6} {r['status']:<9} {r['updated_at']}")

    print()
    print("── v_effective_dim 里 douyi（视图只取 APPROVED）──")
    rows2 = await c.fetch("""
        SELECT dim_id, permission, via FROM wiki_auth.v_effective_dim
         WHERE consumer_id = $1 ORDER BY dim_id
    """, DOUYI)
    for r in rows2:
        print(f"  {r['dim_id']:<18} {r['permission']:<6} {r['via']}")
    if not rows2:
        print("  (无)")

    await c.close()


asyncio.run(main())

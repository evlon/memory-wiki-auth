"""检查授权数据（维度/授权/项目关联/凭据）"""
import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"


async def main():
    c = await asyncpg.connect(PG)

    n_dim = await c.fetchval("SELECT count(*) FROM wiki_auth.dim_dimension")
    n_grant = await c.fetchval("SELECT count(*) FROM wiki_auth.dim_grant")
    n_proj = await c.fetchval("SELECT count(*) FROM wiki_auth.dim_project_member")
    n_cred = await c.fetchval("SELECT count(*) FROM wiki_auth.dim_credential")
    print(f"  维度={n_dim}  授权={n_grant}  项目关联={n_proj}  凭据={n_cred}")

    print()
    print("  ── 有效授权（含项目展开）──")
    rows = await c.fetch("""
        SELECT consumer_id, dim_id, permission, via
          FROM wiki_auth.v_effective_dim
         ORDER BY consumer_id, dim_id
    """)
    for r in rows:
        print(f"    {r['consumer_id'][:24]}  {r['dim_id']:<18} "
              f"{r['permission']:<6} {r['via']}")

    print()
    print("  ── 记忆落库情况 ──")
    rows2 = await c.fetch("""
        SELECT bank_id, count(*) AS n
          FROM public.memory_units
         WHERE bank_id LIKE 'team-%' OR bank_id LIKE 'u-%'
         GROUP BY bank_id ORDER BY bank_id
    """)
    for r in rows2:
        print(f"    {r['bank_id']:<24} {r['n']} 条")
    if not rows2:
        print("    (暂无)")

    await c.close()


asyncio.run(main())

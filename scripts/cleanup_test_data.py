"""清理测试残留数据（fresh-a/fresh-b 与隔离测试 bank）"""
import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"


async def main():
    c = await asyncpg.connect(PG)

    # 清理测试用的维度/授权
    r1 = await c.execute("DELETE FROM wiki_auth.dim_grant WHERE dim_id IN ('fresh-a','fresh-b')")
    r2 = await c.execute("DELETE FROM wiki_auth.dim_dimension WHERE dim_id IN ('fresh-a','fresh-b')")
    print("  清理测试维度授权:", r1, r2)

    # 清理测试 bank 的记忆
    for bank in ("team-fresh", "dim-test", "dim-test2", "tenant-a", "tenant-b"):
        n = await c.execute("DELETE FROM public.memory_units WHERE bank_id = $1", bank)
        print(f"  清理 {bank}: {n}")
        try:
            await c.execute("DELETE FROM public.banks WHERE bank_id = $1", bank)
        except Exception as e:
            print(f"    (banks 表删除跳过: {type(e).__name__})")

    print()
    print("  ── 清理后 ──")
    print("  维度:", await c.fetchval("SELECT count(*) FROM wiki_auth.dim_dimension"))
    print("  授权:", await c.fetchval("SELECT count(*) FROM wiki_auth.dim_grant"))
    rows = await c.fetch("""
        SELECT bank_id, count(*) AS n FROM public.memory_units
         GROUP BY bank_id ORDER BY bank_id
    """)
    for r in rows:
        print(f"    {r['bank_id']:<24} {r['n']} 条")

    await c.close()


asyncio.run(main())

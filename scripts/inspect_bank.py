"""检查 team-knowledge 里的记忆与标签（文件方式，避免 shell 转义）"""
import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"


async def main():
    c = await asyncpg.connect(PG)
    rows = await c.fetch("""
        SELECT tags, fact_type, count(*) AS n
          FROM public.memory_units
         WHERE bank_id = $1
         GROUP BY tags, fact_type
         ORDER BY n DESC
    """, "team-knowledge")
    print("  tags".ljust(42), "fact_type".ljust(14), "n")
    for r in rows:
        print("  " + str(r["tags"]).ljust(40), str(r["fact_type"]).ljust(14), r["n"])

    total = await c.fetchval(
        "SELECT count(*) FROM public.memory_units WHERE bank_id = $1", "team-knowledge"
    )
    print()
    print("  总计:", total)

    print()
    print("  最近 5 条内容:")
    rows2 = await c.fetch("""
        SELECT tags, left(text, 50) AS t
          FROM public.memory_units WHERE bank_id = $1
         ORDER BY created_at DESC LIMIT 5
    """, "team-knowledge")
    for r in rows2:
        print("   ", str(r["tags"]).ljust(28), r["t"])

    await c.close()


asyncio.run(main())

"""直接捕获生成的 SQL —— 用 monkeypatch 拦截 conn.fetch"""
import asyncio
import asyncpg
import sys

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"

CAPTURED = []
_orig_fetch = asyncpg.Connection.fetch


async def patched_fetch(self, query, *args, **kwargs):
    CAPTURED.append((query, args))
    return await _orig_fetch(self, query, *args, **kwargs)


asyncpg.Connection.fetch = patched_fetch

from hindsight_api.engine.search.retrieval import retrieve_semantic_bm25_combined_sql
from hindsight_api.engine.search.tags import TagGroupLeaf


async def main():
    conn = await asyncpg.connect(PG)
    try:
        await retrieve_semantic_bm25_combined_sql(
            conn,
            query_emb_str="[" + ",".join(["0.1"] * 1536) + "]",
            query_text="配置",
            bank_id="team-fresh",
            fact_types=["world"],
            limit=10,
            tags=None,
            tags_match="any_strict",
            tag_groups=[TagGroupLeaf(tags=["product-fresh"], match="any_strict")],
        )
    except Exception as e:
        print("执行异常:", type(e).__name__, e)
    finally:
        await conn.close()

    print()
    print(f"捕获到 {len(CAPTURED)} 条 SQL")
    for i, (q, a) in enumerate(CAPTURED):
        print(f"\n{'='*70}\n#{i} 参数个数={len(a)}")
        print(q)
        print("参数:", [str(x)[:40] for x in a])


asyncio.run(main())

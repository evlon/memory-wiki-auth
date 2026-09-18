"""用 pool（复现 API 的真实调用方式）捕获 SQL"""
import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"

CAPTURED = []
_orig_fetch = asyncpg.Connection.fetch


async def patched_fetch(self, query, *args, **kwargs):
    CAPTURED.append((query, args))
    return await _orig_fetch(self, query, *args, **kwargs)


asyncpg.Connection.fetch = patched_fetch

from hindsight_api.engine.search.retrieval import retrieve_all_fact_types_parallel


async def main():
    pool = await asyncpg.create_pool(PG, min_size=1, max_size=5)
    try:
        await retrieve_all_fact_types_parallel(
            pool=pool,
            query_text="配置",
            query_embedding_str="[" + ",".join(["0.1"] * 1536) + "]",
            bank_id="team-fresh",
            fact_types=["world", "observation"],
            thinking_budget=1000,
            tags=None,
            tags_match="any_strict",
            tag_groups=None,          # 先不带 tag_groups
            enable_temporal_retrieval=False,
            enable_graph_retrieval=False,
        )
        print("✅ 无 tag_groups 成功")
    except Exception as e:
        print("❌ 无 tag_groups 失败:", type(e).__name__, str(e)[:120])

    CAPTURED.clear()
    try:
        await retrieve_all_fact_types_parallel(
            pool=pool,
            query_text="配置",
            query_embedding_str="[" + ",".join(["0.1"] * 1536) + "]",
            bank_id="team-fresh",
            fact_types=["world", "observation"],
            thinking_budget=1000,
            tags=None,
            tags_match="any_strict",
            tag_groups=None,
            enable_temporal_retrieval=False,
            enable_graph_retrieval=False,
        )
    except Exception:
        pass

    print()
    print(f"捕获 {len(CAPTURED)} 条 SQL")
    for i, (q, a) in enumerate(CAPTURED):
        print(f"\n{'='*70}\n#{i} 参数数={len(a)}")
        print(q[:3000])
        print("参数:", [str(x)[:30] for x in a])
    await pool.close()


asyncio.run(main())

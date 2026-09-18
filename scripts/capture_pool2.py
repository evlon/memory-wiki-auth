"""用 pool + tag_groups 捕获 SQL（这是失败场景）"""
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
from hindsight_api.engine.search.tags import TagGroupLeaf


async def main():
    pool = await asyncpg.create_pool(PG, min_size=1, max_size=5)
    CAPTURED.clear()
    err = None
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
            tag_groups=[TagGroupLeaf(tags=["product-fresh"], match="any_strict")],
            enable_temporal_retrieval=False,
            enable_graph_retrieval=False,
        )
    except Exception as e:
        err = f"{type(e).__name__}: {e}"

    print("结果:", "✅ 成功" if err is None else f"❌ {err[:100]}")
    print(f"捕获 {len(CAPTURED)} 条 SQL")
    for i, (q, a) in enumerate(CAPTURED):
        print(f"\n{'='*70}\n#{i} 参数数={len(a)}")
        # 只打印含 tag 条件的部分 + 找最大 $n
        import re
        nums = sorted({int(m) for m in re.findall(r'\$(\d+)', q)})
        print("SQL 引用的参数号:", nums)
        print("实际参数个数:", len(a))
        if nums and max(nums) > len(a):
            print(f"❌ 参数不足：SQL 要 ${max(nums)}，只给 {len(a)} 个")
        print()
        print(q[:2500])
        print("参数:", [str(x)[:30] for x in a])
    await pool.close()


asyncio.run(main())

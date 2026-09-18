"""复现 MCP 的完整参数（temporal + graph 全开）"""
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


async def run(label, **over):
    CAPTURED.clear()
    kwargs = dict(
        pool=None,
        query_text="配置",
        query_embedding_str="[" + ",".join(["0.1"] * 1536) + "]",
        bank_id="team-fresh",
        fact_types=["world", "observation"],
        thinking_budget=1000,
        tags=None,
        tags_match="any_strict",
        tag_groups=[TagGroupLeaf(tags=["product-fresh"], match="any_strict")],
    )
    kwargs.update(over)
    err = None
    try:
        await retrieve_all_fact_types_parallel(**kwargs)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    print(f"  {label:<50} {'✅' if err is None else '❌ ' + err[:70]}")
    return err, list(CAPTURED)


async def main():
    pool = await asyncpg.create_pool(PG, min_size=1, max_size=5)

    await run("temporal=False graph=False",
              pool=pool, enable_temporal_retrieval=False, enable_graph_retrieval=False)
    await run("temporal=True  graph=False",
              pool=pool, enable_temporal_retrieval=True, enable_graph_retrieval=False)
    err, caps = await run("temporal=True  graph=True  ← MCP 默认",
                          pool=pool, enable_temporal_retrieval=True, enable_graph_retrieval=True)

    if err and caps:
        print()
        print("=" * 70)
        print("失败 SQL 详情：")
        for i, (q, a) in enumerate(caps):
            import re
            nums = sorted({int(m) for m in re.findall(r'\$(\d+)', q)})
            bad = nums and max(nums) > len(a)
            print(f"  #{i} 引用={nums} 实参={len(a)} {'❌参数不足' if bad else 'ok'}")
            if bad:
                print()
                print(q[:3000])
                print("参数:", [str(x)[:30] for x in a])

    await pool.close()


asyncio.run(main())

"""复现 MCP：用 VALID_RECALL_FACT_TYPES 全量 fact_type"""
import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"

CAPTURED = []
_orig_pool_fetch = asyncpg.pool.Pool.fetch


async def patched_pool_fetch(self, query, *args, **kwargs):
    CAPTURED.append((query, args))
    return await _orig_pool_fetch(self, query, *args, **kwargs)


asyncpg.pool.Pool.fetch = patched_pool_fetch

from hindsight_api.mcp_tools import VALID_RECALL_FACT_TYPES
from hindsight_api.engine.search.tags import TagGroupLeaf


async def main():
    print("VALID_RECALL_FACT_TYPES =", list(VALID_RECALL_FACT_TYPES))

    from hindsight_api.engine.memory_engine import MemoryEngine
    from hindsight_api.models import RequestContext

    engine = MemoryEngine()
    await engine.initialize()
    ctx = RequestContext(api_key="apikey-<your-api-key>")

    CAPTURED.clear()
    err = None
    try:
        res = await engine.recall_async(
            bank_id="team-fresh",
            query="配置",
            request_context=ctx,
            fact_type=list(VALID_RECALL_FACT_TYPES),   # ← MCP 的做法
            tag_groups=[TagGroupLeaf(tags=["product-fresh"], match="any_strict")],
        )
        print("\n✅ 成功:", str(res)[:150])
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        print("\n❌ 失败:", err[:200])

    import re
    print(f"\n捕获 {len(CAPTURED)} 条 SQL")
    for i, (q, a) in enumerate(CAPTURED):
        nums = sorted({int(m) for m in re.findall(r'\$(\d+)', q)})
        bad = bool(nums) and max(nums) > len(a)
        if bad:
            print(f"  #{i} ❌ 引用={nums} 实参={len(a)}")
            print()
            print(q[:3500])
            print()
            print("参数:", [str(x)[:35] for x in a])
        else:
            print(f"  #{i} ok 引用={nums} 实参={len(a)}")

    await engine.close()


asyncio.run(main())

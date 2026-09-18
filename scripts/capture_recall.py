"""复现 MCP recall_async 的完整路径，捕获坏 SQL"""
import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"

CAPTURED = []
_orig_fetch = asyncpg.Connection.fetch


async def patched_fetch(self, query, *args, **kwargs):
    CAPTURED.append((query, args))
    return await _orig_fetch(self, query, *args, **kwargs)


asyncpg.Connection.fetch = patched_fetch

# 也 patch pool 的 fetch（recall 用 pool）
_orig_pool_fetch = asyncpg.pool.Pool.fetch


async def patched_pool_fetch(self, query, *args, **kwargs):
    CAPTURED.append((query, args))
    return await _orig_pool_fetch(self, query, *args, **kwargs)


asyncpg.pool.Pool.fetch = patched_pool_fetch


async def main():
    from hindsight_api.engine.memory_engine import MemoryEngine
    from hindsight_api.models import RequestContext
    from hindsight_api.engine.search.tags import TagGroupLeaf

    # 构造 engine（参照 main.py 的方式）
    import hindsight_api.main as M
    import inspect

    print("=== 找 engine 构造方式 ===")
    src = inspect.getsource(M.main)
    for line in src.split("\n"):
        if "MemoryEngine(" in line or "memory_engine" in line.lower() and "=" in line:
            print("  ", line.strip()[:110])

    # 直接用一个最小 engine
    from hindsight_api.engine.memory_engine import Budget

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
            tag_groups=[TagGroupLeaf(tags=["product-fresh"], match="any_strict")],
            tags_match="any_strict",
        )
        print("\n✅ recall_async 成功:", str(res)[:150])
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        print("\n❌ recall_async 失败:", err[:200])

    print(f"\n捕获 {len(CAPTURED)} 条 SQL")
    import re
    for i, (q, a) in enumerate(CAPTURED):
        nums = sorted({int(m) for m in re.findall(r'\$(\d+)', q)})
        bad = bool(nums) and max(nums) > len(a)
        print(f"  #{i} 引用={nums} 实参={len(a)} {'❌参数不足' if bad else 'ok'}")
        if bad:
            print()
            print(q[:3000])
            print("参数:", [str(x)[:35] for x in a])
            print()

    await engine.close()


asyncio.run(main())

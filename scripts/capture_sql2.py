"""捕获多 fact_type 场景的 SQL（复现 API 的失败）"""
import asyncio
import asyncpg

PG = "postgresql://hindsight:<your-db-password>@hindsight-pg:5432/hindsight"

CAPTURED = []
_orig_fetch = asyncpg.Connection.fetch


async def patched_fetch(self, query, *args, **kwargs):
    CAPTURED.append((query, args))
    return await _orig_fetch(self, query, *args, **kwargs)


asyncpg.Connection.fetch = patched_fetch

from hindsight_api.engine.search.retrieval import retrieve_semantic_bm25_combined_sql
from hindsight_api.engine.search.tags import TagGroupLeaf


async def try_case(label, fact_types, tag_groups):
    CAPTURED.clear()
    conn = await asyncpg.connect(PG)
    err = None
    try:
        await retrieve_semantic_bm25_combined_sql(
            conn,
            query_emb_str="[" + ",".join(["0.1"] * 1536) + "]",
            query_text="配置",
            bank_id="team-fresh",
            fact_types=fact_types,
            limit=10,
            tags=None,
            tags_match="any_strict",
            tag_groups=tag_groups,
        )
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        await conn.close()

    status = "✅ 成功" if err is None else f"❌ {err[:80]}"
    print(f"  {label:<45} {status}")
    return err, list(CAPTURED)


async def main():
    leaf = [TagGroupLeaf(tags=["product-fresh"], match="any_strict")]

    cases = [
        ("1 fact_type (world)", ["world"]),
        ("2 fact_types", ["world", "observation"]),
        ("3 fact_types", ["world", "observation", "experience"]),
    ]
    for label, fts in cases:
        err, caps = await try_case(label, fts, leaf)
        if err and caps:
            print()
            print("    " + "=" * 66)
            print("    失败时的 SQL:")
            q, a = caps[0]
            print("    参数个数:", len(a))
            # 只打印 SQL 结构（去掉长内容）
            for line in q.split("\n"):
                print("    " + line[:150])
            print()
            break


asyncio.run(main())

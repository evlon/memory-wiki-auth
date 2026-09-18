"""验证：validator 注入的是 dict，而 SQL 构造期望 pydantic 对象"""
import asyncio
from hindsight_api.engine.search.tags import (
    build_tag_groups_where_clause, TagGroupLeaf, TagGroupOr,
)

print("=" * 70)
print("A. 传 pydantic 对象（正常路径）")
groups_ok = [TagGroupOr(filters=[TagGroupLeaf(tags=["product-fresh"], match="any_strict")])]
try:
    c, p, _ = build_tag_groups_where_clause(groups_ok, 5)
    print("   clause:", repr(c))
    print("   params:", p)
except Exception as e:
    print("   ❌", type(e).__name__, e)

print()
print("=" * 70)
print("B. 传 validator 注入的 dict（我们的路径）")
groups_dict = [{"or": [{"tags": ["product-fresh"], "match": "any_strict"}]}]
try:
    c2, p2, _ = build_tag_groups_where_clause(groups_dict, 5)
    print("   clause:", repr(c2))
    print("   params:", p2)
except Exception as e:
    print("   ❌", type(e).__name__, str(e)[:200])

print()
print("=" * 70)
print("C. 传单个 dict leaf")
groups_dict2 = [{"tags": ["product-fresh"], "match": "any_strict"}]
try:
    c3, p3, _ = build_tag_groups_where_clause(groups_dict2, 5)
    print("   clause:", repr(c3))
    print("   params:", p3)
except Exception as e:
    print("   ❌", type(e).__name__, str(e)[:200])

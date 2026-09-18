"""更新测试断言：dict → pydantic 对象（配合 e468 修复）"""
import re

p = "tests/test_validator.py"
s = open(p, encoding="utf-8").read()
orig = s

# 1) 单 leaf 断言
s = s.replace(
    '''        assert r.tag_groups[0]["tags"] == ["product-p1"]
        assert r.tag_groups[0]["match"] == "any_strict", "⭐ 必须用 _strict"''',
    '''        # ⚠️ 必须是 pydantic 对象（dict 会导致 SQL 语法错误，见 e468）
        from hindsight_api.engine.search.tags import TagGroupLeaf
        assert isinstance(r.tag_groups[0], TagGroupLeaf), "必须是 TagGroupLeaf，不能是 dict"
        assert r.tag_groups[0].tags == ["product-p1"]
        assert r.tag_groups[0].match == "any_strict", "⭐ 必须用 _strict"''')

# 2) 项目展开断言
s = s.replace(
    '''        tg = r.tag_groups[0]
        assert "or" in tg, f"多个维度必须用 or 表达，实际：{tg}"
        tags = {leaf["tags"][0] for leaf in tg["or"]}
        assert tags == {"project-prj1", "product-p1", "product-p2", "product-p3"}, \\
            f"应展开为 4 个维度，实际：{tags}"
        # ⭐ 全部必须是 _strict
        for leaf in tg["or"]:
            assert leaf["match"] == "any_strict"''',
    '''        from hindsight_api.engine.search.tags import TagGroupOr
        tg = r.tag_groups[0]
        assert isinstance(tg, TagGroupOr), f"多个维度必须用 TagGroupOr，实际：{type(tg)}"
        tags = {leaf.tags[0] for leaf in tg.filters}
        assert tags == {"project-prj1", "product-p1", "product-p2", "product-p3"}, \\
            f"应展开为 4 个维度，实际：{tags}"
        # ⭐ 全部必须是 _strict
        for leaf in tg.filters:
            assert leaf.match == "any_strict"''')

# 3) 其余两处 tags 提取
s = s.replace(
    '''        tags = {leaf["tags"][0] for leaf in (r.tag_groups[0].get("or") or [r.tag_groups[0]])}''',
    '''        _g = r.tag_groups[0]
        _leaves = getattr(_g, "filters", [_g])
        tags = {leaf.tags[0] for leaf in _leaves}''')

# 4) strict 递归校验
s = s.replace(
    '''        def check(groups):
            for g in groups:
                if "tags" in g:
                    assert g["match"] == "any_strict", f"⭐ 必须 _strict，实际 {g}"
                for key in ("or", "and"):
                    if key in g:
                        check(g[key])
                if "not" in g:
                    check([g["not"]])

        check(r.tag_groups)''',
    '''        from hindsight_api.engine.search.tags import (
            TagGroupLeaf, TagGroupAnd, TagGroupOr, TagGroupNot,
        )

        def check(groups):
            for g in groups:
                assert not isinstance(g, dict), f"⭐ 不得是 dict（会导致 SQL 错误）：{g}"
                if isinstance(g, TagGroupLeaf):
                    assert g.match == "any_strict", f"⭐ 必须 _strict，实际 {g}"
                elif isinstance(g, (TagGroupAnd, TagGroupOr)):
                    check(g.filters)
                elif isinstance(g, TagGroupNot):
                    check([g.filter])

        check(r.tag_groups)''')

open(p, "w", encoding="utf-8").write(s)
print("已更新" if s != orig else "⚠️ 未匹配到任何替换，请检查")
print("剩余 dict 断言:", len(re.findall(r'tag_groups\[0\]\["', s)))

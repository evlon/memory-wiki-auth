"""给测试加「共享 store 单例」的回归测试（e491 修复）"""

p = "tests/test_validator.py"
s = open(p, encoding="utf-8").read()

s += '''

# ══════════════════════════════════════════════════════════════════════════════
# 【11】共享 store 单例（e491 修复的回归测试）⭐ 安全关键
# ══════════════════════════════════════════════════════════════════════════════

class TestSharedStore:
    """
    ⚠️ 背景（e491 实测发现的缺陷）：
    Hindsight 分别实例化三个扩展，若每个都 `DimAuthStore(...)`，
    则三份 `_cache` 互不相通 → 管理 API 的 invalidate() 清不到
    validator 的缓存 → **撤销授权最长 30 秒后才生效**。

    实测证据：撤销后立即访问，仍能读到数据。

    修复：进程级单例，三个扩展共用同一个 store。
    """

    def test_同一schema返回同一实例(self):
        from wiki_auth.store import get_shared_store
        a = get_shared_store("postgresql://x/y", schema="wiki_auth")
        b = get_shared_store("postgresql://x/y", schema="wiki_auth")
        assert a is b, "⭐ 必须返回同一实例（否则缓存不互通）"

    def test_不同schema返回不同实例(self):
        from wiki_auth.store import get_shared_store
        a = get_shared_store("postgresql://x/y", schema="wiki_auth")
        b = get_shared_store("postgresql://x/y", schema="wiki_auth2")
        assert a is not b, "不同 schema 应独立（避免串库）"

    def test_三个扩展共用同一store(self):
        """
        ⭐ 核心断言：validator / tenant / admin 三个扩展拿到的 store 必须相同。
        """
        from wiki_auth.store import get_shared_store

        class Cfg(dict):
            def get(self, k, d=None):
                return dict.get(self, k, d)

        s1 = get_shared_store("postgresql://x/y", schema="wiki_auth")
        s2 = get_shared_store("postgresql://x/y", schema="wiki_auth")
        s3 = get_shared_store("postgresql://x/y", schema="wiki_auth")
        assert s1 is s2 is s3, "⭐ 三个扩展必须共用同一 store 实例"

    def test_缓存失效跨实例可见(self):
        """
        ⭐ 关键：在一个实例上 invalidate，另一个实例（同一单例）应立即看不到旧缓存。
        """
        from wiki_auth.store import get_shared_store, DimAccess

        st = get_shared_store("postgresql://x/y", schema="wiki_auth")
        # 手动塞一条缓存
        from wiki_auth.store import _CacheEntry
        import time as _t
        st._cache["consumer-test-0001"] = _CacheEntry(
            access=[DimAccess(dim_id="product-p1", tag_prefix="product-p1",
                              bank_id="team-knowledge", permission="read")],
            expires_at=_t.monotonic() + 999,
        )
        # 另一个"扩展"拿到的是同一实例 → invalidate 立即生效
        st2 = get_shared_store("postgresql://x/y", schema="wiki_auth")
        st2.invalidate("consumer-test-0001")
        assert "consumer-test-0001" not in st._cache, \\
            "⭐ invalidate 必须对共用实例立即可见"
        st._cache.clear()
'''

open(p, "w", encoding="utf-8").write(s)
print("已追加共享 store 测试")

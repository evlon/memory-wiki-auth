"""给测试加 tenant 认证用例（配合 e473 修复）"""

p = "tests/test_validator.py"
s = open(p, encoding="utf-8").read()

s += '''

# ══════════════════════════════════════════════════════════════════════════════
# 【10】MCP 握手认证（e473 修复的回归测试）
# ══════════════════════════════════════════════════════════════════════════════

class TestTenantAuth:
    """
    ⚠️ 背景：Hindsight 的 OperationValidator 只在**具体操作**时被调用，
    MCP 的 **initialize 握手不经过它**。

    实测（e473）：无凭据客户端 initialize 返回 **200** 并拿到 session，
    直到 tools/call 才被拦（且报 "Unknown tool"）。
    数据安全但语义错误 —— 客户端以为连上了。

    修复：用 TenantExtension.authenticate_mcp() 在握手时校验，
    无效则抛 AuthenticationError → Hindsight 返回 401。
    """

    @pytest.mark.asyncio
    async def test_无凭据_握手401(self):
        from wiki_auth.tenant import DimAuthTenantExtension
        from hindsight_api.extensions import AuthenticationError

        s = FakeStore()
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"
        ext._enforce = True
        ext._store = s

        with pytest.raises(AuthenticationError):
            await ext.authenticate_mcp(FakeRequestContext(api_key=None))

    @pytest.mark.asyncio
    async def test_未登记apikey_握手401(self):
        from wiki_auth.tenant import DimAuthTenantExtension
        from hindsight_api.extensions import AuthenticationError

        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"; ext._enforce = True; ext._store = s

        with pytest.raises(AuthenticationError):
            await ext.authenticate_mcp(
                FakeRequestContext(api_key="apikey-<your-api-key>")
            )

    @pytest.mark.asyncio
    async def test_有效apikey_握手通过(self):
        from wiki_auth.tenant import DimAuthTenantExtension

        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A, "niukunliang")
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"; ext._enforce = True; ext._store = s

        # 不应抛异常
        await ext.authenticate_mcp(FakeRequestContext(api_key=KEY_A))

    @pytest.mark.asyncio
    async def test_透传头身份_握手通过(self):
        from wiki_auth.tenant import DimAuthTenantExtension

        s = FakeStore()
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"; ext._enforce = True; ext._store = s

        await ext.authenticate_mcp(
            FakeRequestContext(extra_headers={"x-dim-consumer": CONSUMER_A})
        )

    @pytest.mark.asyncio
    async def test_内部任务跳过认证(self):
        """worker 重放没有凭据，必须跳过（否则任务永远失败）。"""
        from wiki_auth.tenant import DimAuthTenantExtension

        s = FakeStore()
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"; ext._enforce = True; ext._store = s

        # 不应抛异常
        await ext.authenticate_mcp(FakeRequestContext(internal=True, user_initiated=True))
'''

open(p, "w", encoding="utf-8").write(s)
print("已追加 tenant 认证测试")

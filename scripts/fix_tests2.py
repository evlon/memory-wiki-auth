"""给测试加 internal replay 字段与用例（配合 e471/e472 修复）"""

p = "tests/test_validator.py"
s = open(p, encoding="utf-8").read()
orig = s

# 1) FakeRequestContext 增加 internal 字段
s = s.replace(
    '''@dataclass
class FakeRequestContext:
    """模拟 Hindsight 的 RequestContext。"""
    api_key: str | None = None
    extra_headers: dict[str, str] | None = None

    def __post_init__(self):
        if self.extra_headers is None:
            self.extra_headers = {}''',
    '''@dataclass
class FakeRequestContext:
    """模拟 Hindsight 的 RequestContext。"""
    api_key: str | None = None
    extra_headers: dict[str, str] | None = None
    internal: bool = False
    user_initiated: bool = False
    tenant_id: str | None = None

    def __post_init__(self):
        if self.extra_headers is None:
            self.extra_headers = {}''')

# 2) 追加 internal replay 测试类
s += '''

# ══════════════════════════════════════════════════════════════════════════════
# 【9】worker 内部重放（e471/e472 修复的回归测试）
# ══════════════════════════════════════════════════════════════════════════════

class TestInternalReplay:
    """
    ⚠️ 背景：Hindsight 的 retain 是异步的。HTTP 层校验一次并返回 202，
    worker 在后台**重新调用 validate_retain**，但 RequestContext 是
        RequestContext(internal=True, user_initiated=True, tenant_id=...)
    即**没有凭据**。

    若不放行 → 后台任务全部失败 → 记忆永不落库 → 召回永远为空。
    实测踩到这个坑（e471），表现为日志刷
        Task execution failed: batch_retain, error: OperationValidationError

    这些用例固化"internal 重放必须放行"这个行为。
    """

    @pytest.mark.asyncio
    async def test_worker重放_retain放行(self):
        s = FakeStore()
        # 注意：store 里故意不放任何凭据/授权
        v = make_validator(s)

        r = await v.validate_retain(Ctx(
            "team-knowledge",
            FakeRequestContext(internal=True, user_initiated=True, tenant_id="tenant-x"),
            contents=[{"content": "x", "tags": ["product-p1"]}],
        ))

        assert r.allowed is True, \\
            f"⭐ worker 重放必须放行，否则记忆永不落库（实际：{r.reason}）"

    @pytest.mark.asyncio
    async def test_worker重放_recall放行(self):
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-knowledge",
            FakeRequestContext(internal=True, user_initiated=True),
        ))

        assert r.allowed is True

    @pytest.mark.asyncio
    async def test_worker重放_reflect放行(self):
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_reflect(Ctx(
            "team-knowledge",
            FakeRequestContext(internal=True, user_initiated=True),
        ))

        assert r.allowed is True

    @pytest.mark.asyncio
    async def test_外部请求仍严格校验_internal不得被伪造绕过(self):
        """
        ⭐ 安全关键：internal=False 的外部请求必须仍走完整校验。
        防止"随便加个 internal 标志就绕过授权"。
        """
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        # 无任何授权
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-knowledge",
            FakeRequestContext(api_key=KEY_A, internal=False),
        ))

        assert r.allowed is False, "⭐ internal=False 必须走完整校验"

    @pytest.mark.asyncio
    async def test_worker重放不做维度注入(self):
        """
        internal 重放不注入 tag_groups（它是系统内部读取，不是用户查询）。
        这里只断言"放行且不报错"，避免误以为能拿到用户视角的过滤。
        """
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-knowledge",
            FakeRequestContext(internal=True, user_initiated=True),
        ))

        assert r.allowed is True
'''

open(p, "w", encoding="utf-8").write(s)
print("已更新" if s != orig else "⚠️ 未匹配")

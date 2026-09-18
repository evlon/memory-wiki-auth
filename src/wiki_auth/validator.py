"""
维度授权 validator —— Hindsight 的 OperationValidatorExtension 实现

═══════════════════════════════════════════════════════════════════════════════
⚠️⚠️ 这是整个方案的安全关键路径。改动前请完整阅读以下说明。
═══════════════════════════════════════════════════════════════════════════════

它做什么：
   在每次 recall / retain / reflect 之前，检查"这个人能不能访问这个隔离区"，
   并**注入维度过滤条件**（tag_groups），使一次检索只返回他有权看到的维度。

安全设计（四条铁律）：

  铁律 1 · fail-closed
      任何异常 / 无法识别身份 / 查不到授权 → **拒绝**。
      绝不出现"查不到就放行"的写法。

  铁律 2 · 强制 _strict 匹配
      注入的 tag_groups 一律用 `any_strict`。
      原因：默认的 `any`/`all` 模式**会包含未打标签的记忆** —— 那是泄漏口。

  铁律 3 · 个人区硬规则
      `u-<x>` 只有 `<x>` 本人可访问，不走授权表，不可被任何授权绕过。

  铁律 4 · 不依赖 filter_mcp_tools
      那个钩子在异常时是 fail-OPEN（返回未过滤工具）。
      数据安全只靠 validate_*。

═══════════════════════════════════════════════════════════════════════════════
⚠️⚠️ 命名约束（e441 实测发现，极重要）
═══════════════════════════════════════════════════════════════════════════════

**bank 名不能含冒号 `:`** —— 会导致 Hindsight 内部 SQL 语法错误：

    PostgresSyntaxError: syntax error at or near "ORDER"

实测对比（同一时刻，只改 bank 名）：
    bank-no-colon     → recall 正常
    team:knowledge    → recall SQL 错误   ❌
    team-knowledge    → recall 正常       ✅

**原因推测**：bank 名被拼进 SQL，冒号破坏了语法。Hindsight 未对 bank 名转义
—— 这是上游的真实缺陷，建议反馈。

**因此本方案统一用连字符 `-` 作为分隔符**：
    bank : `u-<用户名>`、`team-<团队>`
    tag  : `product-p1`、`project-prj1`、`platform-higress`、`tech-ops`

═══════════════════════════════════════════════════════════════════════════════
⚠️ 关键设计约束：**项目与它集成的产品必须在同一个 bank 内**
═══════════════════════════════════════════════════════════════════════════════

为什么（实测结论）：
    Hindsight 的 `recall_async(self, bank_id: str, ...)` 是**单 bank** 的，
    无跨 bank 联合检索。tag_groups 只在**当前 bank 内**生效。

后果：
    若「项目一」的知识在 team-projects、
       而它集成的「产品一/二/三」知识在 team-products，
    则项目成员 recall(team-projects) 时，展开出的产品维度
    会被 `in_bank` 过滤掉 → **一个产品知识都拿不到**。

因此本方案的 bank 划分原则是：
    **bank 表示「受众边界」（谁可能看到），不表示「知识类型」。**
    受众重叠的维度 → 同一个 bank。
    受众永不重叠 → 才用不同 bank（但此时项目展开不能跨过去）。

推荐划分（见《知识维度命名规范》）：
    u-<用户名>          个人区
    team-knowledge      全部共享业务知识（产品/项目/平台/技术域）
    team-restricted     受限知识（需额外授权，受众与上者不重叠）

本文件在检测到「项目展开跨 bank」时会记 WARNING，便于发现配置错误。

它不做什么：
   · 不写数据（只读授权表）
   · 不缓存"是否允许"的最终结论（只缓存授权规则本身，TTL 30s）

Hindsight 侧的调用点（实测）：
   validate_recall  → memory_engine.py:6082
   validate_retain  → memory_engine.py:4843 / 17960
   filter_bank_list → memory_engine.py:12035
"""

from __future__ import annotations

import logging
import os
from typing import Any

from hindsight_api.extensions import (
    BankListContext,
    BankListResult,
    OperationValidatorExtension,
    RecallContext,
    ReflectContext,
    RetainContext,
    ValidationResult,
)
# ⚠️⚠️ 必须用 pydantic 对象，不能用 dict！
#   实测（e468）：SQL 构造器 build_tag_groups_where_clause 只认 pydantic 对象。
#   传 dict 时它**静默生成空子句 "AND "**（既无 clause 也无 params），
#   最终报 PostgresSyntaxError: syntax error at or near "ORDER"。
#
#   对比（同一入参，只改类型）：
#     pydantic → "AND ((tags IS NOT NULL AND tags != '{}' AND tags && $5))"  ✅
#     dict     → "AND "                                                      ❌
#
#   而 Hindsight 的 `_validate_operation` **不会**对 validator 返回的
#   tag_groups 做 pydantic 校验（源码 memory_engine.py:6088 直接赋值），
#   所以类型正确性必须由 validator 自己保证。
from hindsight_api.engine.search.tags import (
    TagGroupAnd,
    TagGroupLeaf,
    TagGroupNot,
    TagGroupOr,
)

from .identity import Identity, mask_secret, resolve_identity
from .store import (
    PERM_NONE,
    PERM_READ,
    PERM_WRITE,
    DimAccess,
    DimAuthStore,
    database_url_from_env,
    get_shared_store,
)

logger = logging.getLogger(__name__)

# ⚠️ 分隔符用连字符 `-`，不用冒号。
#    最初怀疑是 bank 名含冒号导致 SQL 错误（e441），但 e468 查明真因是
#    tag_groups 传了 dict 而非 pydantic 对象。
#    不过连字符命名仍**建议保留**：与 K8s 资源名、Hindsight bank 名惯例一致，
#    且避免未来在 URL path / 标识符场景踩坑。
_PERSONAL_PREFIX = "u-"
_SHARED_PREFIX = "team-"
# 维度 tag 前缀（同样用连字符）
_DIM_PREFIXES = ("product-", "project-", "platform-", "tech-")


class DimAuthValidator(OperationValidatorExtension):
    """
    按维度授权的 validator。

    配置（环境变量，由 loader 自动收集为 config dict）：
        HINDSIGHT_API_OPERATION_VALIDATOR_EXTENSION=wiki_auth.validator:DimAuthValidator
        HINDSIGHT_API_OPERATION_VALIDATOR_DATABASE_URL=postgresql://...   （可选，默认复用主库）
        HINDSIGHT_API_OPERATION_VALIDATOR_SCHEMA=wiki_auth                 （可选）
        HINDSIGHT_API_OPERATION_VALIDATOR_CACHE_TTL=30                    （可选，秒）
        HINDSIGHT_API_OPERATION_VALIDATOR_ENFORCE=1                       （可选，0=仅观察不拦截）

    ⚠️ ENFORCE=0 仅用于灰度观察（记录"本应拒绝"但不真拒绝）。
       生产必须为 1。
    """

    def __init__(self, config: dict[str, str]):
        super().__init__(config)
        self._schema = config.get("schema", "wiki_auth")
        self._cache_ttl = float(config.get("cache_ttl", "30"))
        self._enforce = config.get("enforce", "1").lower() not in ("0", "false", "no")

        url = config.get("database_url") or database_url_from_env()
        # ⚠️ 必须用共享单例（见 store.py 的说明）：
        #    否则管理 API 的 invalidate() 清不到本实例的缓存，
        #    撤销授权最长 30 秒才生效（e491 实测的安全缺陷）。
        self._store = get_shared_store(
            url, schema=self._schema, cache_ttl_seconds=self._cache_ttl
        )

        logger.info(
            "[wiki-auth] validator 初始化：schema=%s cache_ttl=%ss enforce=%s",
            self._schema, self._cache_ttl, self._enforce,
        )

    # ── 生命周期 ──────────────────────────────────────────────────────────────
    async def on_startup(self) -> None:
        await self._store.connect()
        logger.info("[wiki-auth] validator 启动完成")

    async def on_shutdown(self) -> None:
        await self._store.close()

    # ── 内部工具 ──────────────────────────────────────────────────────────────
    async def _identify(self, request_context) -> Identity | None:
        """
        解析身份（认不出返回 None，调用方必须拒绝）。

        ⚠️⚠️ 特例：worker 的任务重放（e472 实测）
        ─────────────────────────────────────────────────────────────
        Hindsight 的 retain 是**异步**的：HTTP 层先校验一次并返回 202，
        真正的抽取由 worker 在后台执行，此时它**重新调用 validate_retain**，
        但构造的 RequestContext 是：

            RequestContext(internal=True, user_initiated=True,
                           tenant_id=..., api_key_id=..., retry_count=...)

        即：**没有 api_key、没有 extra_headers**（worker 手里没有凭据）。

        如果我们在这里 fail-closed 拒绝，后果是：
            · 写入请求返回 202（用户以为成功）
            · 后台任务全部失败并无限重试
            · **记忆永远不落库** —— 表现为"召回结果为空"
        这是实测踩到的坑（e471）：日志里刷满
            Task execution failed: batch_retain, error:
            OperationValidationError: 无法识别调用方身份

        为什么放行是**安全**的：
            · `internal=True` 表示这是服务内部任务，**不是外部请求**
            · `user_initiated=True` 表示它源自一次**已经通过校验**的用户请求
              （HTTP 层在入队前已调用过 validate_retain 并放行）
            · 身份已由 HTTP 层固化进任务负载，worker 只是重放

        因此：`internal=True` 的重放**视为已授权**，直接放行。
        ⚠️ 但**只对 internal 任务**放行；外部请求（internal=False）仍严格校验。
        """
        if request_context is None:
            return None

        # worker 重放：已由 HTTP 层授权过，跳过重复校验
        if getattr(request_context, "internal", False):
            return Identity(
                consumer_id=f"internal:{getattr(request_context, 'tenant_id', None) or 'worker'}",
                username=None,
                source="internal",
            )

        return await resolve_identity(request_context, self._lookup_credential)

    async def _lookup_credential(self, api_key: str):
        """apikey → (consumer_id, username, developer_id)。"""
        return await self._store.lookup_credential(api_key)

    def _is_internal_replay(self, request_context) -> bool:
        """
        是否 worker 的任务重放（已由 HTTP 层授权过，无需重复校验）。

        见 `_identify` 的详细说明：retain 是异步的，worker 重放时没有凭据。
        """
        return bool(request_context is not None and getattr(request_context, "internal", False))

    def _deny(self, reason: str, *, status_code: int = 403) -> ValidationResult:
        """统一拒绝入口（带日志）。"""
        logger.warning("[wiki-auth] 拒绝：%s", reason)
        if not self._enforce:
            # 灰度模式：只记日志，放行（⚠️ 生产禁用）
            logger.error("[wiki-auth] ⚠️ ENFORCE=0，本应拒绝但已放行：%s", reason)
            return ValidationResult.accept()
        return ValidationResult.reject(reason, status_code=status_code)

    def _build_tag_groups(self, access: list[DimAccess]) -> list[Any]:
        """
        构造维度过滤（并集 + 强制 _strict）。

        ⚠️⚠️ 必须返回 **pydantic 对象**（TagGroupLeaf / TagGroupOr），
           不能返回 dict。实测（e468）：传 dict 时 SQL 构造器静默产出空子句
           "AND "，导致 PostgresSyntaxError（syntax error at or near "ORDER"）。

        ⚠️ 顶层是 OR（用 TagGroupOr 显式表达）。
           踩过的坑：tag_groups 的**顶层默认是 AND**
           （源码 build_tag_groups_where_clause: `" AND ".join(...)`），
           直接传 [{p1},{p2},{p3}] 会变成"同时属于三个产品" → 永远空结果。
        """
        leaves = [
            TagGroupLeaf(tags=[a.tag_prefix], match="any_strict")   # ⭐ 铁律 2
            for a in access
            if a.permission in (PERM_READ, PERM_WRITE) and a.tag_prefix
        ]
        if not leaves:
            return []
        if len(leaves) == 1:
            return [leaves[0]]
        return [TagGroupOr(filters=leaves)]

    def _warn_cross_bank_expansion(
        self, ident: Identity, in_bank: list[DimAccess], all_access: list[DimAccess]
    ) -> None:
        """
        检测「项目展开出的产品维度落在别的 bank」——这是配置错误。

        原因见模块头：recall 是单 bank 的，跨 bank 的展开结果拿不到。
        这里只告警不拦截（拦截会让用户完全无法检索，比拿不到产品知识更糟）。
        """
        expanded = [a for a in all_access if a.via.startswith("project-")]
        if not expanded:
            return
        current_banks = {a.bank_id for a in in_bank}
        outside = [a for a in expanded if a.bank_id not in current_banks]
        if outside:
            logger.warning(
                "[wiki-auth] ⚠️ 项目展开跨 bank（配置问题，这些维度将查不到）："
                "identity=%s 当前bank=%s 跨出的维度=%s。"
                "建议把项目与其集成的产品放在同一个 bank。",
                ident,
                sorted(current_banks),
                [(a.dim_id, a.bank_id) for a in outside][:5],
            )

    # ── 核心校验 ──────────────────────────────────────────────────────────────
    async def validate_recall(self, ctx: RecallContext) -> ValidationResult:
        """召回前校验 + 注入维度过滤。"""
        try:
            if self._is_internal_replay(ctx.request_context):
                logger.debug("[wiki-auth] recall 内部重放放行：bank=%s", ctx.bank_id)
                return ValidationResult.accept()

            ident = await self._identify(ctx.request_context)
            if ident is None:
                return self._deny("无法识别调用方身份（缺少或非法的凭据）")

            bank_id = ctx.bank_id or ""
            if not bank_id:
                return self._deny("缺少 bank_id")

            # 铁律 3：个人区只有本人
            if bank_id.startswith(_PERSONAL_PREFIX):
                owner = bank_id[len(_PERSONAL_PREFIX):]
                if owner != ident.consumer_id and owner != (ident.username or ""):
                    return self._deny(
                        f"个人区 {bank_id} 仅限本人访问（当前身份 {ident.consumer_id}）"
                    )
                logger.debug("[wiki-auth] recall 个人区放行：%s → %s", ident, bank_id)
                return ValidationResult.accept()

            # 共享区：查授权
            access = await self._store.load_access(ident.consumer_id)
            if not access:
                return self._deny(f"身份 {ident} 无任何维度授权")

            in_bank = [a for a in access if a.bank_id == bank_id]
            if not in_bank:
                return self._deny(
                    f"身份 {ident} 无权访问隔离区 {bank_id}"
                    f"（已授权隔离区：{sorted({a.bank_id for a in access})}）"
                )

            # ⚠️ 检测「项目展开跨 bank」——这是配置错误，会导致产品知识查不到
            self._warn_cross_bank_expansion(ident, in_bank, access)

            tag_groups = self._build_tag_groups(in_bank)
            if not tag_groups:
                return self._deny(f"身份 {ident} 在 {bank_id} 内无可读维度")

            logger.info(
                "[wiki-auth] recall 放行：%s bank=%s 维度=%s",
                ident, bank_id, [a.dim_id for a in in_bank],
            )
            return ValidationResult.accept_with(tag_groups=tag_groups)

        except Exception as e:
            # ⭐ 铁律 1：异常 = 拒绝（绝不因内部错误而放行）
            logger.exception("[wiki-auth] validate_recall 异常，按 fail-closed 拒绝")
            return self._deny(f"授权校验异常（fail-closed）：{type(e).__name__}")

    async def validate_retain(self, ctx: RetainContext) -> ValidationResult:
        """
        写入前校验：必须有 write 权限 + 记忆必须带维度标签。

        ⚠️ worker 重放（internal=True）直接放行 —— 见 `_identify` 的说明。
           不放行会导致"HTTP 返回 202 但记忆永不落库"（实测踩坑 e471）。
        """
        try:
            if self._is_internal_replay(ctx.request_context):
                logger.debug("[wiki-auth] retain 内部重放放行：bank=%s", ctx.bank_id)
                return ValidationResult.accept()

            ident = await self._identify(ctx.request_context)
            if ident is None:
                return self._deny("无法识别调用方身份（缺少或非法的凭据）")

            bank_id = ctx.bank_id or ""
            if not bank_id:
                return self._deny("缺少 bank_id")

            # 个人区：本人可写，且不要求 tag
            if bank_id.startswith(_PERSONAL_PREFIX):
                owner = bank_id[len(_PERSONAL_PREFIX):]
                if owner != ident.consumer_id and owner != (ident.username or ""):
                    return self._deny(f"个人区 {bank_id} 仅限本人写入")
                return ValidationResult.accept()

            access = await self._store.load_access(ident.consumer_id)
            in_bank = [a for a in access if a.bank_id == bank_id]
            if not in_bank:
                return self._deny(f"身份 {ident} 无权写入隔离区 {bank_id}")

            writable = [a for a in in_bank if a.permission == PERM_WRITE]
            if not writable:
                perms = sorted({a.permission for a in in_bank})
                return self._deny(
                    f"身份 {ident} 在 {bank_id} 只有 {perms} 权限，不能写入（需 write）"
                )

            # ⭐ 共享区必须带维度 tag —— 否则该记忆无人可见（_strict 模式）
            missing = self._contents_missing_tags(ctx.contents)
            if missing:
                return self._deny(
                    f"共享区写入必须带至少一个维度 tag（否则无人可见）。"
                    f"缺失的内容索引：{missing[:3]}"
                )

            logger.info("[wiki-auth] retain 放行：%s bank=%s", ident, bank_id)
            return ValidationResult.accept()

        except Exception as e:
            logger.exception("[wiki-auth] validate_retain 异常，按 fail-closed 拒绝")
            return self._deny(f"授权校验异常（fail-closed）：{type(e).__name__}")

    async def validate_reflect(self, ctx: ReflectContext) -> ValidationResult:
        """反思/综合前校验（与 recall 同规则）。"""
        try:
            if self._is_internal_replay(ctx.request_context):
                return ValidationResult.accept()

            ident = await self._identify(ctx.request_context)
            if ident is None:
                return self._deny("无法识别调用方身份（缺少或非法的凭据）")

            bank_id = ctx.bank_id or ""
            if bank_id.startswith(_PERSONAL_PREFIX):
                owner = bank_id[len(_PERSONAL_PREFIX):]
                if owner != ident.consumer_id and owner != (ident.username or ""):
                    return self._deny(f"个人区 {bank_id} 仅限本人访问")
                return ValidationResult.accept()

            access = await self._store.load_access(ident.consumer_id)
            in_bank = [a for a in access if a.bank_id == bank_id]
            if not in_bank:
                return self._deny(f"身份 {ident} 无权访问隔离区 {bank_id}")

            tag_groups = self._build_tag_groups(in_bank)
            if not tag_groups:
                return self._deny(f"身份 {ident} 在 {bank_id} 内无可读维度")

            return ValidationResult.accept_with(tag_groups=tag_groups)

        except Exception as e:
            logger.exception("[wiki-auth] validate_reflect 异常，按 fail-closed 拒绝")
            return self._deny(f"授权校验异常（fail-closed）：{type(e).__name__}")

    # ── 辅助钩子 ──────────────────────────────────────────────────────────────
    async def filter_bank_list(self, ctx: BankListContext) -> BankListResult:
        """只返回该用户有权访问的隔离区（+ 自己的个人区）。"""
        try:
            ident = await self._identify(ctx.request_context)
            if ident is None:
                return BankListResult(banks=[])

            access = await self._store.load_access(ident.consumer_id)
            allowed = {a.bank_id for a in access}
            allowed.add(f"{_PERSONAL_PREFIX}{ident.consumer_id}")

            kept = [b for b in ctx.banks if (b.get("bank_id") or "") in allowed]
            logger.debug(
                "[wiki-auth] filter_bank_list：%s 可见 %d/%d 个隔离区",
                ident, len(kept), len(ctx.banks),
            )
            return BankListResult(banks=kept)
        except Exception:
            # ⚠️ 这个钩子是"列表可见性"，异常时返回空（保守），不是放行
            logger.exception("[wiki-auth] filter_bank_list 异常，返回空列表")
            return BankListResult(banks=[])

    async def filter_mcp_tools(
        self, bank_id: str, request_context, tools: frozenset[str]
    ) -> frozenset[str]:
        """
        按权限裁剪工具。

        ⚠️ 注意：Hindsight 在**本方法抛异常时会 fail-OPEN**（返回未过滤工具）。
           所以这里的数据安全**不依赖**本方法 —— 真正的拦截在 validate_*。
           本方法只做体验优化（只读用户看不到 retain）。
        """
        try:
            ident = await self._identify(request_context)
            if ident is None:
                return frozenset()
            perm = await self._store.max_permission(ident.consumer_id)
            if perm == PERM_WRITE:
                return tools
            # 只读：移除写入类工具
            write_tools = {"retain", "store", "store_batch", "update", "forget",
                           "delete_knowledge_node", "put_page", "remember", "capture"}
            return frozenset(t for t in tools if t not in write_tools)
        except Exception:
            logger.exception("[wiki-auth] filter_mcp_tools 异常（注意：Hindsight 会 fail-OPEN）")
            return tools

    # ── 内部：内容标签校验 ────────────────────────────────────────────────────
    @staticmethod
    def _contents_missing_tags(contents: list[dict] | None) -> list[int]:
        """返回缺 tag 的内容索引（空列表 = 全部合规）。"""
        if not contents:
            return [0] if contents is not None else []
        missing: list[int] = []
        for i, c in enumerate(contents):
            if not isinstance(c, dict):
                missing.append(i)
                continue
            tags = c.get("tags") or []
            if not isinstance(tags, list) or not [t for t in tags if t]:
                missing.append(i)
        return missing

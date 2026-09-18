"""
测试用极简 stub —— 只提供 wiki_auth 需要的 hindsight_api 类型符号。

⚠️ 仅用于本地跑 wiki_auth 的单元测试（FakeStore，不碰真实 DB）。
   生产环境用真实的 hindsight-api-slim 包，本 stub 不参与部署。
   不要 import 进 wiki_auth 源码包。

提供：
    hindsight_api.extensions  →  HttpExtension, AuthenticationError, RequestContext,
                                  Tenant, TenantContext, TenantExtension,
                                  BankListContext, BankListResult, RecallContext,
                                  ReflectContext, RetainContext, ValidationResult,
                                  OperationValidatorExtension
    hindsight_api.engine.search.tags → TagGroupLeaf, TagGroupOr, TagGroupAnd, TagGroupNot
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ── engine.search.tags ────────────────────────────────────────────────────────
class TagGroupLeaf(BaseModel):
    tags: list[str] = Field(default_factory=list)
    match: str = "any"


class TagGroupOr(BaseModel):
    filters: list[Any] = Field(default_factory=list)


class TagGroupAnd(BaseModel):
    filters: list[Any] = Field(default_factory=list)


class TagGroupNot(BaseModel):
    filter: Any = None


# ── extensions 基类 ───────────────────────────────────────────────────────────
class RequestContext:
    api_key: str | None = None
    extra_headers: dict[str, str] | None = None
    internal: bool = False
    user_initiated: bool = False
    tenant_id: str | None = None
    retry_count: int = 0

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class AuthenticationError(Exception):
    def __init__(self, message: str = "", headers: dict | None = None):
        super().__init__(message)
        self.headers = headers or {}


class Tenant:
    def __init__(self, schema: str):
        self.schema = schema


class TenantContext:
    def __init__(self, schema_name: str | None = None):
        self.schema_name = schema_name


class Extension:
    def __init__(self, config: dict[str, str] | None = None):
        self.config = config or {}


class TenantExtension(Extension):
    pass


class HttpExtension(Extension):
    pass


# ── OperationValidator 类型 ───────────────────────────────────────────────────
class ValidationResult:
    def __init__(self, allowed: bool = True, status_code: int = 200,
                 tag_groups: list | None = None, reason: str | None = None):
        self.allowed = allowed
        self.status_code = status_code
        self.tag_groups = tag_groups
        self.reason = reason

    @classmethod
    def accept(cls):
        return cls(allowed=True)

    @classmethod
    def accept_with(cls, tag_groups=None):
        return cls(allowed=True, tag_groups=tag_groups)

    @classmethod
    def reject(cls, reason: str = "", status_code: int = 403):
        return cls(allowed=False, status_code=status_code, reason=reason)


class RecallContext:
    def __init__(self, bank_id: str = "", request_context=None, **kwargs):
        self.bank_id = bank_id
        self.request_context = request_context


class ReflectContext:
    def __init__(self, bank_id: str = "", request_context=None, **kwargs):
        self.bank_id = bank_id
        self.request_context = request_context


class RetainContext:
    def __init__(self, bank_id: str = "", request_context=None, contents=None, **kwargs):
        self.bank_id = bank_id
        self.request_context = request_context
        self.contents = contents


class BankListContext:
    def __init__(self, banks: list | None = None, request_context=None, **kwargs):
        self.banks = banks or []
        self.request_context = request_context


class BankListResult:
    def __init__(self, banks: list | None = None):
        self.banks = banks or []


class OperationValidatorExtension(Extension):
    pass


# 兼容 from hindsight_api.extensions import X 的符号集合
__all__ = [
    "HttpExtension",
    "AuthenticationError",
    "RequestContext",
    "Tenant",
    "TenantContext",
    "TenantExtension",
    "Extension",
    "BankListContext",
    "BankListResult",
    "RecallContext",
    "ReflectContext",
    "RetainContext",
    "ValidationResult",
    "OperationValidatorExtension",
]

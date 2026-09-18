"""stub：engine.search.tags 类型（pydantic，validator 依赖 match 字段）。"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TagGroupLeaf(BaseModel):
    tags: list[str] = Field(default_factory=list)
    match: str = "any"


class TagGroupOr(BaseModel):
    filters: list[Any] = Field(default_factory=list)


class TagGroupAnd(BaseModel):
    filters: list[Any] = Field(default_factory=list)


class TagGroupNot(BaseModel):
    filter: Any = None


__all__ = ["TagGroupLeaf", "TagGroupOr", "TagGroupAnd", "TagGroupNot"]

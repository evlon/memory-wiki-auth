"""
wiki_auth —— 多维度知识共享的授权层

对外导出：
    DimAuthValidator     Hindsight 的 OperationValidatorExtension 实现（核心）
    DimAuthStore         授权规则读写
    DimAccess            单条有效授权
    Identity             已识别的调用方身份

Hindsight 启用方式（环境变量）：
    HINDSIGHT_API_OPERATION_VALIDATOR_EXTENSION=wiki_auth.validator:DimAuthValidator
"""

from .identity import Identity, extract_api_key, mask_secret, resolve_identity
from .store import (
    PERM_NONE,
    PERM_READ,
    PERM_WRITE,
    DimAccess,
    DimAuthStore,
    database_url_from_env,
    get_shared_store,
)
from .admin_api import build_admin_router
from .admin_auth import AdminAuth
from .admin_ext import DimAuthAdminExtension
from .oidc import SESSION_COOKIE, OidcClient, OidcUser
from .tenant import DimAuthTenantExtension
from .validator import DimAuthValidator

__all__ = [
    "DimAuthValidator",
    "DimAuthTenantExtension",
    "DimAuthAdminExtension",
    "build_admin_router",
    "AdminAuth",
    "OidcClient",
    "OidcUser",
    "SESSION_COOKIE",
    "DimAuthStore",
    "DimAccess",
    "Identity",
    "resolve_identity",
    "extract_api_key",
    "mask_secret",
    "database_url_from_env",
    "get_shared_store",
    "PERM_NONE",
    "PERM_READ",
    "PERM_WRITE",
]

__version__ = "1.2.0"

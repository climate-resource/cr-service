"""WorkOS authentication, logging and observability for Climate Resource FastAPI services."""

import importlib.metadata

from cr_service.auth.dependencies import AuthConfig
from cr_service.context import bind, get_context, log_scope, unbind
from cr_service.info import ServiceInfo
from cr_service.logging_config import configure_logging
from cr_service.service import setup
from cr_service.settings import Environment, ServiceSettings

__version__ = importlib.metadata.version("cr-service")

__all__ = [
    "AuthConfig",
    "Environment",
    "ServiceInfo",
    "ServiceSettings",
    "__version__",
    "bind",
    "configure_logging",
    "get_context",
    "log_scope",
    "setup",
    "unbind",
]

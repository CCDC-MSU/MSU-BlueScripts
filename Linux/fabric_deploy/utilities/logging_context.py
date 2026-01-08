"""
Logging context helpers for tagging log records with host/module metadata.
"""

from __future__ import annotations

import contextvars
import logging
from contextlib import contextmanager

DEFAULT_LOG_FORMAT = (
    "[%(asctime)s] [%(ccdc_host)s] [%(ccdc_module)s] %(levelname)-5s %(message)s"
)
DEFAULT_LOG_DATEFMT = "%H:%M:%S"

_HOST_CTX = contextvars.ContextVar("ccdc_host", default="-")
_MODULE_CTX = contextvars.ContextVar("ccdc_module", default=None)


@contextmanager
def log_context(host: str | None = None, module: str | None = None):
    """Temporarily set log context for host/module."""
    tokens = []
    if host is not None:
        tokens.append((_HOST_CTX, _HOST_CTX.set(host)))
    if module is not None:
        tokens.append((_MODULE_CTX, _MODULE_CTX.set(module)))
    try:
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


class LogContextFilter(logging.Filter):
    """Inject host/module context into log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        host = _HOST_CTX.get()
        if not hasattr(record, "ccdc_host"):
            record.ccdc_host = host if host else "-"
        module_ctx = _MODULE_CTX.get()
        if not hasattr(record, "ccdc_module"):
            if module_ctx:
                record.ccdc_module = module_ctx
            else:
                record.ccdc_module = record.name.split(".")[-1]
        return True


def ensure_log_context_filter(handler: logging.Handler) -> None:
    """Attach the log context filter once to a handler."""
    for existing in handler.filters:
        if isinstance(existing, LogContextFilter):
            return
    handler.addFilter(LogContextFilter())


class LogCaptureStream:
    """File-like stream that forwards lines into a logger with context."""

    def __init__(
        self,
        logger: logging.Logger,
        default_level: int = logging.INFO,
        mirror_logger: logging.Logger | None = None,
        host: str | None = None,
        module: str | None = None,
    ):
        self._logger = logger
        self._default_level = default_level
        self._mirror_logger = mirror_logger
        self._host = host if host is not None else _HOST_CTX.get()
        self._module = module if module is not None else _MODULE_CTX.get()
        self._buffer = ""

    def write(self, data):
        if not data:
            return
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self._log_line(line)

    def flush(self):
        if self._buffer:
            self._log_line(self._buffer)
            self._buffer = ""

    def _log_line(self, line: str) -> None:
        message = line.rstrip()
        if not message:
            return
        level, cleaned = _parse_level_prefix(message, self._default_level)
        extra = {}
        if self._host:
            extra["ccdc_host"] = self._host
        if self._module:
            extra["ccdc_module"] = self._module
        self._logger.log(level, cleaned, extra=extra if extra else None)
        if self._mirror_logger and level < logging.ERROR:
            self._mirror_logger.log(level, cleaned, extra=extra if extra else None)


def _parse_level_prefix(line: str, default_level: int):
    stripped = line.lstrip()
    prefixes = {
        "[DEBUG]": logging.DEBUG,
        "[INFO]": logging.INFO,
        "[WARN]": logging.WARNING,
        "[WARNING]": logging.WARNING,
        "[ERROR]": logging.ERROR,
    }
    for prefix, level in prefixes.items():
        if stripped.startswith(prefix):
            cleaned = stripped[len(prefix) :].lstrip(" :")
            return level, cleaned or stripped

    word_prefixes = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    for word, level in word_prefixes.items():
        if stripped.startswith(f"{word}:") or stripped.startswith(f"{word} -"):
            cleaned = stripped[len(word) :].lstrip(" :-")
            return level, cleaned or stripped

    return default_level, stripped

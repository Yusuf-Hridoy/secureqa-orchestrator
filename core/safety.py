"""Safety guard for validating scan targets against allowlists and production heuristics."""

import json
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import unquote, urlparse

from config.settings import settings
from core.logging_config import get_logger
from core.models import AuditLogEntry, SafetyResult
from core.storage import log_audit


class ProductionBlockError(Exception):
    """Raised when a scan is attempted on a production target while blocking is enabled."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Production target blocked: {target} ({reason})")


class SafetyGuard:
    """Validates URLs against allowlists, blocklists, and production heuristics."""

    def __init__(self, allowlist_path: str | None = None) -> None:
        self._path = (
            Path(allowlist_path)
            if allowlist_path
            else Path(settings.allowlist_path)
        )
        self._data = self._load_allowlist()
        self._allowed_patterns = self._data.get("allowed_patterns", [])
        self._blocked_patterns = self._data.get("blocked_patterns", [])
        self._logger = get_logger(__name__)

    def _load_allowlist(self) -> dict:
        if not self._path.exists():
            return {"allowed_patterns": [], "blocked_patterns": []}
        with self._path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _normalize_url(self, url: str) -> str:
        """Decode URL-encoded characters to prevent bypass attempts."""
        return unquote(url)

    def _extract_host(self, url: str) -> str:
        """Extract ``hostname:port`` (or just ``hostname``) from a URL."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
        if port is not None:
            return f"{host}:{port}"
        return host

    def _hosts_to_check(self, host: str) -> list[str]:
        """Return host variants to check (handles IP/localhost aliases)."""
        hosts = [host]
        if host == "localhost":
            hosts.append("127.0.0.1")
        elif host == "127.0.0.1":
            hosts.append("localhost")
        elif host == "::1":
            hosts.extend(["localhost", "127.0.0.1"])
        return hosts

    def _match_patterns(self, url: str, patterns: list[str]) -> bool:
        """Check whether *url* matches any glob *pattern*."""
        normalized = self._normalize_url(url)
        host = self._extract_host(normalized)

        for pattern in patterns:
            for h in self._hosts_to_check(host):
                if fnmatch(h, pattern):
                    return True
            if fnmatch(normalized, pattern):
                return True
        return False

    def is_allowed(self, url: str) -> bool:
        """Return ``True`` if *url* matches an allowed pattern."""
        return self._match_patterns(url, self._allowed_patterns)

    def is_blocked(self, url: str) -> bool:
        """Return ``True`` if *url* matches a blocked pattern."""
        return self._match_patterns(url, self._blocked_patterns)

    def is_production(self, url: str) -> bool:
        """Heuristic check for production URLs."""
        normalized = self._normalize_url(url).lower()
        host = self._extract_host(normalized).lower()

        # Explicit production indicators in the full URL
        if any(indicator in normalized for indicator in ("prod", "production", "live")):
            return True

        # Consumer-facing www hostnames
        if host.startswith("www."):
            return True

        # Generic heuristic: no dev/staging indicators + blocking enabled
        if settings.block_production:
            dev_indicators = ("staging", "dev", "test", "localhost", "127.0.0.1", "::1")
            if not any(indicator in host for indicator in dev_indicators):
                return True

        return False

    def validate_target(self, url: str) -> SafetyResult:
        """Run all safety checks and return a ``SafetyResult``.

        Logs an audit entry for every outcome. Raises
        :class:`ProductionBlockError` when a production target is
        encountered while ``settings.block_production`` is enabled.
        """
        normalized = self._normalize_url(url)
        host = self._extract_host(normalized)
        is_prod = self.is_production(normalized)

        # Deny-first: blocked patterns take precedence
        if self.is_blocked(normalized):
            reason = "Target matches blocked pattern"
            log_audit(
                AuditLogEntry(
                    event="target_blocked",
                    target=host,
                    details={"url": url, "reason": reason},
                )
            )
            return SafetyResult(
                allowed=False,
                reason=reason,
                is_production=is_prod,
                target=host,
            )

        if not self.is_allowed(normalized):
            reason = "Target not in allowlist"
            log_audit(
                AuditLogEntry(
                    event="target_blocked",
                    target=host,
                    details={"url": url, "reason": reason},
                )
            )
            return SafetyResult(
                allowed=False,
                reason=reason,
                is_production=is_prod,
                target=host,
            )

        if is_prod and settings.block_production:
            reason = "Production target blocked by policy"
            log_audit(
                AuditLogEntry(
                    event="prod_blocked",
                    target=host,
                    details={"url": url, "reason": reason},
                )
            )
            raise ProductionBlockError(target=host, reason=reason)

        log_audit(
            AuditLogEntry(
                event="target_validated",
                target=host,
                details={"url": url},
            )
        )
        return SafetyResult(
            allowed=True,
            reason="Target passed safety checks",
            is_production=is_prod,
            target=host,
        )

"""
Scope Manager — strict boundary control for bug bounty compliance.
Validates targets against include/exclude rules supporting:
  - Exact domains
  - Wildcard patterns (*.example.com)
  - CIDR notation (192.168.1.0/24)
  - Regex patterns
"""
import ipaddress
import logging
import re
import fnmatch
from typing import Optional

from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import ScopeRule

logger = logging.getLogger(__name__)


class ScopeManager:
    """Validates hosts/IPs against the configured scope rules."""

    def __init__(self):
        self._include_rules: list = []
        self._exclude_rules: list = []

    async def load_rules(self):
        """Load active rules from the database."""
        self._include_rules.clear()
        self._exclude_rules.clear()
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScopeRule).where(ScopeRule.active == True)
            )
            for rule in result.scalars().all():
                entry = {
                    "pattern_type": rule.pattern_type,
                    "pattern": rule.pattern,
                }
                if rule.rule_type == "include":
                    self._include_rules.append(entry)
                else:
                    self._exclude_rules.append(entry)
        logger.info(
            "Scope loaded: %d include, %d exclude rules",
            len(self._include_rules), len(self._exclude_rules),
        )

    def is_in_scope(self, host: str) -> bool:
        """
        Check if a host/IP is within scope.
        Logic:
          1. If exclude rules exist and host matches any → OUT OF SCOPE
          2. If include rules exist, host must match at least one → else OUT OF SCOPE
          3. If no rules at all → IN SCOPE (permissive default)
        """
        host = host.strip().lower()

        # Check exclusions first
        for rule in self._exclude_rules:
            if self._matches(host, rule):
                logger.debug("Host %s EXCLUDED by rule %s", host, rule["pattern"])
                return False

        # If include rules exist, host must match at least one
        if self._include_rules:
            for rule in self._include_rules:
                if self._matches(host, rule):
                    return True
            logger.debug("Host %s not matched by any include rule", host)
            return False

        # No rules → permissive
        return True

    def _matches(self, host: str, rule: dict) -> bool:
        """Test if a host matches a single rule."""
        pattern = rule["pattern"]
        ptype = rule["pattern_type"]

        if ptype == "domain":
            return host == pattern.lower()

        elif ptype == "wildcard":
            return fnmatch.fnmatch(host, pattern.lower())

        elif ptype == "cidr":
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                addr = ipaddress.ip_address(host)
                return addr in network
            except ValueError:
                return False

        elif ptype == "regex":
            try:
                return bool(re.match(pattern, host, re.IGNORECASE))
            except re.error:
                logger.error("Invalid regex scope pattern: %s", pattern)
                return False

        return False

    async def validate_and_filter(self, hosts: list[str]) -> tuple[list[str], list[str]]:
        """
        Filter a list of hosts. Returns (in_scope, out_of_scope).
        Reloads rules from DB before validation.
        """
        await self.load_rules()
        in_scope = []
        out_of_scope = []
        for h in hosts:
            if self.is_in_scope(h):
                in_scope.append(h)
            else:
                out_of_scope.append(h)
                logger.warning("SCOPE VIOLATION — dropping host: %s", h)
        return in_scope, out_of_scope


# Global singleton
scope_manager = ScopeManager()

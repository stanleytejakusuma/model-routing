from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ClassificationResult:
    is_capital: bool
    reason: str
    repo_id: str | None = None


def _normalize_path(path: Path) -> str:
    return str(path.expanduser().resolve(strict=False))


class CapitalRegistry:
    """Human-owned registry consumer with unknown-defaults-to-capital behavior."""

    def __init__(self, payload: dict[str, Any]):
        self.payload = payload
        defaults = payload.get("defaults", {})
        self.unknown_is_capital = bool(defaults.get("unknown_is_capital", True))
        self.repos = payload.get("repos", [])
        self.services = payload.get("services", [])
        self.vault_bundles = payload.get("vault_bundles", [])
        self.vault_surfaces = payload.get("vault_surfaces", [])
        self.addresses = payload.get("addresses", [])
        self.capital_hosts = payload.get("capital_hosts", [])
        self.capital_network_targets = payload.get("capital_network_targets", [])
        self.pre_blessed_commands = payload.get("pre_blessed_commands", [])

    @classmethod
    def from_file(cls, path: Path) -> "CapitalRegistry":
        with path.open("r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    def classify_path(self, path: Path) -> ClassificationResult:
        candidate = _normalize_path(path)
        matches = []
        for repo in self.repos:
            for raw_path in repo.get("paths", []):
                registered = _normalize_path(Path(raw_path))
                if candidate == registered or candidate.startswith(f"{registered}/"):
                    matches.append((len(registered), repo))
        if matches:
            _, repo = max(matches, key=lambda item: item[0])
            is_capital = bool(repo.get("capital", True))
            reason = "registry-capital" if is_capital else "registry-non-capital"
            return ClassificationResult(is_capital, reason, repo.get("id"))
        if self.unknown_is_capital:
            return ClassificationResult(True, "unknown-default-capital", None)
        return ClassificationResult(False, "unknown-default-non-capital", None)

    def classify_remote(self, remote_url: str) -> ClassificationResult:
        for repo in self.repos:
            if remote_url in repo.get("remotes", []):
                is_capital = bool(repo.get("capital", True))
                reason = "registry-capital-remote" if is_capital else "registry-non-capital-remote"
                return ClassificationResult(is_capital, reason, repo.get("id"))
        if self.unknown_is_capital:
            return ClassificationResult(True, "unknown-default-capital", None)
        return ClassificationResult(False, "unknown-default-non-capital", None)

    def is_capital_service(self, service_name: str) -> bool:
        for service in self.services:
            if self.service_matches(service_name, service):
                return bool(service.get("capital", True))
        return self.unknown_is_capital

    def repo_for_service(self, service_name: str) -> Path | None:
        """Return the registered source repo for one exact capital service."""
        for service in self.services:
            if not self.service_matches(service_name, service) or not bool(service.get("capital", True)):
                continue
            repo_path = service.get("repo_path")
            if repo_path:
                return Path(_normalize_path(Path(str(repo_path))))
            return None
        return None

    def service_matches(self, service_name: str, service: dict[str, Any]) -> bool:
        if service.get("name") == service_name:
            return True
        pattern = str(service.get("pattern", ""))
        if not pattern:
            return False
        match_mode = service.get("match", "exact")
        if match_mode == "contains":
            return pattern in service_name
        if match_mode == "prefix":
            return service_name.startswith(pattern)
        if match_mode == "suffix":
            return service_name.endswith(pattern)
        return False

    def is_capital_vault_bundle(self, bundle_name: str) -> bool:
        for bundle in self.vault_bundles:
            if bundle.get("name") == bundle_name:
                return bool(bundle.get("capital", True))
        return self.unknown_is_capital

    def is_capital_vault_surface(self, surface: str) -> bool:
        entry = self.vault_surface_entry(surface)
        if entry is not None:
            return bool(entry.get("capital", True))
        return self.unknown_is_capital

    def vault_surface_entry(self, surface: str) -> dict[str, Any] | None:
        parts = _surface_parts(surface)
        for entry in self.vault_surfaces:
            raw_path = entry.get("path")
            if raw_path:
                registered = _normalize_path(Path(str(raw_path)))
                for part in parts:
                    candidate = _normalize_path(Path(part)) if Path(part).is_absolute() else part
                    if candidate == registered or candidate.startswith(f"{registered}/"):
                        return entry
            suffix = entry.get("suffix")
            if suffix and any(part.endswith(str(suffix)) for part in parts):
                return entry
            prefix = entry.get("prefix")
            if prefix and any(Path(part).name.startswith(str(prefix)) for part in parts):
                return entry
        return None

    def is_capital_address(self, address: str) -> bool:
        folded = address.lower()
        for entry in self.addresses:
            value = entry.get("value")
            env_name = entry.get("env")
            if env_name:
                value = os.environ.get(str(env_name))
            if value and str(value).lower() == folded:
                return bool(entry.get("capital", True))
        return self.unknown_is_capital

    def is_capital_address_env_name(self, env_name: str) -> bool:
        for entry in self.addresses:
            if entry.get("env") == env_name:
                return bool(entry.get("capital", True))
        return self.unknown_is_capital

    def is_capital_host(self, host: str) -> bool:
        normalized = _normalize_host(host)
        for entry in self.capital_hosts:
            if isinstance(entry, str):
                candidate = _normalize_host(entry)
                is_capital = True
            else:
                candidate = _normalize_host(str(entry.get("name", "")))
                is_capital = bool(entry.get("capital", True))
            if normalized == candidate:
                return is_capital
        return self.unknown_is_capital

    def has_host_entry(self, host: str) -> bool:
        normalized = _normalize_host(host)
        for entry in self.capital_hosts:
            candidate = _normalize_host(entry if isinstance(entry, str) else str(entry.get("name", "")))
            if normalized == candidate:
                return True
        return False

    def is_pre_blessed(self, exact_action: str) -> bool:
        """Owner-registered EXACT command strings that skip ONLY the Opus review in
        the approval flow. They REMAIN capital: still classified as triggers, still
        require a signed intent, still require the human confirm at sign time. Exact
        match only — no wildcards, no substrings, so there is nothing to smuggle."""
        command = str(exact_action).strip()
        return any(command == str(entry).strip() for entry in self.pre_blessed_commands)

    def is_capital_network_target(self, value: str) -> bool:
        text = str(value).strip().lower()
        for entry in self.capital_network_targets:
            if isinstance(entry, str):
                target = _normalize_host(entry)
                is_capital = True
            else:
                target = _normalize_host(str(entry.get("name") or entry.get("host") or ""))
                is_capital = bool(entry.get("capital", True))
            if target and _contains_host_token(text, target):
                return is_capital
        return False


def _normalize_host(host: str) -> str:
    normalized = str(host).strip().lower()
    if "@" in normalized:
        normalized = normalized.rsplit("@", maxsplit=1)[-1]
    if ":" in normalized:
        normalized = normalized.split(":", maxsplit=1)[0]
    return normalized


def _contains_host_token(text: str, host: str) -> bool:
    return bool(re.search(rf"(?<![a-z0-9.-]){re.escape(host)}(?![a-z0-9.-])", text))


def _surface_parts(surface: str) -> list[str]:
    return [part for part in str(surface).split() if part]

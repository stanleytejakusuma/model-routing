from __future__ import annotations

import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from model_routing.registry import CapitalRegistry, ClassificationResult


EVM_ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Reads never threaten capital (except secret/key/vault reads, handled below), so
# they classify read-only regardless of cwd. Dual-use tools (find/awk/xargs/sed/
# tee/less/more) are deliberately EXCLUDED — they can mutate.
READ_ONLY_COMMANDS = {
    "basename", "cat", "cksum", "column", "comm", "cmp", "cut", "dirname", "diff",
    "du", "df", "egrep", "fgrep", "file", "grep", "head", "jq", "ls", "md5sum",
    "nl", "od", "pwd", "readlink", "realpath", "rg", "sha1sum", "sha256sum",
    "sort", "stat", "tail", "tr", "tree", "uniq", "wc",
}
READ_ONLY_GIT_SUBCOMMANDS = {"branch", "diff", "log", "rev-parse", "show", "status"}
READ_ONLY_SYSTEMCTL_SUBCOMMANDS = {"is-active", "is-enabled", "show", "status", "list-units", "list-unit-files", "cat"}
READ_ONLY_MCP_PREFIXES = ("get", "list", "read", "search", "status")
SHELL_CONTROL_TOKENS = {";", "&&", "||", "|", ">", ">>", "<", "<<", "`"}
SINGLE_AMPERSAND_RE = re.compile(r"(?<!&)&(?!&)")
HEREDOC_AUTHORING_HEADER_RE = re.compile(
    r"^cat[ \t]+>>?[ \t]+(?P<sink>\S+)[ \t]+<<'(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)'\n"
)
HEREDOC_AUTHORING_RAW_GUARDS = (";", "&&", "||", "&", "|", "$(", "`", "<(", ">(")
HEREDOC_LITERAL_PATH_FORBIDDEN_RE = re.compile(r"[$`*?\[\]{}~;|&<>\\()]")
PSEUDO_FILESYSTEM_ROOTS = (Path("/dev"), Path("/proc"), Path("/sys"))

# --- capital TRIGGER detection (cwd-independent, full-string scan) ---
SERVICE_MANAGER_TOKENS = ("systemctl", "service", "docker", "docker-compose", "podman", "nerdctl", "systemd-run")
CAPITAL_SERVICE_VERBS = (
    "restart", "stop", "start", "reload", "kill", "enable", "disable",
    "daemon-reload", "up", "down", "rm", "recreate", "force-recreate", "scale",
)
CEX_MUTATING_RE = re.compile(
    r"(-X\s*(post|put|delete|patch))"
    r"|(--data\b)|(--data-raw\b)|(--data-binary\b)|(--data-urlencode\b)|(--json\b)"
    r"|((?:^|\s)-d\b)"
    r"|(/order\b)|(/batchorders\b)|(/fapi/v\d+/order)|(/api/v\d+/order)|(/sapi/)",
    re.IGNORECASE,
)
ADDRESS_MUTATING_RE = re.compile(
    r"\b(transfer|transferfrom|send|sendtransaction|withdraw|sign|approve|swap|deposit|redeem|mint|burn)\b",
    re.IGNORECASE,
)
# Concrete secret ARTIFACTS (not merely a source file named '...signer...').
SECRET_ARTIFACT_RE = re.compile(
    r"(\.age\b)|(\.pem\b)|(\.key\b)|(\.keystore\b)|(\.p12\b)"
    r"|(signer[-_]?key)|(private[-_]?key)|(secret[-_]?key)|(\bkeypair\b)"
    r"|(\bmnemonic\b)|(\bseed[-_]?phrase\b)",
    re.IGNORECASE,
)


# Published PUBLIC keys are not secrets — reading one is not exfiltration.
PUBLIC_KEY_RE = re.compile(
    r"(\.pub\b)|(public[-_.]?key)|([-_.]public\.(?:pem|key)\b)|(\bid_[a-z0-9]+\.pub\b)",
    re.IGNORECASE,
)
# Script / source / doc files are tooling, not vault bundles. Used ONLY to relax the
# name-shape (prefix/suffix) surface guesses, never explicit registered paths.
NON_SECRET_EXT_RE = re.compile(r"\.(sh|bash|zsh|py|md|txt|log|rst)\b", re.IGNORECASE)


@dataclass(frozen=True)
class CommandClassification:
    action_type: str
    exact_action: str
    cwd: str
    repo_id: str | None
    host: str
    target: str
    is_read_only: bool
    read_only_reason: str
    is_capital: bool
    capital_reason: str
    risk_class: str


def classify_tool_call(
    tool_name: str,
    payload: dict[str, Any],
    cwd: Path,
    registry: CapitalRegistry,
    host: str = "local",
) -> CommandClassification:
    action_type = _action_type(tool_name)
    exact_action = _exact_action(tool_name, payload)
    target = _target(tool_name, payload, cwd)
    is_read_only, read_only_reason = _is_read_only(tool_name, exact_action)
    capital = _classify_capital(
        cwd,
        target,
        registry,
        exact_action=exact_action,
        host=host,
        tool_name=tool_name,
    )
    if capital.is_capital and capital.reason == "capital-secret-surface":
        # Secret/key/vault access requires an intent even when it is a read (exfil).
        is_read_only = False
        read_only_reason = "capital-secret-access-requires-intent"
        risk_class = "capital-secret"
    elif capital.is_capital:
        risk_class = "capital-high"
    else:
        risk_class = "non-capital"
    return CommandClassification(
        action_type=action_type,
        exact_action=exact_action,
        cwd=str(cwd),
        repo_id=capital.repo_id,
        host=host,
        target=target,
        is_read_only=is_read_only,
        read_only_reason=read_only_reason,
        is_capital=capital.is_capital,
        capital_reason=capital.reason,
        risk_class=risk_class,
    )


def _action_type(tool_name: str) -> str:
    folded = tool_name.lower()
    if folded == "bash":
        return "shell"
    if folded in {"edit", "write"}:
        return "file-write"
    if "mcp" in folded:
        return "mcp"
    return "tool"


def _exact_action(tool_name: str, payload: dict[str, Any]) -> str:
    if tool_name.lower() == "bash":
        return str(payload.get("command", ""))
    for key in ("file_path", "path", "target", "name"):
        if payload.get(key):
            return f"{tool_name}:{payload[key]}"
    return tool_name


def _target(tool_name: str, payload: dict[str, Any], cwd: Path) -> str:
    if tool_name.lower() == "bash":
        return _bash_target(str(payload.get("command", "")))
    for key in ("file_path", "path", "target", "service"):
        value = payload.get(key)
        if value:
            path = Path(str(value))
            if not path.is_absolute() and key in {"file_path", "path"}:
                return str(cwd / path)
            return str(value)
    return str(cwd)


def _bash_target(command: str) -> str:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return command
    if len(tokens) >= 3 and tokens[0] == "systemctl":
        return tokens[-1]
    if len(tokens) >= 2:
        return tokens[-1]
    return command


def _is_read_only(tool_name: str, exact_action: str) -> tuple[bool, str]:
    folded_tool = tool_name.lower()
    if folded_tool == "bash":
        return _is_read_only_bash(exact_action)
    if folded_tool in {"edit", "write"}:
        return False, "agent-file-write"
    if "mcp" in folded_tool:
        leaf = folded_tool.rsplit("__", maxsplit=1)[-1].replace("-", "_")
        if leaf.startswith(READ_ONLY_MCP_PREFIXES):
            return True, "read-only-mcp-allowlist"
        return False, "mutating-mcp-or-unknown"
    return False, "not-in-read-only-allowlist"


def _is_read_only_bash(command: str) -> tuple[bool, str]:
    if not command.strip():
        return False, "empty-command"
    if (
        "\n" in command
        or "\r" in command
        or SINGLE_AMPERSAND_RE.search(command)
        or any(token in command for token in SHELL_CONTROL_TOKENS)
        or "$(" in command
    ):
        return False, "shell-control-not-allowlisted"
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False, "unparseable-command"
    if not tokens:
        return False, "empty-command"

    command_name = Path(tokens[0]).name
    if command_name == "git":
        if len(tokens) >= 2 and tokens[1] in READ_ONLY_GIT_SUBCOMMANDS:
            return True, "read-only-git-allowlist"
        return False, "not-in-read-only-allowlist"
    if command_name == "systemctl":
        subcommand = next((token for token in tokens[1:] if not token.startswith("-")), "")
        if subcommand in READ_ONLY_SYSTEMCTL_SUBCOMMANDS:
            return True, "read-only-systemctl-allowlist"
        return False, "not-in-read-only-allowlist"
    if command_name in READ_ONLY_COMMANDS:
        return True, "read-only-command-allowlist"
    return False, "not-in-read-only-allowlist"


def _classify_capital(
    cwd: Path,
    target: str,
    registry: CapitalRegistry,
    *,
    exact_action: str,
    host: str,
    tool_name: str,
) -> ClassificationResult:
    """Capital == the action matches an enumerated live-capital TRIGGER, independent
    of cwd. Authoring (edits to capital-repo SOURCE), dev commands, and non-secret
    reads are non-capital. Unknown -> non-capital. Bash commands are scanned in full
    except for a strict, whole-command cat-heredoc authoring shape, so a trigger
    cannot be smuggled by position or shell-wrapping.

    Trigger set: (A) secret/key/vault access [read or write], (B) capital-service
    mutation, (C) live-CEX order, (E) capital-address transfer/sign. Capital-host
    mutations (ssh/scp) are caught automatically because A/B/C/E scan the whole
    command, including the remote portion."""
    repo_id = registry.classify_path(cwd).repo_id  # label only; repo membership does NOT gate
    is_file_write = tool_name.lower() in {"edit", "write", "notebookedit"}
    scan_action = exact_action
    if tool_name.lower() == "bash":
        reduced = _heredoc_authoring_scan(exact_action, cwd, registry)
        if reduced is not None:
            scan_action = reduced
    haystack = f"{scan_action} {target}"

    # A. Secret / key / vault surface access (read OR write) — the one gated 'read'.
    if _touches_secret_surface(haystack, target, registry, is_file_write=is_file_write):
        return ClassificationResult(True, "capital-secret-surface", repo_id)

    # File-write tools: only secret-surface access gates them. Editing capital-repo
    # SOURCE is authoring (reversible) -> free.
    if is_file_write:
        return ClassificationResult(False, "authoring-file-write", repo_id)

    # B. Capital service mutation (systemctl/docker/... + mutating verb + capital service).
    if _capital_service_mutation(haystack, registry):
        return ClassificationResult(True, "capital-service-mutation", repo_id)

    # C. Live-CEX order (mutating HTTP to a capital network target). Plain GET -> free.
    if CEX_MUTATING_RE.search(haystack) and registry.is_capital_network_target(haystack):
        return ClassificationResult(True, "capital-cex-order", repo_id)

    # E. Capital-address transfer/sign op.
    if ADDRESS_MUTATING_RE.search(haystack) and _references_capital_address(haystack, registry):
        return ClassificationResult(True, "capital-address-op", repo_id)

    # Everything else — authoring, dev commands, reads, unknown — is non-capital.
    return ClassificationResult(False, "non-capital", repo_id)


def _heredoc_authoring_scan(command: str, cwd: Path, registry: CapitalRegistry) -> str | None:
    """Return a body-free scan string for one exact, literal cat heredoc write.

    This deliberately recognizes one narrow whole-command shape instead of parsing
    shell syntax. Every mismatch, uncertainty, or unsafe sink returns ``None`` so
    callers retain the existing full-command trigger scan.
    """
    if "\r" in command or any(guard in command for guard in HEREDOC_AUTHORING_RAW_GUARDS):
        return None

    header = HEREDOC_AUTHORING_HEADER_RE.match(command)
    if header is None:
        return None

    sink = _literal_heredoc_sink(header.group("sink"))
    if sink is None:
        return None

    delimiter = header.group("delimiter")
    body_and_terminator = command[header.end():]
    lines = body_and_terminator.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # A single final newline after the terminator is harmless.
    if not lines or lines[-1] != delimiter or delimiter in lines[:-1]:
        return None

    sink_path = Path(sink)
    if not sink_path.is_absolute():
        sink_path = cwd / sink_path
    try:
        resolved_sink = sink_path.expanduser().resolve(strict=False)
    except OSError:
        return None
    if any(resolved_sink == root or root in resolved_sink.parents for root in PSEUDO_FILESYSTEM_ROOTS):
        return None
    try:
        mode = sink_path.lstat().st_mode
    except FileNotFoundError:
        pass  # A new ordinary file is a safe sink shape.
    except OSError:
        return None
    else:
        if not stat.S_ISREG(mode):
            return None

    # Keep Bash heredoc authoring aligned with the Edit/Write secret-surface rule.
    if _touches_secret_surface(str(resolved_sink), str(resolved_sink), registry, is_file_write=True):
        return None

    final_newline = "\n" if body_and_terminator.endswith("\n") else ""
    return f"{command[:header.end()]}{delimiter}{final_newline}"


def _literal_heredoc_sink(raw_sink: str) -> str | None:
    """Parse exactly one non-expanding path token, or fail closed."""
    if raw_sink.startswith("#") or HEREDOC_LITERAL_PATH_FORBIDDEN_RE.search(raw_sink):
        return None
    try:
        tokens = shlex.split(raw_sink)
    except ValueError:
        return None
    if len(tokens) != 1 or not tokens[0]:
        return None
    return tokens[0]


def _touches_secret_surface(haystack: str, target: str, registry: CapitalRegistry, *, is_file_write: bool) -> bool:
    # For file writes scan only the target path, so a source file merely NAMED
    # 'signer_utils.py' is not gated; for shell commands scan the whole command.
    scan = target if is_file_write else haystack
    entry = registry.vault_surface_entry(scan)
    if entry is not None and bool(entry.get("capital", True)) and not _benign_name_shape_match(scan, entry):
        return True
    # Substring fallback over registered surface paths — robust to ssh/scp 'host:/path'
    # prefixes that defeat absolute-path parsing (e.g. 'scp x prod-host-1:/opt/prod-signer/').
    for surface in registry.vault_surfaces:
        raw = surface.get("path")
        if raw and bool(surface.get("capital", True)):
            token = str(raw).rstrip("/")
            if token and token in scan:
                return True
    # Concrete secret artifacts (.age/.pem/signer-key/...), excluding published PUBLIC keys.
    return _secret_artifact_hit(scan)


def _secret_artifact_hit(scan: str) -> bool:
    """A concrete secret artifact is referenced. PUBLIC keys are published, not
    secret, so a token that is a public key does not count."""
    for tok in scan.split():
        if SECRET_ARTIFACT_RE.search(tok) and not PUBLIC_KEY_RE.search(tok):
            return True
    return False


def _benign_name_shape_match(scan: str, entry: dict) -> bool:
    """True when a vault_surface entry matched ONLY via a name-shape guess
    (prefix/suffix) against script/source files (e.g. 'vault-up.sh'). Explicit
    registered 'path' entries are never relaxed, and if ANY shape-matching token is
    not a script/source file the match stands — no smuggling a real secret in
    alongside a benign vault- script."""
    if entry.get("path"):
        return False
    prefix = entry.get("prefix")
    suffix = entry.get("suffix")
    shape_names = []
    for tok in scan.split():
        name = tok.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        if (prefix and name.startswith(str(prefix))) or (suffix and name.endswith(str(suffix))):
            shape_names.append(name)
    return bool(shape_names) and all(NON_SECRET_EXT_RE.search(n) for n in shape_names)


def _capital_service_mutation(haystack: str, registry: CapitalRegistry) -> bool:
    low = haystack.lower()
    if not any(token in low for token in SERVICE_MANAGER_TOKENS):
        return False
    if not any(
        re.search(rf"(?<![a-z0-9-]){re.escape(verb)}(?![a-z0-9-])", low)
        for verb in CAPITAL_SERVICE_VERBS
    ):
        return False
    for service in registry.services:
        if not bool(service.get("capital", True)):
            continue
        for needle in (str(service.get("name", "")), str(service.get("pattern", ""))):
            if needle and needle.lower() in low:
                return True
    return False


def _references_capital_address(haystack: str, registry: CapitalRegistry) -> bool:
    match = EVM_ADDRESS_RE.search(haystack)
    if match and registry.is_capital_address(match.group(0)):
        return True
    for entry in registry.addresses:
        env_name = entry.get("env")
        if env_name and bool(entry.get("capital", True)) and re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(str(env_name))}(?![A-Za-z0-9_])", haystack
        ):
            return True
    return False

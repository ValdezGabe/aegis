"""
Agentic tool-call firewall.

The /chat guard in main.py protects a *conversation*: it inspects a message
before the model sees it and the reply before the user sees it. But modern AI
systems are no longer just chat — they are *agents* that take actions in the
world: reading files, calling APIs, running shell commands, sending email. Each
of those actions is a place an attacker (or a confused model) can cause real
damage: exfiltrate data, reach an internal service, delete files, spend money.

This module is the second half of Aegis: a firewall for *actions* rather than
*words*. Before an agent is allowed to run a tool, the intended call — the tool
name and its arguments — passes through the checks below. Only calls that
survive every check are allowed to execute.

The design follows the OWASP Top 10 for Agentic Applications (2026). The most
relevant risks it addresses:

  - Excessive agency / tool misuse: an agent invoking a tool it should not, or
    with dangerous arguments (least-privilege tool allowlist + per-tool policy).
  - Prompt injection reaching the action layer: an injected instruction smuggled
    inside a tool argument (the same inbound scan the chat guard uses).
  - Privilege escalation via unsafe tool arguments: path traversal on a file
    tool, SSRF on an HTTP tool, destructive shell commands.
  - Runaway autonomy: an agent stuck in a loop hammering tools (rate limiting).
  - Human-in-the-loop: high-impact tools require explicit approval, and a global
    kill switch can halt all agent action at once.

Nothing here talks to the network on its own. main.py wires in the existing
pattern + classifier scan (as `injection_scan`) so the action layer reuses the
same detection the chat layer already trusts.
"""

import ipaddress
import re
import time
from collections import deque
from urllib.parse import urlparse


# ==================================================================
# TOOL REGISTRY — least privilege
# ==================================================================
# An agent may only call a tool that appears here. Anything else is denied by
# default. This is the single most important agentic control: it turns "the
# agent can do anything the model decides" into "the agent can do exactly these
# named things, and nothing more."
#
# Each tool declares:
#   - requires_approval: high-impact tools that a human must sign off on before
#     they run. The firewall denies them with a "pending approval" reason rather
#     than executing automatically. This is the human-in-the-loop control.
#   - description: plain text, so the audit log reads clearly.
TOOL_REGISTRY = {
    "web_search": {
        "requires_approval": False,
        "description": "Search the public web for a query string.",
    },
    "http_get": {
        "requires_approval": False,
        "description": "Fetch a public URL over HTTP(S).",
    },
    "read_file": {
        "requires_approval": False,
        "description": "Read a file from inside the agent sandbox.",
    },
    "write_file": {
        "requires_approval": True,
        "description": "Write a file inside the agent sandbox.",
    },
    "run_shell": {
        "requires_approval": True,
        "description": "Run a shell command in the sandbox.",
    },
    "send_email": {
        "requires_approval": True,
        "description": "Send an email on the user's behalf.",
    },
}


# ==================================================================
# RATE LIMITING — stop runaway autonomy
# ==================================================================
# An agent in a bad loop can call tools hundreds of times a second, draining
# quota or amplifying an attack. We allow at most MAX_CALLS tool calls per
# identity within a sliding RATE_WINDOW of seconds. State is kept in memory, so
# it resets on restart — fine for a single-instance gateway; a production fleet
# would move this to Redis so the limit is shared across replicas.
MAX_CALLS = 30
RATE_WINDOW = 60  # seconds

# identity -> deque of recent call timestamps (seconds).
_call_history: dict[str, deque] = {}


def _rate_limited(identity: str) -> bool:
    """Return True if this identity has exceeded its tool-call budget."""
    now = time.time()
    history = _call_history.setdefault(identity, deque())
    # Drop timestamps that have aged out of the window.
    cutoff = now - RATE_WINDOW
    while history and history[0] < cutoff:
        history.popleft()
    if len(history) >= MAX_CALLS:
        return True
    history.append(now)
    return False


# ==================================================================
# PER-TOOL ARGUMENT POLICY
# ==================================================================
# Being allowed to call a tool is not the same as being allowed to call it with
# *any* arguments. read_file is safe; read_file("/etc/shadow") is not. Each
# function below inspects one tool's arguments and returns (blocked, reason).

# Paths an agent must never touch, even inside the sandbox — secrets and
# credential material. Matched case-insensitively as substrings of the path.
SENSITIVE_PATH_MARKERS = [
    ".env",
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".aws",
    ".kube",
    "credentials",
    "secrets",
    "/etc/passwd",
    "/etc/shadow",
    ".git/config",
    ".npmrc",
    ".pypirc",
]


def _check_file_path(arguments: dict) -> tuple[bool, str]:
    """
    Guard read_file / write_file. The agent is confined to a sandbox root, so a
    path may not escape it and may not point at known secret files.
    """
    path = str(arguments.get("path", ""))
    if not path:
        return True, "no 'path' argument provided"

    # Path traversal: '..' segments, a home-directory reference, or a URL-style
    # scheme are all attempts to reach outside the sandbox.
    if ".." in path or path.startswith("~") or "://" in path:
        return True, f"path traversal attempt: {path!r}"

    lowered = path.lower()
    for marker in SENSITIVE_PATH_MARKERS:
        if marker in lowered:
            return True, f"path targets sensitive file ({marker}): {path!r}"

    return False, ""


# Private / internal address ranges an outbound fetch must never reach. Hitting
# these from inside the network is Server-Side Request Forgery (SSRF): the agent
# is tricked into reaching an internal service or the cloud metadata endpoint
# (169.254.169.254), which can hand out credentials.
def _is_private_host(host: str) -> bool:
    """True if the host resolves to a loopback/private/link-local address."""
    if host in ("localhost", "metadata", "metadata.google.internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not a literal IP (a domain name). We do not resolve DNS here — that is
        # a documented next step (DNS-rebinding defense). For now we block the
        # obvious literals and named-metadata hosts above.
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
    )


def _check_http_url(arguments: dict) -> tuple[bool, str]:
    """Guard http_get. Only public http(s) URLs; block SSRF to internal hosts."""
    url = str(arguments.get("url", ""))
    if not url:
        return True, "no 'url' argument provided"

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return True, f"disallowed URL scheme: {parsed.scheme!r}"

    host = parsed.hostname or ""
    if _is_private_host(host):
        return True, f"SSRF blocked: URL targets internal host {host!r}"

    return False, ""


# Shell fragments that are destructive or a common exfiltration/backdoor
# pattern. Even inside a sandbox these should never run unattended.
DANGEROUS_SHELL_PATTERNS = [
    r"\brm\s+-rf\b",
    r":\(\)\s*\{",          # fork bomb  :(){ :|:& };:
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bchmod\s+-R\b",
    r"\bcurl\b[^|]*\|\s*(ba)?sh",   # curl ... | sh
    r"\bwget\b[^|]*\|\s*(ba)?sh",
    r">\s*/dev/sd",
    r"\bnc\b\s+-e",         # netcat reverse shell
    r"/etc/(passwd|shadow)",
]


def _check_shell_command(arguments: dict) -> tuple[bool, str]:
    """Guard run_shell. Block destructive / backdoor command patterns."""
    command = str(arguments.get("command", ""))
    if not command:
        return True, "no 'command' argument provided"

    for pattern in DANGEROUS_SHELL_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True, f"dangerous shell command blocked (matched /{pattern}/)"

    return False, ""


# Map each tool to its argument policy. Tools with no entry have no extra
# argument checks beyond the allowlist and the injection scan.
ARGUMENT_POLICIES = {
    "read_file": _check_file_path,
    "write_file": _check_file_path,
    "http_get": _check_http_url,
    "run_shell": _check_shell_command,
}


# ==================================================================
# DECISION ENGINE
# ==================================================================
# A single global kill switch. When set (main.py flips this from an env var),
# every tool call is denied — a one-line emergency stop for all agent action.
KILL_SWITCH = False


def evaluate_tool_call(tool: str, arguments: dict, identity: str, injection_scan):
    """
    Decide whether an agent's intended tool call may proceed.

    Args:
      tool:          the tool the agent wants to call, e.g. "http_get".
      arguments:     the tool's arguments as a dict, e.g. {"url": "..."}.
      identity:      who is making the call (for rate limiting + the audit log).
      injection_scan: a callable(text) -> (blocked: bool, reason: str). main.py
                     passes in the existing pattern + classifier scan so the
                     action layer reuses the chat layer's detection.

    Returns a decision dict:
      {
        "allowed": bool,
        "control": which check decided it (e.g. "allowlist", "ssrf"),
        "reason":  human-readable explanation,
        "requires_approval": bool,   # true when denied pending human sign-off
      }

    Checks run cheapest-and-most-severe first, so an obvious block never pays for
    an expensive check further down.
    """
    # 0) Kill switch — emergency stop for everything.
    if KILL_SWITCH:
        return _deny("kill_switch", "agent kill switch is engaged; all tool calls halted")

    # 1) Rate limit — stop runaway loops before doing any other work.
    if _rate_limited(identity):
        return _deny(
            "rate_limit",
            f"identity {identity!r} exceeded {MAX_CALLS} tool calls / {RATE_WINDOW}s",
        )

    # 2) Least-privilege allowlist — unknown tools are denied outright.
    if tool not in TOOL_REGISTRY:
        return _deny("allowlist", f"tool {tool!r} is not in the allowlist")

    spec = TOOL_REGISTRY[tool]

    # 3) Injection scan — an attacker may hide "ignore your instructions and ..."
    #    inside a tool argument. We scan only the *string values* of the
    #    arguments, not the JSON keys or punctuation: the injection detector is
    #    trained on natural language, so feeding it structured scaffolding
    #    ({"path": ...}) just produces false positives. main.py passes in the
    #    same pattern + classifier scan the chat guard uses.
    scan_text = _collect_text(arguments)
    if scan_text.strip():
        blocked, reason = injection_scan(scan_text)
        if blocked:
            return _deny("injection", f"prompt injection in tool arguments: {reason}")

    # 4) Per-tool argument policy — SSRF, path traversal, dangerous shell, etc.
    policy = ARGUMENT_POLICIES.get(tool)
    if policy:
        blocked, reason = policy(arguments)
        if blocked:
            return _deny("argument_policy", reason)

    # 5) Human-in-the-loop — high-impact tools require explicit approval, so we
    #    deny automatic execution and surface that a human must sign off.
    if spec["requires_approval"]:
        return {
            "allowed": False,
            "control": "approval_required",
            "reason": f"tool {tool!r} requires human approval before it runs",
            "requires_approval": True,
        }

    # Survived every check.
    return {
        "allowed": True,
        "control": "none",
        "reason": "all agentic checks passed",
        "requires_approval": False,
    }


def _collect_text(value) -> str:
    """
    Pull every string value out of an arguments structure (dicts, lists, nested)
    and join them with spaces. Keys and punctuation are left out so the
    natural-language injection detector only sees natural-language content.
    """
    parts = []
    if isinstance(value, str):
        parts.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            parts.append(_collect_text(v))
    elif isinstance(value, (list, tuple)):
        for v in value:
            parts.append(_collect_text(v))
    return " ".join(p for p in parts if p)


def _deny(control: str, reason: str) -> dict:
    """Build a standard deny decision."""
    return {
        "allowed": False,
        "control": control,
        "reason": reason,
        "requires_approval": False,
    }

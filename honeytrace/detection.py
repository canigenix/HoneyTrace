"""Conservative, command-aware Cowrie indicators. No shell commands are executed.

This is shallow shell tokenization, NOT a complete shell interpreter. Evasion is
possible; signals represent observed syntax rather than proven attacker intent.
"""
from __future__ import annotations

import re
import shlex
from collections import Counter
from pathlib import PurePosixPath

RULE_VERSION = "1.1"
RULE_IDS = {
    "recon": "HT-R101", "delivery": "HT-R102", "persistence": "HT-R103",
    "destructive": "HT-R104", "privilege": "HT-R105", "obfuscated": "HT-R106",
    "execution": "HT-R107",
}
_RETRIEVERS = {"curl", "wget", "tftp", "ftpget", "scp"}
_RECON = {"whoami", "uname", "id", "hostname", "ifconfig", "netstat", "ss", "ps", "pwd", "ls", "lscpu"}
_INTERPRETERS = {"sh", "bash", "dash", "ash", "zsh"}
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")
_OPERATORS = re.compile(r"^[;&|]+$")
_MAX_LENGTH = 4096


def _name(value: str) -> str:
    return PurePosixPath(value).name.lower()


def _shell_segments(command: str):
    """Yield tokenized simple commands and preceding shell operators.

    Quotes are handled by shlex, and literal arguments are never recursively
    analyzed unless an explicit shell -c executes them.
    """
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    tokens = list(lexer)
    segment: list[str] = []
    prior = ""
    for token in tokens:
        if _OPERATORS.fullmatch(token):
            if segment:
                yield segment, prior
                segment = []
            prior = token
        else:
            segment.append(token)
    if segment:
        yield segment, prior


def _strip_wrapper(items: list[str]) -> list[str]:
    """Unwrap a few well-known command prefixes; do not guess arbitrary shells."""
    args = items[:]
    for _ in range(6):
        if not args:
            return []
        head = _name(args[0])
        if _ENV_ASSIGNMENT.match(args[0]):
            args.pop(0)
            continue
        if head == "env":
            args.pop(0)
            while args and (args[0].startswith("-") or _ENV_ASSIGNMENT.match(args[0])):
                args.pop(0)
            continue
        if head in {"command", "nohup"}:
            args.pop(0)
            continue
        if head == "sudo":
            args.pop(0)
            while args and args[0].startswith("-"):
                option = args.pop(0)
                if option in {"-u", "-g", "-h", "-p", "-C"} and args:
                    args.pop(0)
            continue
        if head == "busybox":
            args.pop(0)
            continue
        break
    return args


def command_indicators(command: str, *, _depth: int = 0) -> frozenset[str]:
    """Return coarse behavior families without executing or saving commands.

    Unparseable quoting returns no matches rather than treating quoted examples
    as live execution. Limited recursive inspection handles explicit 'sh -c'.
    """
    if not isinstance(command, str) or len(command) > _MAX_LENGTH:
        return frozenset()
    result: set[str] = set()
    try:
        segments = list(_shell_segments(command))
    except ValueError:
        return frozenset()
    for raw, prior in segments:
        if _name(raw[0]) == "sudo" and "-l" in raw[1:]:
            result.add("privilege")
        args = _strip_wrapper(raw)
        if not args:
            continue
        head = _name(args[0])
        rest = args[1:]
        lower = [a.lower() for a in rest]
        if head in _RECON or (head == "ip" and lower and lower[0] in {"a", "addr", "address", "route", "r", "link"}):
            result.add("recon")
        if head == "cat" and any(a in {"/etc/passwd", "/etc/os-release"} for a in lower):
            result.add("recon")
        if head == "crontab" and "-l" in lower:
            result.add("recon")  # Listing a crontab is NOT evidence of persistence.
        if head in _RETRIEVERS and not any(arg in {"--help", "--version", "-h"} for arg in lower):
            result.add("delivery")
        if head == "crontab" and (any(a in {"-e", "-r", "-"} for a in lower) or any(not a.startswith("-") for a in rest)):
            result.add("persistence")
        if head == "systemctl" and lower and lower[0] in {"enable", "preset"}:
            result.add("persistence")
        if head in {"echo", "printf", "tee", "install", "cp", "mv"}:
            destinations: list[str] = []
            if head in {"echo", "printf"}:
                # Only the immediate target of a shell redirection is a write.
                destinations = [raw[i + 1].lower() for i, token in enumerate(raw[:-1]) if token in {">", ">>"}]
            elif head == "tee":
                destinations = [a for a in lower if not a.startswith("-")]
            elif len(lower) >= 2:
                destinations = [lower[-1]]
            if any((a.endswith("/authorized_keys") and "/.ssh/" in a)
                   or a == "/etc/crontab" or a.startswith(("/etc/cron.", "/etc/cron/"))
                   or a == "/etc/rc.local" for a in destinations):
                result.add("persistence")
        if head == "rm":
            flags = "".join(a[1:] for a in rest if a.startswith("-") and not a.startswith("--"))
            recursive = "r" in flags or "--recursive" in lower
            force = "f" in flags or "--force" in lower
            if recursive and force:
                result.add("destructive")
        if head in {"mkfs", "shred"} or head.startswith("mkfs."):
            result.add("destructive")
        if head == "dd" and any(a.startswith("of=") for a in lower) and any(a.startswith("if=") for a in lower):
            result.add("destructive")
        if head == "getcap":
            result.add("privilege")
        if head == "cat" and "/etc/shadow" in lower:
            result.add("privilege")
        if head == "find" and ("-perm" in lower or "-capable" in lower):
            result.add("privilege")
        if head == "base64" and any(a in {"-d", "--decode"} for a in lower):
            result.add("obfuscated")
        if head == "eval":
            result.add("obfuscated")
        # A script invoked from the shell, or a shell receiving data on stdin.
        if args[0].startswith(("./", "/tmp/", "/var/tmp/")):
            result.add("execution")
        if head in _INTERPRETERS:
            if prior == "|" or (rest and not rest[0].startswith("-") and rest[0] not in {"-"}):
                result.add("execution")
            cpos = next((i for i, a in enumerate(rest) if a == "-c" or (a.startswith("-") and "c" in a[1:] and len(a) <= 5)), None)
            if cpos is not None:
                result.add("obfuscated")
                if _depth < 2 and cpos + 1 < len(rest):
                    result.update(command_indicators(rest[cpos + 1], _depth=_depth + 1))
        if head in {"python", "python2", "python3", "perl", "ruby"} and any(a in {"-c", "-e"} for a in lower):
            result.add("obfuscated")
    return frozenset(result)


def session_indicators(commands: list[str]) -> tuple[dict[str, int], list[str]]:
    """Count each command at most once per family; recognize co-occurrence."""
    counts: Counter[str] = Counter()
    for command in commands:
        counts.update(command_indicators(command))
    found = {RULE_IDS[family] for family in counts if family in RULE_IDS}
    return dict(counts), sorted(found)

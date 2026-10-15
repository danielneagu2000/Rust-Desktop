#!/usr/bin/env python3
"""PreToolUse hook: no release without a security review of exactly the code being released.

A release is the "Publish new version" workflow (.github/workflows/release.yml), started through
the GitHub MCP tool or `gh`. After reviewing every change since the last release tag (AGENTS.md,
"Releases"), record the reviewed commit:

    git fetch origin master && git rev-parse origin/master > .claude/security-reviewed

Any later push to master needs a new review: the marker must name the commit being released.
"""

import json
import os
import re
import subprocess
import sys

RELEASE_WORKFLOW_ID = "372846883"  # numeric id of release.yml in danielneagu2000/Rust-Desktop


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


data = json.load(sys.stdin)
tool, args = data.get("tool_name", ""), data.get("tool_input") or {}
ref = "master"
if tool == "Bash":
    cmd = args.get("command", "")
    starts = bool(re.search(r"\bgh\s+workflow\s+run\b[^\n;&|]*release", cmd)
                  or re.search(r"release\.ya?ml/dispatches", cmd))
    m = re.search(r"--ref[ =](\S+)", cmd)
    ref = m.group(1) if m else ref
else:
    workflow = str(args.get("workflow_id", ""))
    starts = (args.get("method", "run_workflow") == "run_workflow"
              and (re.search(r"(^|/)release\.ya?ml$", workflow) is not None or workflow == RELEASE_WORKFLOW_ID))
    ref = str(args.get("ref") or ref)
if not starts:
    sys.exit(0)

root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
ref = ref.removeprefix("refs/heads/")
try:
    out = subprocess.run(["git", "ls-remote", "origin", f"refs/heads/{ref}"], cwd=root,
                         capture_output=True, text=True, timeout=60).stdout.split()
except (OSError, subprocess.TimeoutExpired):
    out = []
if not out:
    deny(f"Release blocked: could not read the commit of origin/{ref} to compare with the security review.")
head = out[0]
try:
    with open(os.path.join(root, ".claude", "security-reviewed")) as f:
        reviewed = (f.read().split() or [""])[0]
except OSError:
    reviewed = ""
if reviewed != head:
    deny(
        f"Release blocked: no security review recorded for origin/{ref} ({head[:12]}). "
        "Rule from the owner: never start a release without a thorough security review. "
        "Review every change since the last release tag (AGENTS.md, section Releases), fix what it finds, "
        "report the result to the user, then record it with: "
        f"git fetch origin {ref} && git rev-parse origin/{ref} > .claude/security-reviewed"
    )

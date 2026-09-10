# OSINT Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the single remaining `osint`-category tool endpoint from the legacy monolith (`hexstrike_server.py` at commit `d689933`) into `hexstrike/tools/osint.py`, reaching full parity for the `osint` category (1 tool already ported — `amass_enum` — → 2 total). This is the entire remaining scope of the category; `amass` was the only other `osint`-tagged endpoint found in the legacy source (verified via `grep -n '@app.route("/api/tools/' hexstrike_server.py` against known OSINT tool names — `theharvester`, `spiderfoot`, `sherlock`, etc. mentioned in `requirements.txt`'s installation notes have no corresponding route in the legacy monolith and are out of scope).

**Architecture:** Same pattern as `network`/`web`/`cloud`/`forensics`/`password`: a single Python function decorated with `@ToolRegistry.register(...)`, building a `List[str]` command and returning `run_tool_command(cmd)` from `hexstrike/tools/base.py`. `hexstrike/tools/__init__.py` already imports `osint` (no change needed there).

**Tech Stack:** Python 3.13, pytest — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`. Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`.

## Global Constraints

- **Verbatim behavior, adapted only where a shell construct has no `List[str]` equivalent**: the legacy `hakrawler` endpoint pipes its input through a shell (`command = f"echo '{url}' | hakrawler -d {depth} ..."`, executed via a shell string). The new architecture runs commands as `List[str]` with `shell=False` (see `hexstrike/core/process.py:37-43`) — a literal pipe isn't available. `hakrawler` supports a native `-url` flag that accepts the target directly, with identical crawl behavior to piping the URL via stdin. This plan uses `-url <url>` instead of `echo | hakrawler`, following the same precedent as the network migration's `rpcclient_enum` (native flag replacing an unavailable shell pipe, sibling tool set unchanged, only the transport mechanism differs).
- **No shell strings**: commands are built as `List[str]` and executed via `subprocess.run(command, ...)` with no `shell=True`.
- **`additional_args` handling**: optional (`Optional[str] = None`), appended via `additional_args.split()` (whitespace split — not `shlex.split`), always last.
- **Legacy manual validation is not reproduced for the missing-`url` case**: legacy did `if not url: return jsonify({"error": ...}), 400`. The new pattern makes `url` a required parameter with no default; a missing value raises `TypeError`, converted to a 400 by `hexstrike/api/app.py:15-20`. Do not re-add a manual `if not url` check.
- **Preserve the exact (slightly redundant) conditional logic for `-subs`**: legacy sets it whenever `robots or sitemap or wayback` is truthy — even though `-subs` has nothing to do with wayback/sitemap by name. This is legacy behavior, not a bug to fix. Preserve it as-is.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: Create `tests/test_osint_tools.py`, port `hakrawler_crawl`

**Files:**
- Modify: `hexstrike/tools/osint.py`
- Create: `tests/test_osint_tools.py`

**Interfaces:**
- Produces: `hakrawler_crawl(url, depth=2, forms=True, robots=True, sitemap=True, wayback=False, additional_args=None)` registered as tool name `"hakrawler_crawl"` at endpoint `/api/tools/hakrawler`, category `"osint"`.

**Legacy source (`d689933:hexstrike_server.py:15439-15486`):**
```python
command = f"echo '{url}' | hakrawler -d {depth}"
if forms:
    command += " -s"
if robots or sitemap or wayback:
    command += " -subs"
command += " -u"
if additional_args:
    command += f" {additional_args}"
```

**New (`List[str]`) equivalent — `-url` replaces the echo-pipe, order otherwise identical:**
```python
cmd = ["hakrawler", "-url", url, "-d", str(depth)]
if forms:
    cmd.append("-s")
if robots or sitemap or wayback:
    cmd.append("-subs")
cmd.append("-u")
if additional_args:
    cmd.extend(additional_args.split())
```

- [ ] **Step 1: Write the failing test**

Create `tests/test_osint_tools.py`:

```python
import pytest
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
import hexstrike.tools


def _mock_execute(monkeypatch):
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)
    return captured


def test_hakrawler_crawl_handler_invocation_defaults(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("hakrawler_crawl")
    assert tool is not None
    assert tool.category == "osint"
    assert tool.endpoint == "/api/tools/hakrawler"

    res = tool.handler(url="https://example.com")
    assert res["success"] is True
    assert captured["cmd"] == ["hakrawler", "-url", "https://example.com", "-d", "2", "-s", "-subs", "-u"]


def test_hakrawler_crawl_handler_invocation_no_flags(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("hakrawler_crawl")

    res = tool.handler(url="https://example.com", depth=5, forms=False, robots=False, sitemap=False, wayback=False, additional_args="-t 20")
    assert res["success"] is True
    assert captured["cmd"] == ["hakrawler", "-url", "https://example.com", "-d", "5", "-u", "-t", "20"]


def test_hakrawler_crawl_handler_invocation_wayback_only(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("hakrawler_crawl")

    res = tool.handler(url="https://example.com", forms=False, robots=False, sitemap=False, wayback=True)
    assert res["success"] is True
    assert captured["cmd"] == ["hakrawler", "-url", "https://example.com", "-d", "2", "-subs", "-u"]


def test_osint_category_has_2_tools():
    osint_tools = ToolRegistry.get_by_category("osint")
    assert len(osint_tools) == 2
    names = {t.name for t in osint_tools}
    assert names == {"amass_enum", "hakrawler_crawl"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_osint_tools.py -v`
Expected: FAIL — `ToolRegistry.get("hakrawler_crawl")` returns `None`.

- [ ] **Step 3: Write minimal implementation**

Add to `hexstrike/tools/osint.py`:

```python
@ToolRegistry.register(
    name="hakrawler_crawl",
    category="osint",
    description="Web endpoint discovery and crawling using Hakrawler",
    endpoint="/api/tools/hakrawler"
)
def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, robots: bool = True, sitemap: bool = True, wayback: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["hakrawler", "-url", url, "-d", str(depth)]
    if forms:
        cmd.append("-s")
    if robots or sitemap or wayback:
        cmd.append("-subs")
    cmd.append("-u")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_osint_tools.py -v`
Expected: PASS

- [ ] **Step 5: Run the entire test suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add hexstrike/tools/osint.py tests/test_osint_tools.py docs/superpowers/plans/2026-09-10-osint-tools-migration.md
git commit -m "$(cat <<'EOF'
feat(tools): port hakrawler_crawl to osint tool registry, complete category

Replaces legacy's shell-piped `echo url | hakrawler` with hakrawler's
native `-url` flag, since the new architecture never invokes a shell
(no List[str] equivalent of a pipe exists) — same precedent as the
network migration's rpcclient_enum. Crawl behavior against the target
is unchanged; only the transport mechanism differs. Completes the
osint category at 2/2 tools (amass_enum, hakrawler_crawl).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

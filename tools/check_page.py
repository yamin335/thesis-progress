#!/usr/bin/env python3
"""Static checks for the dashboard page, run before every publish of index.html or assets/.

No browser exists on the build machine, so this script catches what a browser would reveal on
first load:

1. ``assets/app.js`` must parse as a script (esprima, when installed; the thesis venv has it).
2. Every element id the script looks up with ``$('...')`` must exist in ``index.html``, and every
   id of a canvas the script draws on by name must too (a missing id leaves a section empty).
3. The versioned asset URLs in ``index.html`` (``?v=...``) must be identical for the script and the
   stylesheet, so a cache can never pair an old script with a new page.
4. ``index.html`` must not contain inline scripts or external hosts other than the allowed CDN
   (the Content-Security-Policy would block them).
5. The ``el()`` helper is used with ``open:`` attributes; a literal ``'open'`` string or ``null``
   there is a known bug pattern (an attribute set to the text "null" is still present).

Run from the dashboard repository root::

    python3 tools/check_page.py            # exit code 0 when everything passes

See ARCHITECTURE.md ("Checks before publishing").
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_HOSTS = ("https://cdnjs.cloudflare.com/",)


def parse_script(path: Path) -> list[str]:
    """Parse the script with esprima; returns a list of problems (empty when it parses)."""
    try:
        import esprima
    except ImportError:
        print("note: esprima not installed, skipping the syntax check "
              "(install with: uv pip install esprima)")
        return []
    try:
        esprima.parseScript(path.read_text(encoding="utf-8"), tolerant=False)
        return []
    except Exception as error:  # esprima raises its own Error subclass
        return [f"{path.name}: parse error: {error}"]


def ids_in_html(html: str) -> set[str]:
    """All element ids declared in the page."""
    return set(re.findall(r'\bid="([^"]+)"', html))


def ids_used_in_script(js: str) -> set[str]:
    """Element ids the script looks up by name: ``$('id')`` and string canvas ids passed to charts."""
    used = set(re.findall(r"\$\('([^']+)'\)", js))
    used |= set(re.findall(r"(?:makeChart|barChart|emptyChart|showCanvas)\('([^']+)'", js))
    return used


def check_versions(html: str) -> list[str]:
    """The script and stylesheet must carry the same ``?v=`` value."""
    versions = set(re.findall(r'assets/(?:app\.js|style\.css)\?v=([\w.-]+)', html))
    if len(versions) != 1:
        return [f"index.html: asset versions differ or are missing: {sorted(versions)}"]
    return []


def check_csp(html: str) -> list[str]:
    """No inline scripts and no script hosts outside the allowed CDN."""
    problems = []
    for src in re.findall(r'<script[^>]*\bsrc="([^"]+)"', html):
        if src.startswith("http") and not src.startswith(ALLOWED_HOSTS):
            problems.append(f"index.html: script host not allowed by the CSP: {src}")
    if re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html):
        problems.append("index.html: inline script found (blocked by the CSP)")
    return problems


def check_open_attribute(js: str) -> list[str]:
    """``open:`` must be a boolean expression, never the literal strings 'open' or ''/null."""
    problems = []
    for match in re.finditer(r"\bopen:\s*('open'|\"open\"|null\b|''|\"\")", js):
        line = js[:match.start()].count("\n") + 1
        problems.append(f"app.js:{line}: open attribute given as {match.group(1)}; use a boolean")
    return problems


def main() -> int:
    """Run every check and print the findings; exit 1 when any check fails."""
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    js_path = ROOT / "assets" / "app.js"
    js = js_path.read_text(encoding="utf-8")
    problems = []
    problems += parse_script(js_path)
    missing = sorted(ids_used_in_script(js) - ids_in_html(html))
    problems += [f"app.js looks up id '{i}' which index.html does not define" for i in missing]
    problems += check_versions(html)
    problems += check_csp(html)
    problems += check_open_attribute(js)
    for problem in problems:
        print("FAIL:", problem)
    if not problems:
        print("page checks passed: script parses, %d ids resolved, asset version %s"
              % (len(ids_used_in_script(js)), re.search(r'\?v=([\w.-]+)', html).group(1)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

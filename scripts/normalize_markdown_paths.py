#!/usr/bin/env python3
import argparse
import re
from pathlib import Path


INLINE_LINK_RE = re.compile(r"(!?\[[^\]]*\]\()([^\)\n]+)(\))")
REFERENCE_LINK_RE = re.compile(r"^(\s*\[[^\]]+\]:\s*)(\S+)(.*)$", re.MULTILINE)
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def should_normalize(target: str) -> bool:
    stripped = target.strip()
    if "\\" not in stripped:
        return False
    if stripped.startswith("#"):
        return False
    if SCHEME_RE.match(stripped):
        return False
    if stripped.startswith("//"):
        return False
    return True


def normalize_target(target: str) -> str:
    if not should_normalize(target):
        return target
    return target.replace("\\", "/")


def normalize_inline_links(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        prefix, target, suffix = match.groups()
        return f"{prefix}{normalize_target(target)}{suffix}"

    return INLINE_LINK_RE.sub(repl, text)


def normalize_reference_links(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        prefix, target, suffix = match.groups()
        return f"{prefix}{normalize_target(target)}{suffix}"

    return REFERENCE_LINK_RE.sub(repl, text)


def normalize_markdown(text: str) -> str:
    text = normalize_inline_links(text)
    text = normalize_reference_links(text)
    return text


def iter_markdown_files(paths: list[str]) -> list[Path]:
    collected: list[Path] = []
    seen: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_file() and path.suffix.lower() == ".md":
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                collected.append(path)
            continue
        if path.is_dir():
            for child in sorted(path.rglob("*.md")):
                resolved = child.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    collected.append(child)
    return collected


def process_file(path: Path) -> bool:
    original = path.read_text(encoding="utf-8")
    normalized = normalize_markdown(original)
    if normalized == original:
        return False
    path.write_text(normalized, encoding="utf-8", newline="\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize backslashes to forward slashes in Markdown paths."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["docs"],
        help="Markdown files or directories to clean. Defaults to docs.",
    )
    args = parser.parse_args()

    markdown_files = iter_markdown_files(args.paths)
    if not markdown_files:
        print("No Markdown files found.")
        return 0

    changed_files: list[Path] = []
    for markdown_file in markdown_files:
        if process_file(markdown_file):
            changed_files.append(markdown_file)

    if not changed_files:
        print("No files needed changes.")
        return 0

    print(f"Updated {len(changed_files)} file(s):")
    for path in changed_files:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

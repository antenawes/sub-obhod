#!/usr/bin/env python3
"""Fetch text config lists, optionally decode base64 subscriptions, and deduplicate lines."""

from __future__ import annotations

import base64
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, unquote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
SOURCES_FILE = ROOT / "sources.txt"
OUTPUT_FILE = ROOT / "all_configs.txt"
TIMEOUT_SECONDS = 35
RETRIES = 2

CONFIG_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "ssr", "socks", "socks4", "socks5",
    "http", "https", "hysteria", "hysteria2", "hy2", "tuic", "wireguard",
}


def normalize_github_url(url: str) -> str:
    """Convert github.com/.../blob/... links to raw.githubusercontent.com links."""
    url = url.strip()
    if not url:
        return url
    parts = urlsplit(url)
    if parts.netloc.lower() not in {"github.com", "www.github.com"}:
        return url

    path_parts = parts.path.strip("/").split("/")
    # Expected form: /OWNER/REPO/blob/BRANCH/PATH...
    if len(path_parts) < 5 or path_parts[2] != "blob":
        return url

    owner, repo, _blob, branch = path_parts[:4]
    file_path = unquote("/".join(path_parts[4:]))
    raw_path = f"/{owner}/{repo}/{branch}/{file_path}"
    return urlunsplit(("https", "raw.githubusercontent.com", raw_path, parts.query, ""))


def maybe_decode_base64(text: str) -> str:
    """Decode a single-line base64 subscription only when it clearly contains configs."""
    stripped = text.strip().lstrip("\ufeff")
    nonempty = [line.strip() for line in stripped.splitlines() if line.strip()]
    if len(nonempty) != 1:
        return text

    candidate = re.sub(r"\s+", "", nonempty[0])
    if len(candidate) < 80 or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", candidate):
        return text

    try:
        padded = candidate + ("=" * ((-len(candidate)) % 4))
        decoded_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = decoded_bytes.decode("utf-8-sig")
    except (ValueError, UnicodeDecodeError):
        return text

    lowered = decoded.lower()
    if any(f"{scheme}://" in lowered for scheme in CONFIG_SCHEMES):
        return decoded
    return text


def fetch_text(url: str) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "hourly-config-collector/1.0 (GitHub Actions)",
            "Accept": "text/plain,*/*;q=0.8",
        },
    )
    last_error: Exception | None = None
    for attempt in range(RETRIES + 1):
        try:
            with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                payload = response.read()
            text = payload.decode("utf-8-sig", errors="replace")
            return maybe_decode_base64(text)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < RETRIES:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"не удалось скачать {url}: {last_error}")


def dedupe_key(line: str) -> str:
    """Key for deduplication; for connection URIs ignore the display-name fragment."""
    line = line.strip().lstrip("\ufeff")
    if not line:
        return ""

    # A malformed connection URI (for example, an invalid bracketed IPv6 host)
    # can make urlsplit raise ValueError. Skip that bad config instead of stopping
    # the entire hourly collection.
    try:
        parsed = urlsplit(line)
    except ValueError:
        lowered = line.lower()
        if any(lowered.startswith(f"{scheme}://") for scheme in CONFIG_SCHEMES):
            return ""
        return line

    scheme = parsed.scheme.lower()
    if scheme not in CONFIG_SCHEMES or not parsed.netloc:
        return line

    # Preserve case-sensitive credentials; normalize only the hostname.
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, host_port = netloc.rsplit("@", 1)
        prefix = userinfo + "@"
    else:
        host_port = netloc
        prefix = ""

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        hostname, port = None, None

    if hostname:
        normalized_host = hostname.lower()
        if ":" in normalized_host and not normalized_host.startswith("["):
            normalized_host = f"[{normalized_host}]"
        if port is not None:
            normalized_host += f":{port}"
        normalized_netloc = prefix + normalized_host
    else:
        normalized_netloc = netloc

    # Query parameter order usually does not affect a connection URI.
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    normalized_query = urlencode(sorted(query_pairs), doseq=True)
    return urlunsplit((scheme, normalized_netloc, parsed.path, normalized_query, ""))


def read_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        raise FileNotFoundError(f"Не найден файл источников: {SOURCES_FILE}")
    sources: list[str] = []
    seen: set[str] = set()
    for raw_line in SOURCES_FILE.read_text(encoding="utf-8-sig").splitlines():
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        url = normalize_github_url(value)
        if url not in seen:
            seen.add(url)
            sources.append(url)
    return sources


def main() -> int:
    sources = read_sources()
    if not sources:
        print("В sources.txt нет источников.", file=sys.stderr)
        return 2

    unique_lines: list[str] = []
    known_keys: set[str] = set()
    fetched = 0
    failed: list[tuple[str, str]] = []
    duplicates = 0
    skipped_blank = 0

    for index, url in enumerate(sources, start=1):
        try:
            content = fetch_text(url)
            fetched += 1
        except Exception as exc:  # one unavailable source must not break the whole collection
            failed.append((url, str(exc)))
            print(f"[{index}/{len(sources)}] ERROR: {url} — {exc}", file=sys.stderr)
            continue

        added_from_source = 0
        for raw_line in content.splitlines():
            line = raw_line.strip().lstrip("\ufeff")
            if not line:
                skipped_blank += 1
                continue
            key = dedupe_key(line)
            if not key:
                skipped_blank += 1
                continue
            if key in known_keys:
                duplicates += 1
                continue
            known_keys.add(key)
            unique_lines.append(line)
            added_from_source += 1
        print(f"[{index}/{len(sources)}] OK: {url} (+{added_from_source} строк)")

    if fetched == 0:
        print("Ни один источник не скачан; существующий all_configs.txt не изменён.", file=sys.stderr)
        return 1

    output = "\n".join(unique_lines)
    if output:
        output += "\n"
    OUTPUT_FILE.write_text(output, encoding="utf-8")

    print("\n--- Итог ---")
    print(f"Источников всего: {len(sources)}")
    print(f"Успешно скачано: {fetched}")
    print(f"Ошибок источников: {len(failed)}")
    print(f"Удалено повторов: {duplicates}")
    print(f"Пропущено пустых строк: {skipped_blank}")
    print(f"Уникальных строк в all_configs.txt: {len(unique_lines)}")
    print(f"Файл записан: {OUTPUT_FILE}")

    # Partial outages are reported but do not fail the workflow if some sources worked.
    if failed:
        print("\nИсточники с ошибками:", file=sys.stderr)
        for url, error in failed:
            print(f"- {url}: {error}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

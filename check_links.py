#!/usr/bin/env python3
"""
بررسی لینک‌های raw گیت‌هاب.

برای هر لینک:
  - وضعیت دسترسی (HTTP) را می‌گیرد
  - زمان آخرین commit که آن فایل را تغییر داده از GitHub API می‌خواند
خروجی را در فایل Update.txt می‌نویسد.

استفاده:
  python check_links.py links.txt Update.txt
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

TEHRAN = timezone(timedelta(hours=3, minutes=30))
UA = "link-monitor/1.0"

# https://raw.githubusercontent.com/{owner}/{repo}/refs/heads/{branch}/{path}
RAW_RE = re.compile(
    r"^https?://raw\.githubusercontent\.com/"
    r"(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
    r"(?:refs/heads/|refs/tags/|heads/)?"
    r"(?P<branch>[^/]+)/(?P<path>.+)$"
)


def http_get(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def check_raw(url):
    """آیا لینک raw در دسترس است؟"""
    try:
        status, body = http_get(url)
        return f"OK ({status}) - {len(body)} بایت"
    except urllib.error.HTTPError as e:
        return f"خطا ({e.code})"
    except Exception as e:  # noqa: BLE001
        return f"خطا ({type(e).__name__}: {e})"


def last_commit_info(owner, repo, branch, path):
    """زمان و hash آخرین commitی که این فایل را تغییر داده."""
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    query = urllib.parse.urlencode({"sha": branch, "path": path, "per_page": 1})
    api = f"https://api.github.com/repos/{owner}/{repo}/commits?{query}"
    try:
        _, body = http_get(api, headers=headers)
        commits = json.loads(body)
        if not commits:
            return None, None
        c = commits[0]
        when = datetime.fromisoformat(c["commit"]["committer"]["date"].replace("Z", "+00:00"))
        return when, c["sha"][:7]
    except Exception as e:  # noqa: BLE001
        return f"خطا در دریافت commit ({type(e).__name__}: {e})", None


def fmt_time(dt):
    if dt is None:
        return "نامشخص"
    if isinstance(dt, str):
        return dt
    return f"{dt.astimezone(TEHRAN):%Y-%m-%d %H:%M} (تهران) | {dt:%Y-%m-%d %H:%M} UTC"


def read_links(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def main():
    links_file = sys.argv[1] if len(sys.argv) > 1 else "links.txt"
    out_file = sys.argv[2] if len(sys.argv) > 2 else "Update.txt"

    now = datetime.now(timezone.utc)
    lines = [
        f"گزارش بررسی لینک‌ها",
        f"زمان بررسی: {now.astimezone(TEHRAN):%Y-%m-%d %H:%M} (تهران) | {now:%Y-%m-%d %H:%M} UTC",
        "=" * 70,
        "",
    ]

    for url in read_links(links_file):
        lines.append(url)
        m = RAW_RE.match(url)
        if not m:
            lines.append("  وضعیت: لینک raw گیت‌هاب معتبر نیست")
            lines.append("")
            continue

        owner, repo, branch, path = m["owner"], m["repo"], m["branch"], m["path"]
        lines.append(f"  وضعیت: {check_raw(url)}")

        when, sha = last_commit_info(owner, repo, branch, path)
        if isinstance(when, str):
            lines.append(f"  آخرین بروزرسانی: {when}")
        else:
            lines.append(f"  آخرین بروزرسانی: {fmt_time(when)}")
            if sha:
                lines.append(f"  commit: {sha}")
        lines.append("")

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()

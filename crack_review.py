#!/usr/bin/env python3
"""
crack_review.py - Summarize a hashcat cracked-password dump (hash:password).

Reports:
  * password reuse (how many times each password was reused)
  * easily crackable passwords (heuristic, no wordlist required)
  * passwords with exactly one number
  * passwords under 8 characters

Usage:
    python3 crack_review.py cracked.txt
    python3 crack_review.py cracked.txt --out report          # -> report.html + report.csv
    python3 crack_review.py cracked.txt --html-only
    python3 crack_review.py cracked.txt --csv-only
    python3 crack_review.py cracked.txt --min-reuse 3          # reuse table threshold
"""

import argparse
import csv
import html
import os
import re
import sys
from collections import Counter, defaultdict

# ---- Heuristics for "easily crackable" -------------------------------------

# Small built-in list of the usual suspects. Add your own as needed.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "welcome", "welcome1",
    "admin", "admin123", "letmein", "monkey", "dragon", "iloveyou", "abc123",
    "123456", "1234567", "12345678", "123456789", "1234567890", "qwerty",
    "qwerty123", "qwertyuiop", "111111", "000000", "123123", "654321",
    "superman", "batman", "trustno1", "sunshine", "princess", "football",
    "baseball", "master", "shadow", "michael", "ashley", "changeme",
    "summer", "winter", "spring", "autumn", "companyname",
}

KEYBOARD_WALKS = [
    "qwerty", "asdf", "zxcv", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234", "12345", "123456", "0987", "qazwsx", "1qaz2wsx", "!qaz",
]

# Season/month names commonly used with a year, e.g. Summer2024
SEASONS_MONTHS = [
    "spring", "summer", "autumn", "fall", "winter",
    "january", "february", "march", "april", "may", "june", "july",
    "august", "september", "october", "november", "december",
]


def is_keyboard_walk(pw_lower):
    return any(walk in pw_lower for walk in KEYBOARD_WALKS)


def is_season_year(pw_lower):
    # e.g. summer2024, Winter24, Fall_2023
    for token in SEASONS_MONTHS:
        if re.match(rf"^{token}[^a-z0-9]?\d{{2,4}}[^a-z0-9]?$", pw_lower):
            return True
    return False


def looks_like_word_plus_suffix(pw):
    """
    Classic 'CompanyName1!' style: letters, then a few digits, then optional
    small run of symbols. The bread-and-butter of corporate password policies.
    """
    return bool(re.match(r"^[A-Za-z]{3,}\d{1,4}[!@#$%^&*.\-_]{0,3}$", pw))


def easily_crackable_reasons(pw):
    """Return a list of reasons a password is considered easily crackable.
    Empty list means it did not trip any heuristic."""
    reasons = []
    pw_lower = pw.lower()

    if len(pw) < 8:
        reasons.append("under 8 chars")
    if pw_lower in COMMON_PASSWORDS:
        reasons.append("in common list")
    if pw.isdigit():
        reasons.append("all digits")
    if pw.isalpha() and pw.islower():
        reasons.append("all lowercase letters")
    if is_keyboard_walk(pw_lower):
        reasons.append("keyboard walk")
    if is_season_year(pw_lower):
        reasons.append("season/month + year")
    if looks_like_word_plus_suffix(pw):
        reasons.append("word+digits+symbol pattern")
    # single character repeated, e.g. aaaaaa / 111111
    if len(set(pw)) == 1 and len(pw) > 0:
        reasons.append("single repeated char")

    return reasons


def count_digits(pw):
    return sum(c.isdigit() for c in pw)


# ---- Parsing ----------------------------------------------------------------

def parse_file(path):
    """Yield (hash, password) tuples. Splits on the FIRST colon so passwords
    that contain ':' are preserved. Skips blank lines."""
    records = []
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n").rstrip("\r")
            if not line:
                continue
            if ":" not in line:
                skipped += 1
                continue
            h, pw = line.split(":", 1)
            records.append((h, pw))
    return records, skipped


# ---- Analysis ---------------------------------------------------------------

def analyze(records):
    passwords = [pw for _, pw in records]
    total = len(passwords)

    pw_counts = Counter(passwords)
    reused = {pw: c for pw, c in pw_counts.items() if c > 1}

    # accounts affected by reuse = sum of counts for reused passwords
    accounts_with_reuse = sum(c for c in reused.values())
    unique_reused_pw = len(reused)

    one_number = [pw for pw in passwords if count_digits(pw) == 1]
    under_8 = [pw for pw in passwords if len(pw) < 8]

    crackable = []  # (password, reasons)
    for pw in passwords:
        reasons = easily_crackable_reasons(pw)
        if reasons:
            crackable.append((pw, reasons))

    # Top 5 most common passwords at each of these lengths
    top_by_length = {}
    for length in (6, 7, 8):
        c = Counter(pw for pw in passwords if len(pw) == length)
        top_by_length[length] = c.most_common(5)

    return {
        "total": total,
        "unique_passwords": len(pw_counts),
        "pw_counts": pw_counts,
        "reused": reused,
        "accounts_with_reuse": accounts_with_reuse,
        "unique_reused_pw": unique_reused_pw,
        "one_number_count": len(one_number),
        "under_8_count": len(under_8),
        "crackable": crackable,
        "crackable_count": len(crackable),
        "top_by_length": top_by_length,
    }


# ---- Output -----------------------------------------------------------------

def pct(n, total):
    return f"{(100.0 * n / total):.1f}%" if total else "0.0%"


def print_summary(a):
    t = a["total"]
    print("=" * 60)
    print("  Cracked Password Review")
    print("=" * 60)
    print(f"  Total cracked entries      : {t}")
    print(f"  Unique passwords           : {a['unique_passwords']}")
    print(f"  Reused passwords (distinct): {a['unique_reused_pw']}")
    print(f"  Accounts hit by reuse      : {a['accounts_with_reuse']} ({pct(a['accounts_with_reuse'], t)})")
    print(f"  Easily crackable           : {a['crackable_count']} ({pct(a['crackable_count'], t)})")
    print(f"  Exactly one number         : {a['one_number_count']} ({pct(a['one_number_count'], t)})")
    print(f"  Under 8 characters         : {a['under_8_count']} ({pct(a['under_8_count'], t)})")
    print("=" * 60)

    top = a["pw_counts"].most_common(10)
    if top and top[0][1] > 1:
        print("  Top reused passwords:")
        for pw, c in top:
            if c > 1:
                print(f"    {c:>5}x  {pw}")
        print("=" * 60)

    for length in (6, 7, 8):
        entries = a["top_by_length"].get(length, [])
        print(f"  Top 5 {length}-character passwords:")
        if entries:
            for pw, c in entries:
                print(f"    {c:>5}x  {pw}")
        else:
            print("    (none)")
    print("=" * 60)


def write_csv(a, base):
    # Reuse table
    reuse_path = f"{base}_reuse.csv"
    with open(reuse_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["password", "times_used"])
        for pw, c in sorted(a["reused"].items(), key=lambda kv: (-kv[1], kv[0])):
            w.writerow([pw, c])

    # Easily crackable table
    crack_path = f"{base}_crackable.csv"
    with open(crack_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["password", "reasons"])
        for pw, reasons in sorted(a["crackable"], key=lambda x: x[0]):
            w.writerow([pw, "; ".join(reasons)])

    # Summary table
    summary_path = f"{base}_summary.csv"
    t = a["total"]
    with open(summary_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["metric", "count", "percent"])
        w.writerow(["total_cracked", t, "100.0%"])
        w.writerow(["unique_passwords", a["unique_passwords"], pct(a["unique_passwords"], t)])
        w.writerow(["distinct_reused_passwords", a["unique_reused_pw"], pct(a["unique_reused_pw"], t)])
        w.writerow(["accounts_hit_by_reuse", a["accounts_with_reuse"], pct(a["accounts_with_reuse"], t)])
        w.writerow(["easily_crackable", a["crackable_count"], pct(a["crackable_count"], t)])
        w.writerow(["exactly_one_number", a["one_number_count"], pct(a["one_number_count"], t)])
        w.writerow(["under_8_chars", a["under_8_count"], pct(a["under_8_count"], t)])

    # Top 5 by length (6/7/8)
    length_path = f"{base}_top_by_length.csv"
    with open(length_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["length", "rank", "password", "times_used"])
        for length in (6, 7, 8):
            entries = a["top_by_length"].get(length, [])
            if not entries:
                w.writerow([length, "", "(none)", 0])
                continue
            for rank, (pw, c) in enumerate(entries, start=1):
                w.writerow([length, rank, pw, c])

    return [summary_path, reuse_path, crack_path, length_path]


def write_html(a, base):
    t = a["total"]
    e = html.escape

    def row(metric, n):
        return f"<tr><td>{e(metric)}</td><td class='num'>{n}</td><td class='num'>{pct(n, t)}</td></tr>"

    reuse_rows = "\n".join(
        f"<tr><td class='pw'>{e(pw)}</td><td class='num'>{c}</td></tr>"
        for pw, c in sorted(a["reused"].items(), key=lambda kv: (-kv[1], kv[0]))
    ) or "<tr><td colspan='2'>No reused passwords.</td></tr>"

    crack_rows = "\n".join(
        f"<tr><td class='pw'>{e(pw)}</td><td>{e('; '.join(r))}</td></tr>"
        for pw, r in sorted(a["crackable"], key=lambda x: x[0])
    ) or "<tr><td colspan='2'>None flagged.</td></tr>"

    length_blocks = ""
    for length in (6, 7, 8):
        entries = a["top_by_length"].get(length, [])
        rows = "\n".join(
            f"<tr><td class='num'>{rank}</td><td class='pw'>{e(pw)}</td><td class='num'>{c}</td></tr>"
            for rank, (pw, c) in enumerate(entries, start=1)
        ) or "<tr><td colspan='3'>None.</td></tr>"
        length_blocks += f"""
<h2>Top 5 {length}-Character Passwords</h2>
<table>
<tr><th>Rank</th><th>Password</th><th>Times Used</th></tr>
{rows}
</table>"""

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Cracked Password Review</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }}
  h1 {{ font-size: 1.5rem; }}
  h2 {{ font-size: 1.15rem; margin-top: 2rem; border-bottom: 2px solid #ddd; padding-bottom: .3rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: .5rem; background: #fff; }}
  th, td {{ border: 1px solid #e0e0e0; padding: .4rem .6rem; text-align: left; font-size: .9rem; }}
  th {{ background: #2b2b2b; color: #fff; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  td.pw {{ font-family: ui-monospace, Menlo, Consolas, monospace; }}
  tr:nth-child(even) {{ background: #f5f5f5; }}
  .meta {{ color: #666; font-size: .8rem; }}
</style></head><body>
<h1>Cracked Password Review</h1>
<p class="meta">Total cracked entries: {t} &nbsp;|&nbsp; Unique passwords: {a['unique_passwords']}</p>

<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Count</th><th>Percent</th></tr>
{row("Distinct reused passwords", a['unique_reused_pw'])}
{row("Accounts hit by reuse", a['accounts_with_reuse'])}
{row("Easily crackable", a['crackable_count'])}
{row("Exactly one number", a['one_number_count'])}
{row("Under 8 characters", a['under_8_count'])}
</table>

<h2>Password Reuse (used more than once)</h2>
<table>
<tr><th>Password</th><th>Times Used</th></tr>
{reuse_rows}
</table>

<h2>Easily Crackable (heuristic)</h2>
<table>
<tr><th>Password</th><th>Reasons</th></tr>
{crack_rows}
</table>
{length_blocks}
</body></html>"""

    path = f"{base}.html"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


# ---- Main -------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Review a hashcat cracked-password dump.")
    ap.add_argument("infile", help="Path to hash:password text file")
    ap.add_argument("--out", default="crack_report", help="Output basename (default: crack_report)")
    ap.add_argument("--html-only", action="store_true", help="Only write HTML")
    ap.add_argument("--csv-only", action="store_true", help="Only write CSV")
    args = ap.parse_args()

    if not os.path.isfile(args.infile):
        sys.exit(f"[!] File not found: {args.infile}")

    records, skipped = parse_file(args.infile)
    if not records:
        sys.exit("[!] No valid hash:password lines found.")

    a = analyze(records)
    print_summary(a)
    if skipped:
        print(f"  [note] skipped {skipped} line(s) with no colon.")

    written = []
    if not args.csv_only:
        written.append(write_html(a, args.out))
    if not args.html_only:
        written.extend(write_csv(a, args.out))

    print("\n  Files written:")
    for p in written:
        print(f"    {p}")


if __name__ == "__main__":
    main()

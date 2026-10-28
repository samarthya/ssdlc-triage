#!/usr/bin/env python3
"""triage.py: put CVEs into fix-by tiers using CISA KEV, FIRST EPSS and whether the service is exposed.

The idea in one line: a CVSS score says how bad a bug *could* be; KEV says it *is* being exploited, EPSS says how
*likely* exploitation is in the next 30 days, and only you know whether the service is reachable from the
internet. Those three facts decide how fast it must be fixed.

    python triage.py --exposed CVE-2021-44228 CVE-2022-3602
    python triage.py -f findings.txt --format json
    python triage.py -f - --fail-on T1 < cves.txt        # CI gate: exit 1 if anything is T0 or T1

Only the standard library is used, so it runs on any Python 3.12+ runner without `pip install`.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.request
from dataclasses import asdict, dataclass
from itertools import batched  # new in Python 3.12
from pathlib import Path

# --- Data sources -------------------------------------------------------------------------------------------
# CISA's Known Exploited Vulnerabilities catalog: CVEs with reliable evidence of exploitation in the wild.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST's Exploit Prediction Scoring System: probability (0-1) of exploitation in the next 30 days, updated daily.
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
# The EPSS API caps the query string at about 2,000 characters, so ask for CVEs in batches of 100.
EPSS_BATCH = 100

USER_AGENT = "ssdlc-triage/1.0 (+https://github.com/samarthya/ssdlc-triage)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# --- Policy -------------------------------------------------------------------------------------------------
# Tier name -> days to fix. None means "with the next planned upgrade" (no deadline of its own).
# These numbers mirror the timeboxes in the blog post; change them to match your own policy.
type Days = int | None  # `type` aliases are new in Python 3.12
DEADLINES: dict[str, Days] = {"T0": 3, "T1": 14, "T2": 30, "T3": None}
TIER_ORDER = list(DEADLINES)  # ["T0", "T1", "T2", "T3"], most urgent first

# EPSS at or above this counts as "likely to be exploited". 0.10 is a starting guess: tune it on your own data
# after a quarter (how many T1/T2 findings did it create, and how many of those were ever exploited?).
DEFAULT_EPSS_THRESHOLD = 0.10


@dataclass(frozen=True, slots=True)
class Result:
    """One triaged CVE: the facts we looked up and the tier they lead to."""

    cve: str
    kev: bool
    epss: float
    percentile: float
    exposed: bool
    tier: str
    days: Days

    @property
    def due(self) -> str:
        return f"{self.days} days" if self.days is not None else "next upgrade"


def tier(in_kev: bool, epss: float, exposed: bool, threshold: float = DEFAULT_EPSS_THRESHOLD) -> tuple[str, Days]:
    """The whole policy. Loosely modelled on CISA BOD 26-04: exploited and reachable comes first.

    Read it top to bottom; the first rule that matches wins.
    """
    likely = epss >= threshold
    if in_kev and exposed:
        return "T0", DEADLINES["T0"]  # known exploited and reachable from the internet: drop everything
    if in_kev or (exposed and likely):
        return "T1", DEADLINES["T1"]  # exploited somewhere (but not reachable), or likely and reachable
    if likely or exposed:
        return "T2", DEADLINES["T2"]  # one risk factor, not both
    return "T3", DEADLINES["T3"]  # none of the above: fix with the next planned upgrade


# --- Fetching the feeds -------------------------------------------------------------------------------------
def get_json(url: str) -> dict:
    """GET a URL and parse the JSON body. A User-Agent is set because some APIs reject Python's default one."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def load_kev(path: Path | None) -> set[str]:
    """Return the set of CVE IDs in KEV, from a local copy of the feed (air-gapped runners) or the live URL."""
    data = json.loads(path.read_text(encoding="utf-8")) if path else get_json(KEV_URL)
    return {v["cveID"] for v in data["vulnerabilities"]}


def load_epss(cves: list[str]) -> dict[str, tuple[float, float]]:
    """Return {cve: (epss, percentile)}. CVEs that EPSS has not scored yet are simply missing from the answer."""
    scores: dict[str, tuple[float, float]] = {}
    for chunk in batched(cves, EPSS_BATCH):
        for row in get_json(EPSS_URL + ",".join(chunk))["data"]:
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return scores


# --- Input and output ---------------------------------------------------------------------------------------
def read_cves(args: argparse.Namespace) -> list[str]:
    """Collect CVE IDs from the command line and/or a file ('-' is stdin), dropping blanks, comments and repeats."""
    raw = list(args.cves)
    if args.file:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")
        raw += [line.split("#", 1)[0] for line in text.splitlines()]  # allow "# comments" in the file

    cves: list[str] = []
    for item in (s.strip().upper() for s in raw):
        if not item:
            continue
        if not CVE_RE.match(item):
            sys.exit(f"triage.py: not a CVE ID: {item!r}")
        if item not in cves:  # keep the input order, but each CVE once
            cves.append(item)
    if not cves:
        sys.exit("triage.py: no CVE IDs given (pass them as arguments or with -f)")
    return cves


def print_results(results: list[Result], fmt: str) -> None:
    match fmt:
        case "json":
            print(json.dumps([asdict(r) | {"due": r.due} for r in results], indent=2))
        case "csv":
            w = csv.writer(sys.stdout)
            w.writerow(["cve", "kev", "epss", "percentile", "exposed", "tier", "due"])
            for r in results:
                w.writerow([r.cve, r.kev, f"{r.epss:.5f}", f"{r.percentile:.5f}", r.exposed, r.tier, r.due])
        case _:  # human-readable table
            for r in results:
                print(f"{r.cve:<18} kev={str(r.kev):<5} epss={r.epss:.3f}  {r.tier}  fix within {r.due}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Tier CVEs by exploitation (KEV), likelihood (EPSS) and exposure.")
    ap.add_argument("cves", nargs="*", help="CVE IDs, e.g. CVE-2021-44228")
    ap.add_argument("-f", "--file", help="read CVE IDs from a file, one per line ('-' for stdin)")
    ap.add_argument("--exposed", action="store_true", help="the service is reachable from the internet")
    ap.add_argument("--epss-threshold", type=float, default=DEFAULT_EPSS_THRESHOLD,
                    help=f"EPSS score that counts as likely (default {DEFAULT_EPSS_THRESHOLD})")
    ap.add_argument("--kev-file", type=Path, help="use a downloaded copy of the KEV JSON feed instead of the URL")
    ap.add_argument("--format", choices=["table", "json", "csv"], default="table")
    ap.add_argument("--fail-on", choices=TIER_ORDER,
                    help="exit with status 1 if any CVE is in this tier or a more urgent one (for CI gates)")
    args = ap.parse_args(argv)

    cves = read_cves(args)
    kev = load_kev(args.kev_file)
    epss = load_epss(cves)

    results = []
    for cve in cves:
        score, pct = epss.get(cve, (0.0, 0.0))  # not scored yet: treat as 0, KEV and exposure still apply
        t, days = tier(cve in kev, score, args.exposed, args.epss_threshold)
        results.append(Result(cve, cve in kev, score, pct, args.exposed, t, days))

    print_results(results, args.format)

    # CI gate: "T1" fails on T0 or T1. Compare positions in TIER_ORDER, where a lower index is more urgent.
    if args.fail_on:
        limit = TIER_ORDER.index(args.fail_on)
        if any(TIER_ORDER.index(r.tier) <= limit for r in results):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

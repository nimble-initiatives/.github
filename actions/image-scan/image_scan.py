#!/usr/bin/env python3
"""Scan release images with Trivy and judge the results against the image policy (OPS-247).

Called by .github/workflows/security-trivy-image.yml, the `Security - Trivy` job. Its steps:

  check-ignores IGNOREFILE   every exception names an id, says why (`statement`) and
                             expires (`expired_at`, at most MAX_EXCEPTION_DAYS ahead).
  scan --out DIR             runs trivy once per image and platform in $TARGETS. Writes one
                             JSON report each, plus scan-errors.json for the ones that failed.
  evaluate --reports DIR     judges every expected report, prints annotations, writes the
                             markdown summary, exits 1 if anything blocks.
  sarif --reports DIR --out DIR
                             each report as SARIF for code scanning (the daily rescan), with
                             its own category per image and platform: HIGH and CRITICAL
                             vulnerabilities, and every secret.

The policy. It blocks on:
  - a CRITICAL vulnerability with a fixed version available (a rebuild or a bump fixes it),
  - any secret Trivy finds in a layer (a token baked into the image, the G12 class),
  - an image or platform that has no report (fail closed: unscanned is not clean), or whose
    report is for another image or another platform.
HIGH findings and CRITICAL ones with no fix are counted in the summary and triaged under the
policy in docs/plans/2026-09-26-001-sec-shift-left-devsecops-plan.md §3, not blocked here.

$TARGETS is a JSON array: [{"name": "api", "image": "ghcr.io/wieldyapp/api-service@sha256:…",
"platforms": ["linux/amd64", "linux/arm64"], "aliases": ["migrate"]}]. `platforms` defaults to
both. `aliases` (optional) are other deployments of the same digest: scanned once, under `name`,
but `sarif` writes each of them its own SARIF, so every deployment keeps its own code-scanning
category (OPS-478). Every image must be pinned by digest: the point is to vouch for exactly what
gets promoted, and a tag can move.

Standard library only; YAML is read through `yq -o=json` (mikefarah yq v4, preinstalled on
GitHub's Ubuntu runners), like check-reusable-permissions.py.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys

DEFAULT_PLATFORMS = ["linux/amd64", "linux/arm64"]
PLATFORMS = set(DEFAULT_PLATFORMS)
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$")
# An exception is a decision with an owner and an end date, not a mute button (plan §3).
MAX_EXCEPTION_DAYS = 90
IGNORE_SECTIONS = ("vulnerabilities", "secrets", "misconfigurations", "licenses")
ERRORS_FILE = "scan-errors.json"
# How many blocking findings the summary lists per image. The JSON reports hold them all.
LIST_LIMIT = 15


# The only images the GITHUB_TOKEN is presented for. Registry credentials are per host, so a
# ghcr.io login would also be sent for another org's image there, and ghcr.io refuses it
# ("denied") even when the image is public. Everything else is pulled anonymously.
# nimble-initiatives/.github: the one change from wieldy's copy. The org is set by the action
# (IMAGE_SCAN_AUTH_PREFIX, default ghcr.io/nimble-initiatives/); wieldy's default stays for the tests.
AUTH_PREFIX = os.environ.get("IMAGE_SCAN_AUTH_PREFIX") or "ghcr.io/wieldyapp/"


class TargetError(ValueError):
    pass


def registry_env(image):
    """The environment for a registry call on `image`: ours keep the docker login, everything
    else gets an empty docker config, so it is pulled anonymously."""
    env = dict(os.environ)
    if not image.startswith(AUTH_PREFIX):
        anon = pathlib.Path(env.get("RUNNER_TEMP") or "/tmp") / "anonymous-docker-config"
        anon.mkdir(parents=True, exist_ok=True)
        env["DOCKER_CONFIG"] = str(anon)
    return env


def esc(msg):
    """A workflow-command message: GitHub reads %, CR and LF in it as escapes."""
    return str(msg).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def parse_targets(raw, with_aliases=False):
    """The targets as a list of (name, image, [platforms]), or with_aliases (name, image,
    [platforms], [aliases]). Raises TargetError on anything off."""
    try:
        items = json.loads(raw)
    except json.JSONDecodeError as e:
        raise TargetError(f"targets is not JSON: {e}") from e
    if not isinstance(items, list) or not items:
        raise TargetError("targets must be a non-empty JSON array")
    out, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            raise TargetError(f"target {item!r} is not an object")
        name, image = item.get("name", ""), item.get("image", "")
        platforms = item.get("platforms") or DEFAULT_PLATFORMS
        aliases = item.get("aliases") or []
        if not isinstance(aliases, list):
            raise TargetError(f"{name}: aliases {aliases!r} must be a list of names")
        for n in [name, *aliases]:
            if not isinstance(n, str) or not NAME.match(n):
                raise TargetError(f"target name {n!r} must match {NAME.pattern}")
            if n in seen:
                raise TargetError(f"target name {n!r} appears twice")
            seen.add(n)
        if not isinstance(image, str) or not IMAGE.match(image):
            raise TargetError(f"{name}: image {image!r} must be pinned by digest (repo@sha256:<64 hex>)")
        if not isinstance(platforms, list) or not all(p in PLATFORMS for p in platforms):
            raise TargetError(f"{name}: platforms {platforms!r} must be a list drawn from {sorted(PLATFORMS)}")
        platforms = list(dict.fromkeys(platforms))
        out.append((name, image, platforms, aliases) if with_aliases else (name, image, platforms))
    return out


def last_line(text):
    lines = [ln for ln in str(text or "").splitlines() if ln.strip()]
    return lines[-1] if lines else "no output"


def report_name(name, platform):
    return f"{name}__{platform.replace('/', '-')}.json"


# ── check-ignores ────────────────────────────────────────────────────────────────────────

def check_ignores(doc, today):
    """Problems with the exceptions file, as (level, message); level is 'error' or 'warning'."""
    problems = []
    if not isinstance(doc, dict):
        return [("error", "the exceptions file must be a mapping of sections")]
    for section in doc:
        if section not in IGNORE_SECTIONS:
            problems.append(("error", f"unknown section {section!r}; trivy reads {', '.join(IGNORE_SECTIONS)}"))
    horizon = today + datetime.timedelta(days=MAX_EXCEPTION_DAYS)
    for section in IGNORE_SECTIONS:
        entries = doc.get(section) or []
        if not isinstance(entries, list):
            problems.append(("error", f"{section} must be a list"))
            continue
        for i, entry in enumerate(entries):
            where = f"{section}[{i}]"
            if not isinstance(entry, dict):
                problems.append(("error", f"{where} is not a mapping"))
                continue
            rid = entry.get("id")
            if not rid:
                problems.append(("error", f"{where} has no id"))
            else:
                where = f"{section}[{i}] {rid}"
            if not str(entry.get("statement") or "").strip():
                problems.append(("error", f"{where} has no statement: say why it is accepted, who decided, and the issue that tracks it"))
            raw = entry.get("expired_at")
            if not raw:
                problems.append(("error", f"{where} has no expired_at: every exception expires (at most {MAX_EXCEPTION_DAYS} days ahead)"))
                continue
            try:
                expires = datetime.date.fromisoformat(str(raw)[:10])
            except ValueError:
                problems.append(("error", f"{where} expired_at {raw!r} is not a date (YYYY-MM-DD)"))
                continue
            if expires > horizon:
                problems.append(("error", f"{where} expires {expires}, more than {MAX_EXCEPTION_DAYS} days ahead; renew it closer to the date instead"))
            elif expires <= today:
                # Trivy stops applying it by itself, so the finding is back; only tidy-up is left.
                problems.append(("warning", f"{where} expired on {expires} and no longer applies; remove it or renew it"))
    return problems


def load_yaml(path):
    out = subprocess.run(["yq", "-o=json", ".", str(path)], check=True, capture_output=True, text=True)
    return json.loads(out.stdout or "null") or {}


def cmd_check_ignores(args):
    problems = check_ignores(load_yaml(args.ignorefile), datetime.date.today())
    for level, msg in problems:
        print(f"::{level} file={args.ignorefile}::{esc(msg)}")
    errors = sum(1 for level, _ in problems if level == "error")
    if not errors:
        print(f"✓ {args.ignorefile}: every exception has an id, a statement and an expiry")
    return 1 if errors else 0


# ── scan ─────────────────────────────────────────────────────────────────────────────────

def cmd_scan(args):
    try:
        targets = parse_targets(os.environ.get(args.targets_env, ""))
    except TargetError as e:
        print(f"::error title=Image scan targets::{esc(e)}")
        return 1
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    # Once, up front, so every image is judged against the same database.
    # The DB comes from mirror.gcr.io / ghcr.io/aquasecurity: anonymous, like any image not ours.
    subprocess.run(["trivy", "image", "--download-db-only", "--no-progress"], check=True,
                   env=registry_env("mirror.gcr.io/aquasec/trivy-db"))
    # Which DB that was goes into the summary: part of the evidence.
    version = subprocess.run(["trivy", "version", "--format", "json"], capture_output=True, text=True)
    (out / "trivy-version.json").write_text(version.stdout)
    errors = {}
    for name, image, platforms in targets:
        for platform in platforms:
            dest = out / report_name(name, platform)
            print(f"── {name} {platform}: {image}", flush=True)
            res = subprocess.run([
                "trivy", "image", "--quiet", "--no-progress",
                "--image-src", "remote", "--platform", platform,
                "--scanners", "vuln,secret",
                "--skip-db-update",
                "--ignorefile", args.ignorefile,
                "--timeout", "15m",
                "--format", "json", "--output", str(dest),
                image,
            ], capture_output=True, text=True, env=registry_env(image))
            if res.returncode != 0:
                dest.unlink(missing_ok=True)
                errors[dest.name] = (res.stderr or res.stdout).strip()[-1500:]
                print(f"::error title=Trivy failed on {name} {platform}::{esc(last_line(errors[dest.name]))}")
    (out / ERRORS_FILE).write_text(json.dumps(errors, indent=2))
    # The verdict, including on a failed scan, belongs to `evaluate`.
    return 0


# ── evaluate ─────────────────────────────────────────────────────────────────────────────

def findings(report):
    """(vulnerabilities, secrets) across every result in one Trivy JSON report."""
    vulns, found = [], []
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            vulns.append({**v, "_target": target})
        for s in result.get("Secrets") or []:
            found.append({**s, "_target": target})
    return vulns, found


def fixable(v):
    return bool((v.get("FixedVersion") or "").strip())


def judge(name, platform, image, report, scan_error):
    """One image on one platform: a dict with counts, the blocking findings and a verdict."""
    row = {"name": name, "platform": platform, "image": image, "blocking": [], "error": None,
           "critical": 0, "critical_fixable": 0, "high": 0, "high_fixable": 0, "secrets": 0}
    if report is None:
        row["error"] = scan_error or "no report: the image was not scanned"
        return row
    if report.get("ArtifactName") != image:
        row["error"] = f"the report is for {report.get('ArtifactName')!r}, not {image}"
        return row
    # A digest that is a single manifest, not an index, has no platforms to pick from: Trivy
    # ignores --platform and scans what is there. Without this check its one image would
    # also be reported under the platform it isn't built for.
    config = (report.get("Metadata") or {}).get("ImageConfig") or {}
    scanned = f"{config.get('os')}/{config.get('architecture')}"
    if scanned != platform:
        row["error"] = f"the scanned image is {scanned}, not {platform}: the digest has no {platform} image"
        return row
    vulns, found = findings(report)
    for v in vulns:
        sev = v.get("Severity")
        if sev == "CRITICAL":
            row["critical"] += 1
            if fixable(v):
                row["critical_fixable"] += 1
                row["blocking"].append(
                    f"{v.get('VulnerabilityID')} in {v.get('PkgName')} {v.get('InstalledVersion')}"
                    f" (fixed in {v.get('FixedVersion')}) [{v['_target']}]")
        elif sev == "HIGH":
            row["high"] += 1
            row["high_fixable"] += 1 if fixable(v) else 0
    for s in found:
        row["secrets"] += 1
        row["blocking"].append(
            f"secret {s.get('RuleID')} ({s.get('Severity')}) in {s['_target']}"
            f"{':' + str(s.get('StartLine')) if s.get('StartLine') else ''}")
    return row


def verdict(row):
    if row["error"]:
        return "❌ not scanned"
    return "❌ blocked" if row["blocking"] else "✅ pass"


def summary_markdown(rows, db):
    lines = ["### Image scan (Trivy)", ""]
    if db:
        lines += [f"Vulnerability DB built {db}. Blocks on fixable critical vulnerabilities and on any secret in a layer (OPS-247).", ""]
    lines += ["| Image | Platform | Critical (fixable) | High (fixable) | Secrets | Result |",
              "|---|---|---|---|---|---|"]
    for r in rows:
        if r["error"]:
            lines.append(f"| {r['name']} | {r['platform']} | – | – | – | {verdict(r)} |")
        else:
            lines.append(f"| {r['name']} | {r['platform']} | {r['critical']} ({r['critical_fixable']})"
                         f" | {r['high']} ({r['high_fixable']}) | {r['secrets']} | {verdict(r)} |")
    bad = [r for r in rows if r["error"] or r["blocking"]]
    for r in bad:
        lines += ["", f"**{r['name']} {r['platform']}** `{r['image']}`", ""]
        if r["error"]:
            lines.append(f"- {last_line(r['error'])}")
        for b in r["blocking"][:LIST_LIMIT]:
            lines.append(f"- {b}")
        if len(r["blocking"]) > LIST_LIMIT:
            lines.append(f"- …and {len(r['blocking']) - LIST_LIMIT} more in the `trivy-reports` artifact")
    if bad:
        lines += ["", "Rebuild to pick up a patched base image, bump the package, or, if neither is possible yet, "
                  "add an exception with a statement and an expiry to `.github/trivy/ignore.yaml`."]
    return "\n".join(lines) + "\n"


def evaluate(targets, reports_dir):
    reports_dir = pathlib.Path(reports_dir)
    errors_path = reports_dir / ERRORS_FILE
    errors = json.loads(errors_path.read_text()) if errors_path.exists() else {}
    rows, db = [], None
    for name, image, platforms in targets:
        for platform in platforms:
            fname = report_name(name, platform)
            path = reports_dir / fname
            report = None
            if path.exists():
                try:
                    report = json.loads(path.read_text())
                except json.JSONDecodeError as e:
                    errors[fname] = f"the report is not JSON: {e}"
            rows.append(judge(name, platform, image, report, errors.get(fname)))
    return rows


def db_built(reports_dir):
    """When the vulnerability DB the scan used was built, from `trivy version --format json`."""
    path = pathlib.Path(reports_dir) / "trivy-version.json"
    try:
        return json.loads(path.read_text())["VulnerabilityDB"]["UpdatedAt"][:16].replace("T", " ") + " UTC"
    except (OSError, ValueError, KeyError, TypeError):
        return None


def write_output(key, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    delim = f"EOF_{secrets.token_hex(8)}"
    with open(path, "a") as f:
        f.write(f"{key}<<{delim}\n{value}{delim}\n")


def cmd_evaluate(args):
    try:
        targets = parse_targets(os.environ.get(args.targets_env, ""))
    except TargetError as e:
        print(f"::error title=Image scan targets::{esc(e)}")
        return 1
    rows = evaluate(targets, args.reports)
    md = summary_markdown(rows, db_built(args.reports))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(md)
    write_output("summary", md)
    failed = 0
    for r in rows:
        if r["error"]:
            print(f"::error title=Not scanned: {r['name']} {r['platform']}::{esc(last_line(r['error']))}")
            failed += 1
        elif r["blocking"]:
            for b in r["blocking"][:LIST_LIMIT]:
                print(f"::error title=Blocked: {r['name']} {r['platform']}::{esc(b)}")
            failed += 1
        else:
            print(f"✓ {r['name']} {r['platform']}: no fixable critical, no secrets "
                  f"({r['critical']} critical, {r['high']} high to triage)")
    print(md)
    return 1 if failed else 0


# ── sarif ────────────────────────────────────────────────────────────────────────────────

def sarif_category(name, platform):
    """The code-scanning category of one image on one platform. It names the deployment, not
    the digest, so the next upload for it replaces the last one: an alert the new image no
    longer has is closed, and one it still has stays the same alert."""
    return f"trivy-image/{name}/{platform.replace('/', '-')}/"


# What code scanning gets (decided 2026-11-11): vulnerabilities at HIGH and CRITICAL, and every
# secret whatever trivy rates it (the policy blocks any secret; the first one was MEDIUM).
# Medium and low vulnerabilities stay in the JSON reports, in the run's artifact.
SARIF_SEVERITIES = {"HIGH", "CRITICAL"}


def keep_result(rule):
    tags = set((rule or {}).get("properties", {}).get("tags") or [])
    return "vulnerability" not in tags or bool(tags & SARIF_SEVERITIES)


def trim(sarif):
    """Drop the results code scanning doesn't get. Rules stay, so every ruleIndex still holds."""
    for run in sarif.get("runs") or []:
        rules = (run.get("tool") or {}).get("driver", {}).get("rules") or []
        by_id = {r.get("id"): r for r in rules}
        run["results"] = [
            r for r in run.get("results") or []
            if keep_result(rules[r["ruleIndex"]] if isinstance(r.get("ruleIndex"), int) and r["ruleIndex"] < len(rules)
                           else by_id.get(r.get("ruleId")))
        ]
    return sarif


def categorize(sarif, category):
    """Every run in a SARIF log, tagged with the category (runAutomationDetails.id)."""
    for run in sarif.get("runs") or []:
        run["automationDetails"] = {"id": category}
    return sarif


def cmd_sarif(args):
    try:
        targets = parse_targets(os.environ.get(args.targets_env, ""), with_aliases=True)
    except TargetError as e:
        print(f"::error title=Image scan targets::{esc(e)}")
        return 1
    reports, out = pathlib.Path(args.reports), pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    failed = 0
    for name, _image, platforms, aliases in targets:
        for platform in platforms:
            report = reports / report_name(name, platform)
            if not report.exists():
                # Not scanned: `evaluate` has failed the job for it. Its category keeps the
                # last upload's alerts rather than closing them on no evidence.
                print(f"· {name} {platform}: no report, no SARIF")
                continue
            dest = out / report.name.replace(".json", ".sarif")
            res = subprocess.run(["trivy", "convert", "--quiet", "--format", "sarif",
                                  "--output", str(dest), str(report)], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"::error title=SARIF for {name} {platform}::{esc(last_line(res.stderr or res.stdout))}")
                failed += 1
                continue
            log = trim(json.loads(dest.read_text()))
            # One SARIF per deployment, not per digest (OPS-478): a deployment that shares its
            # digest with another still uploads to its own category every day. Otherwise its
            # category goes quiet as soon as the digests converge, and the alerts it gathered
            # while they differed never close.
            for n in [name, *aliases]:
                f = out / report_name(n, platform).replace(".json", ".sarif")
                f.write_text(json.dumps(categorize(log, sarif_category(n, platform))))
                print(f"✓ {n} {platform}: {f.name}" + (f" (same image as {name})" if n != name else ""))
    return 1 if failed else 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check-ignores")
    c.add_argument("ignorefile")
    s = sub.add_parser("scan")
    s.add_argument("--targets-env", default="TARGETS")
    s.add_argument("--ignorefile", required=True)
    s.add_argument("--out", required=True)
    e = sub.add_parser("evaluate")
    e.add_argument("--targets-env", default="TARGETS")
    e.add_argument("--reports", required=True)
    f = sub.add_parser("sarif")
    f.add_argument("--targets-env", default="TARGETS")
    f.add_argument("--reports", required=True)
    f.add_argument("--out", required=True)
    args = p.parse_args(argv)
    return {"check-ignores": cmd_check_ignores, "scan": cmd_scan, "evaluate": cmd_evaluate,
            "sarif": cmd_sarif}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

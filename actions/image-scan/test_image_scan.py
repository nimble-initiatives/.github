"""Unit tests for image_scan.py. Run: python3 -m unittest discover -s .github/ci/image-scan"""

import datetime
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import image_scan as s

DIGEST = "sha256:" + "a" * 64
API = f"ghcr.io/wieldyapp/api-service@{DIGEST}"
TODAY = datetime.date(2026, 11, 11)


def targets(*items):
    return json.dumps(list(items))


def vuln(vid="CVE-2026-0001", sev="CRITICAL", fixed="1.2.4"):
    return {"VulnerabilityID": vid, "PkgName": "openssl", "InstalledVersion": "1.2.3",
            "FixedVersion": fixed, "Severity": sev}


def report(image=API, vulns=(), found=(), platform="linux/amd64"):
    os_, arch = platform.split("/")
    return {"ArtifactName": image, "Metadata": {"ImageConfig": {"os": os_, "architecture": arch}}, "Results": [
        {"Target": "image (alpine 3.22)", "Vulnerabilities": list(vulns)},
        {"Target": "/app/appsettings.json", "Secrets": list(found)},
    ]}


class ParseTargetsTests(unittest.TestCase):
    def test_defaults_to_both_platforms(self):
        self.assertEqual(s.parse_targets(targets({"name": "api", "image": API})),
                         [("api", API, ["linux/amd64", "linux/arm64"])])

    def test_aliases_only_when_asked(self):
        raw = targets({"name": "obs-kc", "image": API, "aliases": ["primary-kc", "spike-kc"]})
        self.assertEqual(s.parse_targets(raw), [("obs-kc", API, ["linux/amd64", "linux/arm64"])])
        self.assertEqual(s.parse_targets(raw, with_aliases=True)[0][3], ["primary-kc", "spike-kc"])
        self.assertEqual(s.parse_targets(targets({"name": "api", "image": API}), with_aliases=True)[0][3], [])

    def test_keeps_given_platforms(self):
        got = s.parse_targets(targets({"name": "imgproxy", "image": API, "platforms": ["linux/amd64"]}))
        self.assertEqual(got[0][2], ["linux/amd64"])

    def test_rejects(self):
        bad = {
            "a tag, not a digest": targets({"name": "api", "image": "ghcr.io/wieldyapp/api-service:v1"}),
            "a short digest": targets({"name": "api", "image": "ghcr.io/x@sha256:abc"}),
            "an empty list": "[]",
            "not JSON": "api",
            "a duplicate name": targets({"name": "api", "image": API}, {"name": "api", "image": API}),
            "an unknown platform": targets({"name": "api", "image": API, "platforms": ["linux/s390x"]}),
            "a name with a slash": targets({"name": "a/b", "image": API}),
            "an alias that is another target's name": targets({"name": "api", "image": API, "aliases": ["app"]},
                                                              {"name": "app", "image": API}),
            "an alias of itself": targets({"name": "api", "image": API, "aliases": ["api"]}),
            "an alias with a slash": targets({"name": "api", "image": API, "aliases": ["a/b"]}),
            "aliases not a list": targets({"name": "api", "image": API, "aliases": "app"}),
            # An empty digest is what a skipped build's output looks like.
            "an empty digest": targets({"name": "api", "image": "ghcr.io/wieldyapp/api-service@"}),
        }
        for why, raw in bad.items():
            with self.subTest(why), self.assertRaises(s.TargetError):
                s.parse_targets(raw)


class CheckIgnoresTests(unittest.TestCase):
    def entry(self, **over):
        e = {"id": "CVE-2026-0001", "statement": "Not reachable; OPS-1", "expired_at": "2026-12-01"}
        e.update(over)
        return {k: v for k, v in e.items() if v is not None}

    def errors(self, doc):
        return [m for level, m in s.check_ignores(doc, TODAY) if level == "error"]

    def test_empty_file_is_fine(self):
        self.assertEqual(s.check_ignores({"vulnerabilities": [], "secrets": []}, TODAY), [])
        self.assertEqual(s.check_ignores({}, TODAY), [])

    def test_complete_entry_is_fine(self):
        self.assertEqual(s.check_ignores({"vulnerabilities": [self.entry()]}, TODAY), [])

    def test_needs_statement_and_expiry_and_id(self):
        for field in ("statement", "expired_at", "id"):
            with self.subTest(field):
                self.assertTrue(self.errors({"secrets": [self.entry(**{field: None})]}))
        self.assertTrue(self.errors({"vulnerabilities": [self.entry(statement="  ")]}))

    def test_expiry_horizon(self):
        self.assertEqual(self.errors({"vulnerabilities": [self.entry(expired_at="2027-02-09")]}), [])  # day 90
        self.assertTrue(self.errors({"vulnerabilities": [self.entry(expired_at="2027-02-10")]}))      # day 91
        self.assertTrue(self.errors({"vulnerabilities": [self.entry(expired_at="soon")]}))

    def test_expired_entry_is_only_a_warning(self):
        problems = s.check_ignores({"vulnerabilities": [self.entry(expired_at="2026-11-11")]}, TODAY)
        self.assertEqual([level for level, _ in problems], ["warning"])

    def test_yq_timestamp_form_is_read(self):
        self.assertEqual(s.check_ignores({"vulnerabilities": [self.entry(expired_at="2026-12-01T00:00:00Z")]}, TODAY), [])

    def test_unknown_section_and_bad_shapes(self):
        self.assertTrue(self.errors({"vulns": []}))
        self.assertTrue(self.errors({"vulnerabilities": {"id": "x"}}))
        self.assertTrue(self.errors({"vulnerabilities": ["CVE-2026-0001"]}))
        self.assertTrue(self.errors(["CVE-2026-0001"]))


class JudgeTests(unittest.TestCase):
    def test_fixable_critical_blocks(self):
        row = s.judge("api", "linux/amd64", API, report(vulns=[vuln()]), None)
        self.assertEqual(row["critical_fixable"], 1)
        self.assertIn("CVE-2026-0001 in openssl 1.2.3 (fixed in 1.2.4)", row["blocking"][0])
        self.assertEqual(s.verdict(row), "❌ blocked")

    def test_unfixed_critical_and_highs_only_count(self):
        row = s.judge("api", "linux/amd64", API,
                      report(vulns=[vuln(fixed=""), vuln(sev="HIGH"), vuln(sev="HIGH", fixed=None), vuln(sev="MEDIUM")]), None)
        self.assertEqual((row["critical"], row["critical_fixable"], row["high"], row["high_fixable"]), (1, 0, 2, 1))
        self.assertEqual(row["blocking"], [])
        self.assertEqual(s.verdict(row), "✅ pass")

    def test_any_secret_blocks(self):
        row = s.judge("api", "linux/amd64", API,
                      report(found=[{"RuleID": "github-pat", "Severity": "CRITICAL", "StartLine": 3}]), None)
        self.assertEqual(row["secrets"], 1)
        self.assertEqual(row["blocking"], ["secret github-pat (CRITICAL) in /app/appsettings.json:3"])

    def test_missing_report_fails_closed(self):
        row = s.judge("api", "linux/arm64", API, None, None)
        self.assertEqual(s.verdict(row), "❌ not scanned")
        row = s.judge("api", "linux/arm64", API, None, "FATAL no matching manifest for linux/arm64")
        self.assertIn("linux/arm64", row["error"])

    def test_report_for_another_image_fails(self):
        other = "ghcr.io/wieldyapp/app-service@" + DIGEST
        self.assertEqual(s.verdict(s.judge("api", "linux/amd64", API, report(image=other), None)), "❌ not scanned")

    def test_null_results_are_clean(self):
        row = s.judge("api", "linux/amd64", API, {**report(), "Results": None}, None)
        self.assertEqual(s.verdict(row), "✅ pass")

    def test_single_platform_digest_is_not_vouched_for_the_other(self):
        # A single-manifest digest: trivy ignores --platform and scans the amd64 image.
        row = s.judge("api", "linux/arm64", API, report(platform="linux/amd64"), None)
        self.assertEqual(s.verdict(row), "❌ not scanned")
        self.assertIn("is linux/amd64, not linux/arm64", row["error"])
        self.assertEqual(s.verdict(s.judge("api", "linux/arm64", API, report(platform="linux/arm64"), None)), "✅ pass")

    def test_report_without_image_config_fails_closed(self):
        row = s.judge("api", "linux/amd64", API, {"ArtifactName": API, "Results": []}, None)
        self.assertEqual(s.verdict(row), "❌ not scanned")


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = pathlib.Path(self.dir.name)

    def write(self, name, platform, body):
        (self.path / s.report_name(name, platform)).write_text(json.dumps(body))

    def run_cmd(self, raw_targets):
        out = self.path / "out.txt"
        summary = self.path / "summary.md"
        env = {"TARGETS": raw_targets, "GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary)}
        with mock.patch.dict(os.environ, env), mock.patch("builtins.print"):
            code = s.main(["evaluate", "--reports", str(self.path)])
        return code, out.read_text() if out.exists() else "", summary.read_text() if summary.exists() else ""

    def test_all_clean_passes_and_writes_summary(self):
        self.write("api", "linux/amd64", report(vulns=[vuln(sev="HIGH")]))
        self.write("api", "linux/arm64", report(platform="linux/arm64"))
        (self.path / "trivy-version.json").write_text(json.dumps({"VulnerabilityDB": {"UpdatedAt": "2026-11-11T06:21:30.5Z"}}))
        code, out, summary = self.run_cmd(targets({"name": "api", "image": API}))
        self.assertEqual(code, 0)
        self.assertIn("| api | linux/amd64 | 0 (0) | 1 (1) | 0 | ✅ pass |", summary)
        self.assertIn("2026-11-11 06:21 UTC", summary)
        self.assertTrue(out.startswith("summary<<EOF_"))

    def test_one_missing_platform_fails(self):
        self.write("api", "linux/amd64", report())
        code, _, summary = self.run_cmd(targets({"name": "api", "image": API}))
        self.assertEqual(code, 1)
        self.assertIn("| api | linux/arm64 | – | – | – | ❌ not scanned |", summary)

    def test_scan_error_is_reported(self):
        self.write("api", "linux/amd64", report())
        (self.path / s.ERRORS_FILE).write_text(json.dumps({s.report_name("api", "linux/arm64"): "boom\nFATAL unauthorized\n"}))
        code, _, summary = self.run_cmd(targets({"name": "api", "image": API}))
        self.assertEqual(code, 1)
        self.assertIn("- FATAL unauthorized", summary)

    def test_corrupt_report_fails(self):
        (self.path / s.report_name("api", "linux/amd64")).write_text("{not json")
        code, _, _ = self.run_cmd(targets({"name": "api", "image": API, "platforms": ["linux/amd64"]}))
        self.assertEqual(code, 1)

    def test_blocking_list_is_capped(self):
        self.write("api", "linux/amd64", report(vulns=[vuln(vid=f"CVE-2026-{i:04}") for i in range(20)]))
        code, _, summary = self.run_cmd(targets({"name": "api", "image": API, "platforms": ["linux/amd64"]}))
        self.assertEqual(code, 1)
        self.assertIn("…and 5 more", summary)

    def test_bad_targets_fail(self):
        code, _, _ = self.run_cmd(targets({"name": "api", "image": "ghcr.io/wieldyapp/api-service:latest"}))
        self.assertEqual(code, 1)


class RegistryEnvTests(unittest.TestCase):
    def test_only_our_images_keep_the_login(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"DOCKER_CONFIG": "/login", "RUNNER_TEMP": d}):
            self.assertEqual(s.registry_env(API)["DOCKER_CONFIG"], "/login")
            for other in ("ghcr.io/nimble-initiatives/strife-marketing@" + DIGEST, "ghcr.io/wieldyapp-evil/x@" + DIGEST,
                          "nats@" + DIGEST, "mirror.gcr.io/aquasec/trivy-db"):
                with self.subTest(other):
                    anon = s.registry_env(other)["DOCKER_CONFIG"]
                    self.assertNotEqual(anon, "/login")
                    self.assertEqual(os.listdir(anon), [])


class SarifTests(unittest.TestCase):
    def test_category_names_the_deployment(self):
        self.assertEqual(s.sarif_category("master-build-api", "linux/arm64"), "trivy-image/master-build-api/linux-arm64/")

    def test_every_run_is_categorized(self):
        log = s.categorize({"runs": [{"tool": {}}, {"tool": {}}]}, "trivy-image/api/linux-amd64/")
        self.assertEqual([r["automationDetails"]["id"] for r in log["runs"]], ["trivy-image/api/linux-amd64/"] * 2)

    def test_trim_keeps_high_critical_and_every_secret(self):
        rules = [{"id": "CVE-1", "properties": {"tags": ["vulnerability", "security", "HIGH"]}},
                 {"id": "CVE-2", "properties": {"tags": ["vulnerability", "security", "MEDIUM"]}},
                 {"id": "CVE-3", "properties": {"tags": ["vulnerability", "security", "CRITICAL"]}},
                 {"id": "jwt-token", "properties": {"tags": ["secret", "security", "MEDIUM"]}},
                 {"id": "CVE-4", "properties": {"tags": ["vulnerability", "security", "LOW"]}}]
        results = [{"ruleId": r["id"], "ruleIndex": i} for i, r in enumerate(rules)]
        log = s.trim({"runs": [{"tool": {"driver": {"rules": rules}}, "results": results}]})
        self.assertEqual([r["ruleId"] for r in log["runs"][0]["results"]], ["CVE-1", "CVE-3", "jwt-token"])
        self.assertEqual(len(log["runs"][0]["tool"]["driver"]["rules"]), 5)  # ruleIndex stays valid

    def test_converts_present_reports_only(self):
        with tempfile.TemporaryDirectory() as d:
            reports, out = pathlib.Path(d) / "r", pathlib.Path(d) / "s"
            reports.mkdir()
            (reports / s.report_name("api", "linux/amd64")).write_text("{}")

            def fake_trivy(cmd, **kw):
                pathlib.Path(cmd[cmd.index("--output") + 1]).write_text(json.dumps({"runs": [{"tool": {}}]}))
                return mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch.dict(os.environ, {"TARGETS": targets({"name": "api", "image": API})}), \
                    mock.patch.object(s.subprocess, "run", fake_trivy), mock.patch("builtins.print"):
                code = s.main(["sarif", "--reports", str(reports), "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertEqual([f.name for f in out.iterdir()], ["api__linux-amd64.sarif"])  # arm64 had no report
            log = json.loads((out / "api__linux-amd64.sarif").read_text())
            self.assertEqual(log["runs"][0]["automationDetails"]["id"], "trivy-image/api/linux-amd64/")


    def test_every_alias_gets_its_own_sarif(self):
        # OPS-478: one scan per digest, one SARIF per deployment, so each keeps its category.
        with tempfile.TemporaryDirectory() as d:
            reports, out = pathlib.Path(d) / "r", pathlib.Path(d) / "s"
            reports.mkdir()
            (reports / s.report_name("obs-kc", "linux/amd64")).write_text("{}")
            converted = []

            def fake_trivy(cmd, **kw):
                converted.append(cmd[-1])
                pathlib.Path(cmd[cmd.index("--output") + 1]).write_text(json.dumps({"runs": [{"tool": {}}]}))
                return mock.Mock(returncode=0, stdout="", stderr="")
            raw = targets({"name": "obs-kc", "image": API, "platforms": ["linux/amd64"], "aliases": ["primary-kc"]})
            with mock.patch.dict(os.environ, {"TARGETS": raw}), \
                    mock.patch.object(s.subprocess, "run", fake_trivy), mock.patch("builtins.print"):
                code = s.main(["sarif", "--reports", str(reports), "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertEqual(len(converted), 1)  # converted once
            self.assertEqual(sorted(f.name for f in out.iterdir()),
                             ["obs-kc__linux-amd64.sarif", "primary-kc__linux-amd64.sarif"])
            cats = {f.name: json.loads(f.read_text())["runs"][0]["automationDetails"]["id"] for f in out.iterdir()}
            self.assertEqual(cats, {"obs-kc__linux-amd64.sarif": "trivy-image/obs-kc/linux-amd64/",
                                    "primary-kc__linux-amd64.sarif": "trivy-image/primary-kc/linux-amd64/"})


class EscapeTests(unittest.TestCase):
    def test_workflow_command_escapes(self):
        self.assertEqual(s.esc("50%\nnext\r"), "50%25%0Anext%0D")


if __name__ == "__main__":
    unittest.main()

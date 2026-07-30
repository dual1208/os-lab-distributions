#!/usr/bin/env python3
"""Regression tests for fail-closed shell producer/consumer boundaries."""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    "install-edge-lab.sh",
    "qualify-a11-b22.sh",
    "soak-a11-b22.sh",
    "test-edge-recovery.sh",
    "topology.sh",
)


def bash_path() -> str | None:
    found = shutil.which("bash")
    if found is not None:
        return found
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    return str(git_bash) if git_bash.is_file() else None


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


class RemainingProducerStatusTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (ROOT / "scripts" / name).read_text(encoding="utf-8")

    def run_bash(self, program: str) -> subprocess.CompletedProcess[str]:
        bash = bash_path()
        if bash is None:
            self.skipTest("bash is unavailable")
        return subprocess.run(
            [bash, "-c", program],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_bash_ok(self, program: str) -> None:
        completed = self.run_bash(program)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_named_scripts_have_no_direct_or_process_substitution_predicates(self):
        for name in SCRIPTS:
            source = self.read(name)
            with self.subTest(name=name):
                self.assertIsNone(re.search(r"\[\[\s*\$\(", source))
                self.assertIsNone(re.search(r"\(\(\s*\$\(", source))
                self.assertNotIn("< <(", source)
        topology = self.read("topology.sh")
        self.assertNotIn("wan=$(wan_device || true)", topology)
        self.assertNotRegex(topology, r"!\s+ip netns list\s*\|")
        for name in ("qualify-a11-b22.sh", "soak-a11-b22.sh", "test-edge-recovery.sh"):
            self.assertNotIn(
                'SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"',
                self.read(name),
            )

    def test_matching_capture_rejects_valid_output_then_failure(self):
        source = self.read("qualify-a11-b22.sh")
        function = shell_function(source, "command_output_matches")
        self.assert_bash_ok(
            f'''set -euo pipefail
{function}
producer() {{ printf 'prefix expected suffix\\n'; return "${{PRODUCER_STATUS}}"; }}
PRODUCER_STATUS=73
if command_output_matches expected producer; then exit 90; fi
PRODUCER_STATUS=0
command_output_matches expected producer
'''
        )

    def test_wan_capture_and_expected_unreachable_status_are_exact(self):
        source = self.read("topology.sh")
        functions = "\n".join(
            shell_function(source, name)
            for name in ("wan_device", "assert_route_lookup_unreachable")
        )
        self.assert_bash_ok(
            f'''set -euo pipefail
{functions}
ip() {{
  if [[ ${{IP_MODE}} == route-list ]]; then
    printf 'default via 192.0.2.1 dev eth0 proto static\\n'
  else
    printf 'RTNETLINK answers: Network is unreachable\\n'
  fi
  return "${{IP_STATUS}}"
}}
IP_MODE=route-list
IP_STATUS=73
if wan_device >/dev/null; then exit 91; fi
IP_STATUS=0
[[ $(wan_device) == eth0 ]]
IP_MODE=route-get
IP_STATUS=73
if assert_route_lookup_unreachable ns 192.0.2.1; then exit 92; fi
IP_STATUS=2
assert_route_lookup_unreachable ns 192.0.2.1
'''
        )

    def test_legacy_stat_wc_and_digest_helpers_reject_partial_success(self):
        source = self.read("install-edge-lab.sh")
        functions = "\n".join(
            shell_function(source, name)
            for name in (
                "checked_stat_equals",
                "checked_line_count",
                "checked_line_count_equals",
                "checked_sha256",
            )
        )
        self.assert_bash_ok(
            f'''set -euo pipefail
{functions}
work=$(mktemp)
trap 'rm -f -- "${{work}}"' EXIT
printf 'line\\n' > "${{work}}"
stat() {{ printf '0:0:600\\n'; return "${{FAKE_STATUS}}"; }}
wc() {{ printf '1\\n'; return "${{FAKE_STATUS}}"; }}
sha256sum() {{ printf '%064d  ignored\\n' 0; return "${{FAKE_STATUS}}"; }}
FAKE_STATUS=73
if checked_stat_equals 0:0:600 ignored; then exit 93; fi
if checked_line_count_equals 1 "${{work}}"; then exit 94; fi
digest=unchanged
if checked_sha256 digest "${{work}}"; then exit 95; fi
[[ ${{digest}} == unchanged ]]
FAKE_STATUS=0
checked_stat_equals 0:0:600 ignored
checked_line_count_equals 1 "${{work}}"
checked_sha256 digest "${{work}}"
[[ ${{digest}} =~ ^[a-f0-9]{{64}}$ ]]
'''
        )

    def test_negated_file_and_systemd_checks_distinguish_errors(self):
        source = self.read("install-edge-lab.sh")
        functions = "\n".join(
            shell_function(source, name)
            for name in ("file_lacks_pattern", "assert_unit_not_active")
        )
        self.assert_bash_ok(
            f'''set -euo pipefail
{functions}
grep() {{ return "${{GREP_STATUS}}"; }}
systemctl() {{ return "${{SYSTEMCTL_STATUS}}"; }}
GREP_STATUS=73
if file_lacks_pattern F forbidden ignored; then exit 96; fi
GREP_STATUS=1
file_lacks_pattern F forbidden ignored
GREP_STATUS=0
if file_lacks_pattern F forbidden ignored; then exit 97; fi
SYSTEMCTL_STATUS=1
if assert_unit_not_active unit; then exit 98; fi
SYSTEMCTL_STATUS=3
assert_unit_not_active unit
SYSTEMCTL_STATUS=4
assert_unit_not_active unit
SYSTEMCTL_STATUS=0
if assert_unit_not_active unit; then exit 99; fi
'''
        )

    def test_checked_digest_pipelines_reject_valid_output_then_failure(self):
        soak = self.read("soak-a11-b22.sh")
        recovery = self.read("test-edge-recovery.sh")
        self.assertRegex(
            soak,
            r"prerequisite_sha256=\$\(sha256sum .*?\| awk .*?\) \|\| exit 1",
        )
        self.assertRegex(
            recovery,
            r"stream_transcript_sha256=\$\(sha256sum .*?\| awk .*?\) \|\| exit 1",
        )
        self.assert_bash_ok(
            '''set -euo pipefail
sha256sum() { printf '%064d  ignored\n' 0; return 73; }
if digest=$(sha256sum ignored | awk '{print $1}'); then exit 100; fi
'''
        )

    def test_recovery_loop_and_log_producers_are_explicitly_checked(self):
        source = self.read("test-edge-recovery.sh")
        self.assertIn(
            'listener_output=$(ip netns exec oslab-b ss -H -ltn "sport = :${STREAM_PORT}") || return 1',
            source,
        )
        self.assertIn('link=$(readlink -- "${descriptor}" 2>/dev/null) || return 1', source)
        self.assertIn('client_log_lines=$(wc -l < "${TRIAL_CLIENT_LOG}") || return 1', source)
        self.assertNotIn("for trial in $(seq", source)


if __name__ == "__main__":
    unittest.main()

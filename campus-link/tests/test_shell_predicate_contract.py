#!/usr/bin/env python3
"""Fail-closed producer/consumer contracts for production shell gates."""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    "accelerated-fault-soak.sh",
    "certificate-rotation-gate.sh",
    "fault-in-stream.sh",
    "nat-rebinding-gate.sh",
    "relay-restart-driver.sh",
    "relay-restart-permit-authorize.sh",
    "relay-restart-actuator.sh",
    "relay-restart-transport.sh",
    "qualification-chain.sh",
    "gate-evidence.sh",
)


def bash_path() -> str | None:
    bash = shutil.which("bash")
    if bash is not None:
        return bash
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    return str(git_bash) if git_bash.is_file() else None


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


class ShellPredicateContractTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (ROOT / "scripts" / name).read_text(encoding="utf-8")

    def run_bash(self, program: str) -> subprocess.CompletedProcess[str]:
        bash = bash_path()
        if bash is None:
            self.skipTest("bash is unavailable")
        return subprocess.run(
            [bash, "-c", program, "--", str(ROOT)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_qualification_predicates_do_not_mask_command_status(self):
        direct_test = re.compile(r"\[\[\s*\$\(")
        direct_arithmetic = re.compile(r"\(\(\s*\$\(")
        direct_digest = re.compile(r"\[\[\s*\$\(sha256sum")
        for name in SCRIPTS:
            with self.subTest(name=name):
                source = self.read(name)
                self.assertIsNone(direct_test.search(source))
                self.assertIsNone(direct_arithmetic.search(source))
                self.assertIsNone(direct_digest.search(source))

    def test_every_remaining_process_substitution_waits_for_its_producer(self):
        expected = {
            "nat-rebinding-gate.sh": (("collect_complete_lines()", "producer_pid=$!"),),
            "relay-restart-driver.sh": (("sanitize_environment()", "producer_pid=$!"),),
            "relay-restart-permit-authorize.sh": (
                ("sanitize_environment()", "producer_pid=$!"),
                ("validate_used_ledger()", "find_pid=$!"),
            ),
            "relay-restart-actuator.sh": (
                ("sanitize_environment()", "producer_pid=$!"),
                ("validate_used_ledger()", "find_pid=$!"),
                ("assert_manifest_bound_start_inhibit()", "grep_pid=$!"),
            ),
        }
        for name in SCRIPTS:
            source = self.read(name)
            substitutions = source.count("< <(")
            contracts = expected.get(name, ())
            with self.subTest(name=name):
                self.assertEqual(substitutions, len(contracts))
                for function, waiter in contracts:
                    start = source.index(function)
                    end = source.index("\n}\n", start)
                    body = source[start:end]
                    self.assertIn(waiter, body)
                    self.assertRegex(body, r'wait "\$\{[a-z_]+\}"')
                self.assertNotIn("|| true)", source)

    def test_marker_predicate_rejects_valid_output_followed_by_failure(self):
        helper = (ROOT / "scripts" / "gate-evidence.sh").as_posix()
        program = rf'''set -euo pipefail
source "{helper}"
campus_link_marker_value() {{ printf 'expected'; return 73; }}
if campus_link_marker_equals ignored KEY expected; then
  exit 90
fi
campus_link_marker_value() {{ printf 'expected'; return 0; }}
campus_link_marker_equals ignored KEY expected
'''
        completed = self.run_bash(program)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_marker_reader_bounds_and_completely_consumes_regular_input(self):
        helper = (ROOT / "scripts" / "gate-evidence.sh").as_posix()
        program = rf'''set -euo pipefail
source "{helper}"
work=$(mktemp -d)
trap 'rm -rf -- "${{work}}"' EXIT
printf 'FORMAT=1\n' > "${{work}}/exact"
[[ $(campus_link_marker_value "${{work}}/exact" FORMAT) == 1 ]]
printf 'FORMAT=1' > "${{work}}/truncated"
! campus_link_marker_value "${{work}}/truncated" FORMAT >/dev/null
ln -s exact "${{work}}/linked"
! campus_link_marker_value "${{work}}/linked" FORMAT >/dev/null
head -c 65537 /dev/zero | tr '\0' x > "${{work}}/oversized"
! campus_link_marker_value "${{work}}/oversized" FORMAT >/dev/null
stat() {{ command stat "$@"; return 71; }}
! campus_link_marker_value "${{work}}/exact" FORMAT >/dev/null
'''
        completed = self.run_bash(program)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_sorted_inventory_rejects_valid_prefix_from_failed_sort(self):
        helper = (ROOT / "scripts" / "gate-evidence.sh").as_posix()
        program = rf'''set -euo pipefail
source "{helper}"
sort() {{ printf 'alpha\n'; return 72; }}
result=()
if campus_link_sort_unique_array result alpha; then
  exit 91
fi
'''
        completed = self.run_bash(program)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_fault_stream_consumers_check_memory_rate_and_digest_producers(self):
        source = self.read("fault-in-stream.sh")
        self.assertIn(
            'mapfile -t memory_peak_lines < "${memory_peak_source}" || exit 1',
            source,
        )
        self.assertRegex(
            source,
            re.compile(r"a_to_b_rate=\$\(sed .*?\) \|\| exit 1", re.DOTALL),
        )
        self.assertRegex(
            source,
            re.compile(r"b_to_a_rate=\$\(sed .*?\) \|\| exit 1", re.DOTALL),
        )
        self.assertIn("current_prerequisite_sha256=$(sha256sum", source)
        self.assertIn(') || exit 1\n[[ ${current_prerequisite_sha256}', source)

    def test_edge_identity_inventory_rejects_valid_output_then_failure(self):
        source = self.read("install-edge-lab.sh")
        function = shell_function(source, "assert_identity_lacks_group")
        program = f'''set -euo pipefail
id() {{
  [[ $1 == -G && $# == 2 ]] || return 99
  printf '%b' "${{ID_OUTPUT}}"
  return "${{ID_STATUS}}"
}}
{function}
ID_OUTPUT='100 200\n'
ID_STATUS=0
assert_identity_lacks_group site-a 300
ID_OUTPUT='100 300\n'
! assert_identity_lacks_group site-a 300
ID_OUTPUT='100 200\n'
ID_STATUS=71
! assert_identity_lacks_group site-a 300
ID_OUTPUT='100\n200\n'
ID_STATUS=0
! assert_identity_lacks_group site-a 300
'''
        completed = self.run_bash(program)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotRegex(source, r"(?m)^! id -G ")

    def test_edge_release_symlink_scan_checks_traversal_status(self):
        source = self.read("install-edge-lab.sh")
        function = shell_function(source, "assert_no_release_symlinks")
        program = f'''set -euo pipefail
candidate_dir=$(mktemp -d)
trap 'rm -rf -- "${{candidate_dir}}"' EXIT
find() {{
  if [[ ${{EMIT_SYMLINK}} == 1 ]]; then
    printf 'release/link\\0'
  fi
  return "${{FIND_STATUS}}"
}}
{function}
EMIT_SYMLINK=0
FIND_STATUS=0
assert_no_release_symlinks /unused
EMIT_SYMLINK=1
! assert_no_release_symlinks /unused
EMIT_SYMLINK=0
FIND_STATUS=72
! assert_no_release_symlinks /unused
EMIT_SYMLINK=1
! assert_no_release_symlinks /unused
'''
        completed = self.run_bash(program)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn('! find "${release}" -type l -print -quit | grep -q .', source)
        self.assertIn('assert_no_release_symlinks "${release}"', source)


if __name__ == "__main__":
    unittest.main()

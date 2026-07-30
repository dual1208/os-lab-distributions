import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL_RELAY = ROOT / "scripts" / "install-relay.sh"
ROLLBACK_RELAY = ROOT / "scripts" / "rollback-relay.sh"
ROLLBACK_EDGE = ROOT / "scripts" / "rollback-edge.sh"
PROVISION = ROOT / "scripts" / "provision-relay-fault-access.sh"


def bash_path() -> str | None:
    found = shutil.which("bash")
    if found:
        return found
    candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
    return str(candidate) if candidate.is_file() else None


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


class InstallerProducerFailClosedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bash = bash_path()
        cls.install = INSTALL_RELAY.read_text(encoding="utf-8")
        cls.rollback_relay = ROLLBACK_RELAY.read_text(encoding="utf-8")
        cls.rollback_edge = ROLLBACK_EDGE.read_text(encoding="utf-8")
        cls.provision = PROVISION.read_text(encoding="utf-8")

    def run_bash(self, harness: str, mode: str) -> subprocess.CompletedProcess[str]:
        if self.bash is None:
            self.skipTest("bash is unavailable")
        return subprocess.run(
            [self.bash, "-c", harness, "--", mode],
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )

    def assert_valid_then_failure_rejected(self, harness: str) -> None:
        valid = self.run_bash(harness, "0")
        self.assertEqual(valid.returncode, 0, valid.stderr)
        failed = self.run_bash(harness, "7")
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)

    def test_stat_tuple_rejects_valid_output_then_failure(self) -> None:
        validator = shell_function(self.provision, "validate_root_file")
        harness = f"""set -euo pipefail
STATUS=$1
candidate=$(mktemp)
trap 'rm -f -- "${{candidate}}"' EXIT
stat() {{ printf '0:0:600:1\n'; return "${{STATUS}}"; }}
{validator}
validate_root_file "${{candidate}}" 600
"""
        self.assert_valid_then_failure_rejected(harness)

    def test_wc_reader_rejects_valid_output_then_failure(self) -> None:
        reader = shell_function(self.rollback_edge, "read_one_line_file")
        harness = f"""set -euo pipefail
STATUS=$1
candidate=$(mktemp)
trap 'rm -f -- "${{candidate}}"' EXIT
printf 'expected\n' > "${{candidate}}"
wc() {{ printf '1\n'; return "${{STATUS}}"; }}
{reader}
value=
read_one_line_file "${{candidate}}" value
[[ ${{value}} == expected ]]
"""
        self.assert_valid_then_failure_rejected(harness)

    def test_manifest_grep_rejects_valid_count_then_failure(self) -> None:
        counter = shell_function(self.rollback_relay, "checked_fixed_count")
        harness = f"""set -euo pipefail
STATUS=$1
grep() {{ printf '1\n'; return "${{STATUS}}"; }}
{counter}
count=
checked_fixed_count count 'present path' /ignored
[[ ${{count}} == 1 ]]
"""
        self.assert_valid_then_failure_rejected(harness)

    def test_match_collector_rejects_valid_line_then_failure(self) -> None:
        collector = shell_function(self.provision, "collect_extended_matches")
        harness = f"""set -euo pipefail
STATUS=$1
grep() {{ printf 'permituserenvironment no\n'; return "${{STATUS}}"; }}
{collector}
matches=()
collect_extended_matches matches '^permituserenvironment ' ignored
[[ ${{#matches[@]}} -eq 1 && ${{matches[0]}} == 'permituserenvironment no' ]]
"""
        self.assert_valid_then_failure_rejected(harness)

    def test_generated_file_comparison_rejects_complete_output_then_failure(self) -> None:
        comparator = shell_function(self.rollback_relay, "compare_generated_file")
        harness = f"""set -euo pipefail
STATUS=$1
actual=$(mktemp)
trap 'rm -f -- "${{actual}}"' EXIT
printf 'exact\n' > "${{actual}}"
real_mktemp=$(command -v mktemp)
mktemp() {{ "${{real_mktemp}}"; }}
producer() {{ printf 'exact\n'; return "${{STATUS}}"; }}
{comparator}
compare_generated_file "${{actual}}" producer
"""
        self.assert_valid_then_failure_rejected(harness)

    def test_openssl_description_rejects_valid_output_then_failure(self) -> None:
        root_validator = shell_function(self.provision, "validate_root_file")
        comparator = shell_function(self.provision, "compare_generated_file")
        validator = shell_function(
            self.provision, "validate_openssl_ed25519_public_key"
        )
        harness = f"""set -euo pipefail
STATUS=$1
candidate=$(mktemp)
trap 'rm -f -- "${{candidate}}"' EXIT
printf '%s\n' '-----BEGIN PUBLIC KEY-----' payload '-----END PUBLIC KEY-----' > "${{candidate}}"
real_mktemp=$(command -v mktemp)
mktemp() {{ "${{real_mktemp}}"; }}
stat() {{
  case " $* " in
    *' %s '*) printf '96\n' ;;
    *) printf '0:0:600:1\n' ;;
  esac
}}
openssl() {{
  case " $* " in
    *' -text_pub '*) printf 'ED25519 Public-Key:\n'; return "${{STATUS}}" ;;
    *' -pubout '*) command cat -- "${{candidate}}" ;;
    *) return 9 ;;
  esac
}}
{root_validator}
{comparator}
{validator}
validate_openssl_ed25519_public_key "${{candidate}}" 600
"""
        self.assert_valid_then_failure_rejected(harness)

    def test_disabled_unit_probe_rejects_valid_state_then_unexpected_status(self) -> None:
        recorder = shell_function(self.install, "record_relay_unit_state")
        harness = f"""set -euo pipefail
STATUS=$1
snapshot=$(mktemp -d)
trap 'rm -rf -- "${{snapshot}}"' EXIT
systemctl() {{
  case " $* " in
    *' show '*) printf 'inactive\n'; return 0 ;;
    *' is-enabled '*) printf 'disabled\n'; return "${{STATUS}}" ;;
    *) return 9 ;;
  esac
}}
{recorder}
record_relay_unit_state "${{snapshot}}"
[[ ! -e ${{snapshot}}/active.campus-link-relay.service &&
   ! -e ${{snapshot}}/enabled.campus-link-relay.service ]]
"""
        valid = self.run_bash(harness, "1")
        self.assertEqual(valid.returncode, 0, valid.stderr)
        failed = self.run_bash(harness, "7")
        self.assertNotEqual(failed.returncode, 0)

    def test_assigned_scripts_have_no_status_blind_process_substitution(self) -> None:
        for path, source in (
            (INSTALL_RELAY, self.install),
            (ROLLBACK_RELAY, self.rollback_relay),
            (ROLLBACK_EDGE, self.rollback_edge),
            (PROVISION, self.provision),
        ):
            with self.subTest(path=path.name):
                self.assertNotIn("< <(", source)
                self.assertNotIn("cmp -s -- <(", source)
                self.assertNotRegex(source, r"\[\[\s*\$\((?:stat|wc|openssl)\b")
                self.assertNotRegex(source, r"\$\(cat\b[^\n]*\|\|\s*true")


if __name__ == "__main__":
    unittest.main()

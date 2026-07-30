import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


class PrivilegeBootstrapTests(unittest.TestCase):
    @staticmethod
    def bash():
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        return bash

    @staticmethod
    def function(source: str, name: str) -> str:
        start = source.index(f"{name}()")
        end = source.index("\n}\n", start) + 3
        return source[start:end]

    def test_relay_identity_is_separate_manifest_bound_bootstrap(self):
        provision = (ROOT / "scripts" / "provision-relay-identity.sh").read_text(encoding="utf-8")
        installer = (ROOT / "scripts" / "install-relay.sh").read_text(encoding="utf-8")
        deploy = (REPO / "scripts" / "Deploy-CampusLink.ps1").read_text(encoding="utf-8")

        self.assertIn("groupadd --system", provision)
        self.assertIn("useradd --system", provision)
        self.assertIn("--home-dir /nonexistent", provision)
        self.assertIn("--shell /usr/sbin/nologin", provision)
        self.assertIn('passwd_record=$(getent passwd "${RELAY_USER}") || exit 1', provision)
        self.assertIn('group_record=$(getent group "${RELAY_USER}") || exit 1', provision)
        self.assertIn('relay_groups=$(id -G "${RELAY_USER}") || exit 1', provision)
        self.assertIn('[[ ${relay_groups} == "${passwd_gid}" ]]', provision)

        self.assertNotIn("groupadd", installer)
        self.assertNotIn("useradd", installer)
        self.assertIn("provision-relay-identity.sh", installer)
        self.assertIn("relay_passwd_record=$(getent passwd campus-link) || exit 1", installer)
        self.assertIn("relay_groups=$(id -G campus-link) || exit 1", installer)
        self.assertIn('[[ ${relay_groups} == "${relay_gid}" ]]', installer)

        verify = deploy.index("verify scripts/provision-relay-identity.sh")
        run = deploy.index("/bin/bash '$remoteStage/provision-relay-identity.sh'")
        install = deploy.index("/bin/bash '$remoteStage/install-relay.sh'")
        self.assertLess(verify, run)
        self.assertLess(run, install)

    def test_candidate_source_digest_includes_bootstrap_and_orchestrator(self):
        build = (ROOT / "scripts" / "build.sh").read_text(encoding="utf-8")
        installer = (ROOT / "scripts" / "install-edge-lab.sh").read_text(encoding="utf-8")
        for path in ("cloud/cloud-init.yaml", "scripts/Deploy-CampusLink.ps1"):
            self.assertIn(path, build)
            self.assertIn(path, installer)
        self.assertIn('sort -z > "${source_paths}" || exit 1', build)
        self.assertIn(
            'read_complete_nul_inventory "${source_paths}" source_path_inventory',
            build,
        )
        self.assertIn(
            'actual_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD) || return 1',
            build,
        )
        self.assertIn(
            'untracked=$(git -C "${REPO_ROOT}" ls-files --others --', build
        )
        self.assertNotIn("done < <(git -C", build)
        self.assertGreaterEqual(installer.count('sort -z > "${tracked_listing}" || return 1'), 4)
        self.assertEqual(
            installer.count(
                'read_complete_nul_inventory "${tracked_listing}" tracked_paths'
            ),
            4,
        )
        self.assertNotIn("done < <(git -C", installer)
        self.assertIn('actual_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD) || return 1', installer)
        self.assertIn('untracked=$(git -C "${REPO_ROOT}" ls-files --others --', installer)

    def test_post_build_git_producers_cannot_hide_failure_after_valid_output(self):
        bash = self.bash()
        if bash is None:
            self.skipTest("bash is unavailable")
        source = (ROOT / "scripts/build.sh").read_text(encoding="utf-8")
        function = self.function(source, "verify_source_checkout_unchanged")
        harness = f"""set -euo pipefail
mode=$1
REPO_ROOT=/ignored
SOURCE_SCOPE=(campus-link)
TEST_COMMIT=0123456789abcdef0123456789abcdef01234567
{function}
git() {{
  case " $* " in
    *' rev-parse HEAD '*)
      printf '%s\\n' "${{TEST_COMMIT}}"
      [[ ${{mode}} != rev-failure ]] || return 7
      ;;
    *' ls-files --others '*)
      [[ ${{mode}} != untracked ]] || printf 'campus-link/omitted.go\\n'
      [[ ${{mode}} != untracked-failure ]] || return 7
      ;;
    *' diff '*) return 0 ;;
    *) return 9 ;;
  esac
}}
verify_source_checkout_unchanged "${{TEST_COMMIT}}"
"""
        valid = subprocess.run(
            [bash, "-c", harness, "--", "valid"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        for mode in ("rev-failure", "untracked-failure", "untracked"):
            completed = subprocess.run(
                [bash, "-c", harness, "--", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, mode)

    def test_nul_inventory_consumers_reject_incomplete_tail_and_read_failure(self):
        bash = self.bash()
        if bash is None:
            self.skipTest("bash is unavailable")
        for relative in ("scripts/build.sh", "scripts/install-edge-lab.sh"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            function = self.function(source, "read_complete_nul_inventory")
            harness = f"""set -euo pipefail
mode=$1
inventory=$(mktemp)
trap 'rm -f -- "${{inventory}}"' EXIT
case ${{mode}} in
  valid|read-failure) printf 'alpha\\0beta\\0' > "${{inventory}}" ;;
  unterminated) printf 'alpha\\0beta' > "${{inventory}}" ;;
  *) exit 2 ;;
esac
{function}
if [[ ${{mode}} == read-failure ]]; then
  READ_CALLS=0
  read() {{
    READ_CALLS=$((READ_CALLS + 1))
    (( READ_CALLS != 2 )) || return 7
    builtin read "$@"
  }}
fi
items=()
read_complete_nul_inventory "${{inventory}}" items
[[ ${{items[*]}} == 'alpha beta' ]]
"""
            valid = subprocess.run(
                [bash, "-c", harness, "--", "valid"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(valid.returncode, 0, f"{relative}: {valid.stderr}")
            for mode in ("unterminated", "read-failure"):
                failed = subprocess.run(
                    [bash, "-c", harness, "--", mode],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(failed.returncode, 0, f"{relative}: {mode}")

    def test_relay_stage_and_manifest_reject_failed_or_omitted_tail(self):
        bash = self.bash()
        if bash is None:
            self.skipTest("bash is unavailable")
        source = (ROOT / "scripts/install-relay.sh").read_text(encoding="utf-8")
        nul_reader = self.function(source, "read_complete_nul_inventory")
        line_reader = self.function(source, "read_complete_line_inventory")
        stage_validator = self.function(source, "validate_stage_inventory")
        manifest_validator = self.function(source, "validate_manifest_inventory")

        stage_harness = f"""set -euo pipefail
mode=$1
readonly -a stage_names=(alpha beta)
{nul_reader}
{stage_validator}
find() {{
  printf 'alpha\\0'
  [[ ${{mode}} == omitted ]] || printf 'beta\\0'
  [[ ${{mode}} != producer-failure ]] || return 7
}}
validate_stage_inventory /ignored
"""
        for mode, expected in (("valid", 0), ("producer-failure", 1), ("omitted", 1)):
            completed = subprocess.run(
                [bash, "-c", stage_harness, "--", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            if expected == 0:
                self.assertEqual(completed.returncode, 0, completed.stderr)
            else:
                self.assertNotEqual(completed.returncode, 0, mode)

        manifest_harness = f"""set -euo pipefail
mode=$1
manifest=$(mktemp)
trap 'rm -f -- "${{manifest}}"' EXIT
digest=$(printf '0%.0s' {{1..64}})
printf '%s  VERSION\\n' "${{digest}}" > "${{manifest}}"
if [[ ${{mode}} == unterminated ]]; then
  printf '%s  bin/campus-link-relay' "${{digest}}" >> "${{manifest}}"
else
  printf '%s  bin/campus-link-relay\\n' "${{digest}}" >> "${{manifest}}"
fi
{line_reader}
{manifest_validator}
if [[ ${{mode}} == read-failure ]]; then
  READ_CALLS=0
  read() {{
    READ_CALLS=$((READ_CALLS + 1))
    (( READ_CALLS != 2 )) || return 7
    builtin read "$@"
  }}
fi
lines=()
validate_manifest_inventory "${{manifest}}" lines
[[ ${{#lines[@]}} -eq 2 ]]
"""
        valid = subprocess.run(
            [bash, "-c", manifest_harness, "--", "valid"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        for mode in ("unterminated", "read-failure"):
            failed = subprocess.run(
                [bash, "-c", manifest_harness, "--", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(failed.returncode, 0, mode)

    def test_relay_negative_match_distinguishes_absence_from_reader_error(self):
        bash = self.bash()
        if bash is None:
            self.skipTest("bash is unavailable")
        source = (ROOT / "scripts/install-relay.sh").read_text(encoding="utf-8")
        function = self.function(source, "assert_no_extended_regex_match")
        harness = f"""set -euo pipefail
GREP_STATUS=$1
{function}
grep() {{ return "${{GREP_STATUS}}"; }}
assert_no_extended_regex_match forbidden /ignored
"""
        absent = subprocess.run(
            [bash, "-c", harness, "--", "1"], check=False, capture_output=True
        )
        self.assertEqual(absent.returncode, 0)
        for status in ("0", "2"):
            completed = subprocess.run(
                [bash, "-c", harness, "--", status],
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(completed.returncode, 0, status)


if __name__ == "__main__":
    unittest.main()

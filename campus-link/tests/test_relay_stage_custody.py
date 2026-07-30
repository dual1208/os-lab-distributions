import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-relay.sh"
PROTOCOL = ROOT / "PROTOCOL.md"


def bash_path() -> str | None:
    found = shutil.which("bash")
    if found:
        return found
    candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
    return str(candidate) if candidate.exists() else None


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


class RelayStageCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")
        cls.bash = bash_path()

    def run_custody(self, stage_tuple: str, file_tuple: str) -> subprocess.CompletedProcess[str]:
        if self.bash is None:
            self.skipTest("bash is unavailable")
        function = shell_function(self.source, "validate_stage_custody")
        harness = f"""
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf -- "${{tmp}}"' EXIT
printf x > "${{tmp}}/artifact"
stage_names=(artifact)
stat() {{
  [[ $1 == -c && $3 == -- ]]
  if [[ $4 == "${{tmp}}" ]]; then
    printf '%s\n' "$STAGE_TUPLE"
  else
    printf '%s\n' "$FILE_TUPLE"
  fi
}}
{function}
validate_stage_custody "${{tmp}}"
"""
        return subprocess.run(
            [self.bash, "-c", harness],
            text=True,
            capture_output=True,
            env={**os.environ, "STAGE_TUPLE": stage_tuple, "FILE_TUPLE": file_tuple},
            check=False,
        )

    def test_exact_custody_accepts_only_root_private_single_link_artifacts(self) -> None:
        accepted = self.run_custody("0:0:700", "0:0:600:1")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for name, stage_tuple, file_tuple in (
            ("stage mode", "0:0:755", "0:0:600:1"),
            ("stage owner", "1:0:700", "0:0:600:1"),
            ("artifact owner", "0:0:700", "1:0:600:1"),
            ("artifact group write", "0:0:700", "0:0:660:1"),
            ("artifact special bit", "0:0:700", "0:0:4600:1"),
            ("artifact hard link", "0:0:700", "0:0:600:2"),
        ):
            with self.subTest(name=name):
                rejected = self.run_custody(stage_tuple, file_tuple)
                self.assertNotEqual(rejected.returncode, 0)

    def test_open_directory_descriptor_survives_path_replacement(self) -> None:
        if self.bash is None:
            self.skipTest("bash is unavailable")
        system = subprocess.run(
            [self.bash, "-c", "uname -s"], text=True, capture_output=True, check=False
        ).stdout.strip()
        if system.startswith(("MINGW", "MSYS", "CYGWIN")):
            self.skipTest("Windows procfs does not retain Linux directory descriptors")
        harness = r"""
set -euo pipefail
original=$(mktemp -d)
moved=${original}.moved
cleanup() { rm -rf -- "${original}" "${moved}"; }
trap cleanup EXIT
printf original > "${original}/artifact"
exec {stage_fd}<"${original}"
pinned=/proc/$$/fd/${stage_fd}/.
mv -- "${original}" "${moved}"
mkdir -- "${original}"
printf replacement > "${original}/artifact"
[[ $(<"${pinned}/artifact") == original ]]
"""
        completed = subprocess.run(
            [self.bash, "-c", harness], text=True, capture_output=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_installer_revalidates_pinned_candidate_before_mutation(self) -> None:
        self.assertIn('exec {stage_dir_fd}<"${STAGE_INPUT}"', self.source)
        self.assertIn('readonly STAGE=/proc/$$/fd/${stage_dir_fd}/.', self.source)
        self.assertGreaterEqual(self.source.count("revalidate_stage_candidate"), 3)
        self.assertLess(
            self.source.index("revalidate_stage_candidate\nquarantine_pending_permit"),
            self.source.index("activate_snapshot\n"),
        )
        final_recheck = self.source.index(
            "revalidate_stage_candidate\ninstall -d -m 0755 /usr/local/libexec"
        )
        first_install = self.source.index(
            'atomic_install "${STAGE}/control-ca.crt"'
        )
        self.assertLess(final_recheck, first_install)

    def test_protocol_requires_opened_inode_and_exact_custody(self) -> None:
        protocol = PROTOCOL.read_text(encoding="utf-8")
        self.assertIn("opens and pins the exact staging-directory inode", protocol)
        self.assertIn("single-link regular file", protocol)
        self.assertIn("resolve through the pinned directory", protocol)


if __name__ == "__main__":
    unittest.main()

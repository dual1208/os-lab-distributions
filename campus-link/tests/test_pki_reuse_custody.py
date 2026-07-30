import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate-lab-pki.sh"
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


class PKIReuseCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = GENERATOR.read_text(encoding="utf-8")
        cls.bash = bash_path()

    def run_inventory(self, find_status: int, emit_entry: bool) -> subprocess.CompletedProcess[str]:
        if self.bash is None:
            self.skipTest("bash is unavailable")
        function = shell_function(self.source, "assert_no_symlinks")
        harness = f"""
set -euo pipefail
find() {{
  if [[ $EMIT_ENTRY == 1 ]]; then
    printf 'symlink\\0'
  fi
  return "$FIND_STATUS"
}}
{function}
assert_no_symlinks /unused
"""
        return subprocess.run(
            [self.bash, "-c", harness],
            text=True,
            capture_output=True,
            check=False,
            env={
                **os.environ,
                "FIND_STATUS": str(find_status),
                "EMIT_ENTRY": "1" if emit_entry else "0",
            },
        )

    def test_checked_empty_symlink_inventory_is_required(self) -> None:
        accepted = self.run_inventory(0, False)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertNotEqual(self.run_inventory(0, True).returncode, 0)
        self.assertNotEqual(self.run_inventory(9, False).returncode, 0)
        self.assertNotEqual(self.run_inventory(9, True).returncode, 0)

    def test_generator_no_longer_negates_a_find_pipeline(self) -> None:
        self.assertNotIn('! find "${ROOT}"', self.source)
        self.assertIn('assert_no_symlinks "${ROOT}"', self.source)
        self.assertIn("-print0 -quit", shell_function(self.source, "assert_no_symlinks"))

    def test_protocol_rejects_traversal_failure_as_empty_inventory(self) -> None:
        protocol = PROTOCOL.read_text(encoding="utf-8")
        self.assertIn("complete symlink\ninventory is captured from a checked traversal", protocol)
        self.assertIn("failed traversal is not evidence", protocol)


if __name__ == "__main__":
    unittest.main()

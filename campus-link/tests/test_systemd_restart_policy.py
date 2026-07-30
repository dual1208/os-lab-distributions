import re
import unittest
from pathlib import Path


UNITS = (
    "campus-link-edge-a.service",
    "campus-link-edge-b.service",
    "campus-link-relay.service",
)


def unit_values(path: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        key, separator, value = line.partition("=")
        if separator:
            values.setdefault(key, []).append(value)
    return values


def seconds(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|min)?", value)
    if match is None:
        raise ValueError("unsupported systemd duration")
    amount = float(match.group(1))
    return amount * {None: 1.0, "ms": 0.001, "s": 1.0, "min": 60.0}[match.group(2)]


class SystemdRestartPolicyTests(unittest.TestCase):
    def test_certificate_preflight_failures_retry_without_busy_loop_or_lockout(self):
        unit_root = Path(__file__).parents[1] / "systemd"
        for name in UNITS:
            with self.subTest(unit=name):
                values = unit_values(unit_root / name)
                self.assertEqual(values.get("Restart"), ["on-failure"])
                self.assertEqual(values.get("StartLimitIntervalSec"), ["0"])
                self.assertNotIn("StartLimitBurst", values)
                restart_values = values.get("RestartSec")
                self.assertIsNotNone(restart_values)
                self.assertEqual(len(restart_values), 1)
                delay = seconds(restart_values[0])
                self.assertGreaterEqual(delay, 1.0)
                self.assertLessEqual(delay, 30.0)


if __name__ == "__main__":
    unittest.main()

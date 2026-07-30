#!/usr/bin/env python3
"""Static fail-closed routing contract checks for the isolated router lab."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class KillSwitchContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    @staticmethod
    def function(source: str, name: str) -> str:
        start = source.index(f"{name}()")
        end = source.index("\n}\n", start) + 3
        return source[start:end]

    def test_topology_installs_exact_route_and_firewall_kill_switches(self) -> None:
        script = self.read("scripts/topology.sh")
        self.assertIn("KILL_SWITCH_METRIC=32760", script)
        self.assertIn('route add unreachable "${remote_prefix}"', script)
        self.assertIn('iptables -w -I OUTPUT 1 -d "${remote_prefix}"', script)
        self.assertIn('iptables -w -I FORWARD 1 -d "${remote_prefix}"', script)
        self.assertIn("campus-link-private-prefix-kill-switch", script)
        self.assertLess(
            script.index('route add unreachable "${remote_prefix}"'),
            script.index('route add default via "${wan_gateway}"'),
        )
        self.assertIn('sysctl -q -w net.ipv4.ip_forward=0', script)
        self.assertIn('sysctl -q -w net.ipv4.ip_forward=1', script)
        self.assertIn('trap failed_up ERR', script)
        self.assertIn("validate_host_forwarding_baseline", script)
        self.assertIn("campus-link requires the host FORWARD policy to be DROP", script)
        self.assertIn("iptables -w -S FORWARD", script)
        self.assertNotRegex(script, r"(?m)^\s*sysctl -q -w net\.ipv4\.ip_forward=1\s*$")
        self.assertNotIn("ip_forward.before", script)
        self.assertNotIn("HOST_IPV4_CONF_SNAPSHOT", script)
        self.assertLess(
            script.index("validate_host_forwarding_baseline\n  down"),
            script.index('ip netns del oslab-relay'),
        )
        self.assertIn('-s "${WAN_A_ADDRESS}/32" -o "${wan}"', script)
        self.assertIn('-s "${WAN_B_ADDRESS}/32" -o "${wan}"', script)
        self.assertIn('-i "${wan}" -d "${WAN_A_ADDRESS}/32"', script)
        self.assertIn('-i "${wan}" -d "${WAN_B_ADDRESS}/32"', script)
        self.assertIn("--ctstate NEW,ESTABLISHED,RELATED", script)
        self.assertIn("WAN_DEVICE_STATE", script)
        self.assertIn('ip link del br-relay-a', script)
        self.assertIn('ip link del br-relay-b', script)
        self.assertIn("10.81.0.0/24 10.82.0.0/24", script)
        self.assertIn("10.82.0.0/24 10.81.0.0/24", script)

    def test_host_bootstrap_provisions_closed_forwarding_baseline(self) -> None:
        cloud_init = self.read("../cloud/cloud-init.yaml")
        self.assertIn("net.ipv4.ip_forward=1", cloud_init)
        self.assertIn("- [ufw, default, deny, routed]", cloud_init)
        for site in ("a", "b"):
            self.assertIn(f"- name: campus-link-{site}", cloud_init)
            self.assertIn(f"primary_group: campus-link-{site}", cloud_init)
        self.assertEqual(cloud_init.count("groups: []"), 2)

    def test_tun_route_requires_persistent_kill_switch(self) -> None:
        script = self.read("scripts/configure-tun.sh")
        verify = script.index('route show type unreachable "${REMOTE_PREFIX}"')
        wait = script.index("for _ in {1..50}")
        install = script.index('route show "${REMOTE_PREFIX}"')
        self.assertLess(verify, wait)
        self.assertLess(wait, install)
        self.assertIn('iptables -w -C OUTPUT -d "${REMOTE_PREFIX}"', script)
        self.assertIn('iptables -w -C FORWARD -d "${REMOTE_PREFIX}"', script)
        self.assertGreater(script.count('route show type unreachable "${REMOTE_PREFIX}"'), 1)
        self.assertNotIn('route replace "${REMOTE_PREFIX}"', script)

    def test_recovery_gate_proves_unreachable_and_zero_wan_capture(self) -> None:
        script = self.read("scripts/test-edge-recovery.sh")
        self.assertIn("kill_switch_active", script)
        self.assertIn("command_output_matches ' dev cl0 '", script)
        self.assertIn('route get "${remote_probe}"', script)
        self.assertNotIn('route get "${remote_probe}" | grep -q', script)
        self.assertIn('tcpdump -qn -i "${host_device}"', script)
        self.assertIn('"dst net ${remote_prefix}"', script)
        self.assertIn('ip netns exec "${lan_namespace}"', script)
        self.assertIn('campus-link-forward-kill-switch', script)
        self.assertIn("kill_switch=pass", script)

    def test_rollback_rejects_unsafe_prior_topology(self) -> None:
        script = self.read("scripts/rollback-edge.sh")
        validation = script.index("validate_snapshot_security_tuple")
        stop = script.index("stop_unit_if_loaded()")
        self.assertLess(validation, stop)
        self.assertIn("A pre-campus-link", script)
        self.assertIn("campus-link-private-prefix-kill-switch", script)
        self.assertIn("validate_stored_edge_unit", script)
        self.assertIn("validate_stored_site_tree", script)
        self.assertIn("validate_host_forwarding_baseline", script)
        self.assertIn("TCPMSS --clamp-mss-to-pmtu", script)
        self.assertIn("WAN_A_ADDRESS", script)
        self.assertIn("CapabilityBoundingSet=", script)
        self.assertIn("InaccessiblePaths", script)

    def test_router_baseline_has_persistent_plaintext_free_campus_mode(self) -> None:
        topology = self.read("../lab/openwrt-lab-topology")
        start = self.read("../lab/openwrt-lab-start")
        smoke = self.read("../lab/openwrt-lab-smoke")
        installer = self.read("scripts/install-edge-lab.sh")
        restore = self.read("scripts/restore-offline.sh")
        evidence = self.read("scripts/gate-evidence.sh")
        self.assertIn("router-only", topology)
        self.assertIn("CAMPUS_MODE_MARKER", start)
        self.assertIn('openwrt-lab-topology up "${transit_mode}"', start)
        self.assertIn("CROSS_SITE=absent", smoke)
        self.assertIn("router-only.enabled", installer)
        self.assertIn("openwrt-lab-start", installer)
        self.assertIn("qualification-run.manifest", restore)
        self.assertLess(
            restore.index("qualification-run.manifest"),
            restore.index("router-only.enabled"),
        )
        self.assertIn("campus_link_assert_no_plaintext_relay", evidence)
        self.assertIn("br-relay-a", evidence)
        self.assertIn("br-relay-b", evidence)

    def test_negative_namespace_and_key_tree_proofs_preserve_enumerator_status(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        source = self.read("scripts/gate-evidence.sh")
        namespace_function = self.function(
            source, "campus_link_assert_no_plaintext_relay"
        )
        tree_function = self.function(
            source, "campus_link_assert_no_nonregular_entries"
        )

        namespace_harness = f"""set -euo pipefail
mode=$1
{namespace_function}
campus_link_require_root_file() {{ return 0; }}
ip() {{
  if [[ $1 == netns && $2 == list ]]; then
    if [[ ${{mode}} == forbidden ]]; then
      printf 'oslab-relay\\n'
    else
      printf 'safe-namespace\\n'
    fi
    [[ ${{mode}} != producer-failure ]] || return 7
    return 0
  fi
  if [[ $1 == -o && $2 == link && $3 == show ]]; then
    printf '1: lo: <LOOPBACK> mtu 65536\\n'
    return 0
  fi
  [[ $1 == link && $2 == show ]] && return 1
  return 2
}}
campus_link_assert_no_plaintext_relay
"""
        safe = subprocess.run(
            [bash, "-c", namespace_harness, "--", "safe"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(safe.returncode, 0, safe.stderr)
        for mode in ("producer-failure", "forbidden"):
            completed = subprocess.run(
                [bash, "-c", namespace_harness, "--", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, mode)

        tree_harness = f"""set -euo pipefail
mode=$1
{tree_function}
find() {{
  [[ ${{mode}} != extra-entry ]] || printf '/ignored/omitted-tail-link\\n'
  [[ ${{mode}} != producer-failure ]] || return 7
}}
campus_link_assert_no_nonregular_entries /ignored
"""
        safe = subprocess.run(
            [bash, "-c", tree_harness, "--", "safe"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(safe.returncode, 0, safe.stderr)
        for mode in ("producer-failure", "extra-entry"):
            completed = subprocess.run(
                [bash, "-c", tree_harness, "--", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, mode)

    def test_edge_parsers_are_unprivileged_and_cannot_mutate_the_switch(self) -> None:
        for site in ("a", "b"):
            unit = self.read(f"systemd/campus-link-edge-{site}.service")
            self.assertIn(f"User=campus-link-{site}", unit)
            self.assertIn(f"Group=campus-link-{site}", unit)
            self.assertIn("CapabilityBoundingSet=\n", unit)
            self.assertIn("AmbientCapabilities=\n", unit)
            self.assertIn("DevicePolicy=closed", unit)
            self.assertIn("DeviceAllow=/dev/net/tun rw", unit)
            self.assertIn(f"NetworkNamespacePath=/run/netns/campus-{site}", unit)
            peer = "b" if site == "a" else "a"
            self.assertIn(f"-/etc/campus-link/site-{peer}", unit)
            self.assertIn(f"-/run/campus-link/site-{peer}", unit)
            self.assertIn("-/etc/campus-link/pki", unit)
            self.assertIn("-/var/lib/campus-link", unit)
            self.assertIn("-/srv/openwrt-lab", unit)
            self.assertNotIn("ip netns exec", unit)
            self.assertNotIn("ExecStartPost", unit)
        topology = self.read("scripts/topology.sh")
        self.assertIn('ip tuntap add dev cl0 mode tun user "${service_uid}"', topology)
        self.assertIn('route add "${remote_prefix}" dev cl0 metric 10', topology)
        self.assertIn('metric 10 mtu 1200', topology)
        self.assertIn('TCPMSS --clamp-mss-to-pmtu', topology)
        configure = self.read("scripts/configure-tun.sh")
        self.assertIn("mtu 1200", configure)
        self.assertIn('TCPMSS --clamp-mss-to-pmtu', configure)


if __name__ == "__main__":
    unittest.main()

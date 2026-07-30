import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-edge-lab.sh"
ROLLBACK = ROOT / "scripts" / "rollback-edge.sh"
PKI_GENERATOR = ROOT / "scripts" / "generate-lab-pki.sh"


def snapshot_paths(path: Path) -> tuple[str, ...]:
    source = path.read_text(encoding="utf-8")
    match = re.search(r"^readonly -a snapshot_paths=\(\n(?P<body>.*?)^\)$", source, re.M | re.S)
    if match is None:
        raise AssertionError(f"snapshot_paths array is absent from {path.name}")
    paths = []
    for line in match.group("body").splitlines():
        value = line.strip()
        if not re.fullmatch(r"/[A-Za-z0-9._/-]+", value):
            raise AssertionError(f"unsafe snapshot entry in {path.name}: {value!r}")
        paths.append(value)
    return tuple(paths)


class EdgeInstallRollbackTests(unittest.TestCase):
    def test_authorization_reader_checks_complete_input_consumption(self):
        source = INSTALLER.read_text(encoding="utf-8")
        function = re.search(
            r"(?ms)^read_authorization\(\) \{\n(?P<body>.*?)^\}", source
        )
        self.assertIsNotNone(function)
        body = function.group("body")
        self.assertIn('mapfile -t lines < "${file}" || return 1', body)
        self.assertIn('[[ ${key} =~ ^[A-Z][A-Z0-9_]*$ ]] || return 1', body)
        self.assertNotIn("< <(", body)
        self.assertNotIn("|| true", body)

    def test_site_identities_are_distinct_without_peer_group_membership(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("useradd", source)
        self.assertNotIn("groupadd", source)
        self.assertIn("assert_service_identity campus-link-a", source)
        self.assertIn("assert_service_identity campus-link-b", source)
        self.assertIn('passwd_record=$(getent passwd "${name}") || return 1', source)
        self.assertIn('all_groups=$(id -G "${name}") || return 1', source)
        self.assertIn('${all_groups} == "${primary_gid}"', source)
        self.assertIn('[[ ${site_a_uid} != "${site_b_uid}" && ${site_a_gid} != "${site_b_gid}" ]]', source)
        self.assertIn('assert_identity_lacks_group campus-link-a "${site_b_gid}"', source)
        self.assertIn('assert_identity_lacks_group campus-link-b "${site_a_gid}"', source)
        self.assertIn('group_listing=$(id -G "${name}") || return 1', source)
        self.assertNotRegex(source, r"(?m)^! id -G ")

    def test_site_credential_tree_is_exact_before_and_after_mutation(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("assert_edge_tree()", source)
        self.assertIn("control-ca.crt data-ca.crt edge.json", source)
        self.assertIn("root:${group}:750", source)
        self.assertIn("root:${group}:640", source)
        snapshot = source.index("activate_snapshot\n")
        self.assertLess(source.index('assert_edge_tree site-a "${ROOT}" 1'), snapshot)
        installed = source.index('assert_edge_tree site-a "${ROOT}" 0', snapshot)
        self.assertGreater(installed, snapshot)
        self.assertLess(installed, source.index("runuser --user campus-link-a"))

    def test_unmanifested_systemd_overrides_fail_before_snapshot(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("assert_no_unit_overrides()", source)
        for base in ("/etc/systemd/system", "/run/systemd/system", "/etc/systemd/system.control", "/run/systemd/system.control"):
            self.assertIn(base, source)
        self.assertIn("${base}/${unit}.d", source)
        snapshot = source.index("activate_snapshot\n")
        first = source.index("assert_no_unit_overrides\n")
        second = source.index("assert_no_unit_overrides\n", first + 1)
        self.assertLess(first, snapshot)
        self.assertGreater(second, snapshot)

    def test_unsafe_prior_security_tuple_fails_before_snapshot(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("assert_current_security_tuple()", source)
        self.assertIn("assert_installed_edge_unit()", source)
        self.assertIn("validate_host_forwarding_baseline", source)
        self.assertIn("TCPMSS --clamp-mss-to-pmtu", source)
        self.assertIn("WAN_A_ADDRESS", source)
        self.assertIn("CapabilityBoundingSet=", source)
        validation = source.index("assert_current_security_tuple\n")
        snapshot = source.index("activate_snapshot\n")
        self.assertLess(validation, snapshot)

    def test_final_edge_preflight_uses_exact_unprivileged_identity(self):
        source = INSTALLER.read_text(encoding="utf-8")
        for site in ("a", "b"):
            install = (
                f'atomic_install_owned "${{RELEASE}}/config/edge-{site}.json" '
                f'"${{ROOT}}/site-{site}/edge.json" 0640 root campus-link-{site}'
            )
            preflight = (
                f"runuser --user campus-link-{site} --group campus-link-{site} -- \\\n"
                f'  /usr/local/bin/campus-link-edge -check-config -config "${{ROOT}}/site-{site}/edge.json"'
            )
            self.assertIn(install, source)
            self.assertIn(preflight, source)
            self.assertLess(source.index(install), source.index(preflight))
        self.assertIn("command -v runuser >/dev/null", source)
        self.assertIn("campus-link-fault-in-stream.service \\\n", source)

    def test_generated_public_pins_are_bound_to_exact_local_credentials(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(source.count('"local_control_identity"'), 3)
        self.assertEqual(source.count('"local_data_identity"'), 2)
        bindings = (
            (r"\$\{credential_root\}/site-a/site-a-control", "site_a_control_uri", "site_a_control_pin", "local_control_identity"),
            (r"\$\{credential_root\}/site-b/site-b-control", "site_b_control_uri", "site_b_control_pin", "local_control_identity"),
            (r"\$\{credential_root\}/site-a/site-a-data", "site_a_data_uri", "site_a_data_pin", "local_data_identity"),
            (r"\$\{credential_root\}/site-b/site-b-data", "site_b_data_uri", "site_b_data_pin", "local_data_identity"),
            (r"\$\{pki_root\}/relay-control", "relay_control_uri", "relay_control_pin", "local_control_identity"),
        )
        for credential_pattern, uri, pin, field in bindings:
            pattern = (
                rf'"(?:control|data)_cert":"{credential_pattern}\.crt"'
                rf'.*?"{field}":\{{"uri":"\$\{{{uri}\}}",'
                rf'"current_spki":"\$\{{{pin}\}}"\}}'
            )
            self.assertRegex(source, pattern)

        generator = PKI_GENERATOR.read_text(encoding="utf-8")
        self.assertIn(
            '/bin/bash "${AUTH_HELPER}" "${ROOT}" "${ROOT}/authorization.env"',
            generator,
        )

    def test_installer_and_rollback_have_exact_snapshot_manifest_parity(self):
        installed = snapshot_paths(INSTALLER)
        restored = snapshot_paths(ROLLBACK)
        self.assertEqual(installed, restored)
        self.assertEqual(len(installed), len(set(installed)))
        self.assertNotIn("/", installed)
        for path in installed:
            self.assertTrue(path.startswith(("/usr/local/", "/etc/", "/var/lib/campus-link/")))

    def test_every_release_destination_and_state_mutation_is_snapshotted(self):
        paths = set(snapshot_paths(INSTALLER))
        required = {
            "/usr/local/bin/campus-link-edge",
            "/usr/local/bin/campus-linkctl",
            "/usr/local/libexec/campus-link-gate-evidence",
            "/usr/local/libexec/campus-link-status-gate.py",
            "/usr/local/libexec/campus-link-nat-rebind-gate.py",
            "/usr/local/libexec/campus-link-qualification-chain",
            "/usr/local/libexec/campus-link-fault-in-stream",
            "/usr/local/libexec/campus-link-nat-rebinding-gate",
            "/usr/local/libexec/campus-link-relay-restart-driver",
            "/usr/local/libexec/campus-link-rollback-edge",
            "/usr/local/libexec/openwrt-lab-start",
            "/usr/local/libexec/openwrt-lab-stop",
            "/usr/local/libexec/openwrt-lab-smoke",
            "/usr/local/libexec/gate-evidence.sh",  # removed legacy path
            "/etc/campus-link/edge-a.json",
            "/etc/campus-link/edge-b.json",
            "/etc/campus-link/pki",
            "/etc/campus-link/relay-fault",
            "/etc/campus-link/site-a",
            "/etc/campus-link/site-b",
            "/var/lib/campus-link/installed-edge-version",
            "/var/lib/campus-link/installed-release-manifest.sha256",
            "/var/lib/campus-link/deployment-attestation.env",
            "/var/lib/campus-link/router-only.enabled",
        }
        for unit in (
            "campus-link-topology.service",
            "campus-link-edge-a.service",
            "campus-link-edge-b.service",
            "campus-link-external.target",
            "campus-link-full-qualification.service",
            "campus-link-accelerated-fault.service",
            "campus-link-fault-in-stream.service",
            "campus-link-nat-rebinding.service",
            "campus-link-24h-soak.service",
            "campus-link-7d-burn-in.service",
            "campus-link-qualification-chain.service",
        ):
            required.add(f"/etc/systemd/system/{unit}")
        self.assertEqual(required - paths, set())

    def test_rollback_manifest_is_exact_and_not_executed(self):
        source = ROLLBACK.read_text(encoding="utf-8")
        self.assertIn('manifest_line_count=$(wc -l < "${SNAPSHOT}/manifest") || exit 1', source)
        self.assertIn('snapshot_entry_state entry_state "${path}"', source)
        self.assertIn('value=$(grep -Fxc -- "${needle}" "${file}") || status=$?', source)
        self.assertNotRegex(source, r"(?m)^\s*(?:source|\.)\s+.*manifest")
        self.assertNotIn("eval ", source)

    def test_rollback_stops_before_mutation_and_verifies_exact_activity(self):
        source = ROLLBACK.read_text(encoding="utf-8")
        stop = source.index("stop_unit_if_loaded()")
        restore = source.index('for path in "${snapshot_paths[@]}"', stop)
        self.assertLess(stop, restore)
        self.assertNotIn("systemctl stop campus-link-edge-a.service campus-link-edge-b.service campus-link-external.target >/dev/null 2>&1 || true", source)
        self.assertIn('if [[ ${load} != not-found ]]', source)
        self.assertIn('systemctl stop "${unit}" >/dev/null', source)
        self.assertIn("assert_unit_inactive", source)
        self.assertIn("active.campus-link-topology.service", source)
        self.assertIn("for unit in campus-link-topology.service campus-link-edge-a.service", source)
        marker = source.index('printf \'%s\\n\' "${transaction_id}" > "${SNAPSHOT}/.rolled-back"')
        verify = source.rindex('systemctl is-active --quiet "${unit}"', 0, marker)
        self.assertLess(verify, marker)


if __name__ == "__main__":
    unittest.main()

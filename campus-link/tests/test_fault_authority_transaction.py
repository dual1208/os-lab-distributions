import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def snapshot_paths(source: str) -> tuple[str, ...]:
    match = re.search(
        r"^readonly -a snapshot_paths=\(\n(?P<body>.*?)^\)$", source, re.M | re.S
    )
    if match is None:
        raise AssertionError("snapshot_paths is absent")
    return tuple(line.strip() for line in match.group("body").splitlines())


def embedded_python(source: str, marker: str) -> str:
    marker_index = source.index(marker)
    start = source.index("<<'PY'\n", marker_index) + len("<<'PY'\n")
    end = source.index("\nPY\n", start)
    return source[start:end]


class FaultAuthorityTransactionTests(unittest.TestCase):
    def test_edge_authority_mutates_only_after_snapshot_and_verified_release(self):
        installer = read("scripts/install-edge-lab.sh")
        preflight = installer.index("validate-gate-input")
        snapshot = installer.index("activate_snapshot\n", preflight)
        release = installer.index("verify_release", snapshot)
        permit = installer.index(".fault-authority-open", release)
        mutation = installer.index("gate-host", permit)
        final_validation = installer.index(
            'assert_relay_fault_access_bootstrap "${RELAY_ADDRESS}"', mutation
        )
        self.assertLess(preflight, snapshot)
        self.assertLess(snapshot, release)
        self.assertLess(release, permit)
        self.assertLess(permit, mutation)
        self.assertLess(mutation, final_validation)
        self.assertIn("/etc/campus-link/relay-fault", snapshot_paths(installer))
        provisioner = read("scripts/provision-relay-fault-access.sh")
        self.assertIn("require_transaction_snapshot edge", provisioner)
        self.assertIn("openssl genpkey -algorithm ED25519", provisioner)
        self.assertIn('"${PERMIT_PRIVATE_KEY}" 0600', provisioner)
        self.assertIn('"${PERMIT_PUBLIC_KEY}" 0600', provisioner)
        self.assertIn("PERMIT_PRIVATE_KEY_EXPORTED=0", provisioner)

    def test_orchestrator_does_not_mutate_gate_authority_before_installer(self):
        deploy = (REPO / "scripts" / "Deploy-CampusLink.ps1").read_text(encoding="utf-8")
        edge_command = re.search(r'\$edgeCommand = "(?P<body>.*?)"\n', deploy)
        self.assertIsNotNone(edge_command)
        body = edge_command.group("body")
        self.assertNotIn("provision-relay-fault-access.sh gate-host", body)
        self.assertIn(
            "install-edge-lab.sh /srv/openwrt-lab/repo '$relayAddress' '$relayHostKeyTemp'",
            body,
        )
        self.assertIn("trap 'rm -f --", body)
        self.assertIn(
            "/etc/campus-link/relay-fault/permit_ed25519.pub.pem", deploy
        )
        self.assertNotIn(
            'root@${labIp}:/etc/campus-link/relay-fault/permit_ed25519.pem"',
            deploy,
        )

    def test_orchestrator_retries_edge_rollback_after_an_interrupted_install(self):
        deploy = (REPO / "scripts" / "Deploy-CampusLink.ps1").read_text(encoding="utf-8")
        attempted = deploy.index("$edgeInstallAttempted = $true")
        invoke = deploy.index('& ssh "root@$labIp" $edgeCommand', attempted)
        prepared = deploy.index("$edgePrepared = $true", invoke)
        recovery_guard = deploy.index("if ($edgeInstallAttempted)", prepared)
        complete = deploy.index("`$snapshot/.complete", recovery_guard)
        rollback = deploy.index("rollback-edge.sh' '$transactionId'", complete)
        self.assertLess(attempted, invoke)
        self.assertLess(invoke, prepared)
        self.assertLess(prepared, recovery_guard)
        self.assertLess(recovery_guard, complete)
        self.assertLess(complete, rollback)

    def test_relay_authority_snapshot_and_rollback_are_exactly_symmetric(self):
        installer = read("scripts/install-relay.sh")
        rollback = read("scripts/rollback-relay.sh")
        self.assertEqual(snapshot_paths(installer), snapshot_paths(rollback))
        required = {
            "/etc/ssh/campus-link-relay-fault-authorized_keys",
            "/etc/ssh/sshd_config.d/90-campus-link-relay-fault.conf",
            "/etc/sudoers.d/campus-link-relay-fault",
            "/usr/local/libexec/campus-link-provision-relay-fault-access",
            "/usr/local/libexec/campus-link-relay-restart-authorized",
            "/usr/local/libexec/campus-link-relay-restart-actuator",
            "/usr/local/libexec/campus-link-relay-restart-permit-authorize",
            "/etc/ssh/campus-link-relay-fault-permit-ed25519.pub.pem",
        }
        self.assertEqual(required - set(snapshot_paths(installer)), set())

    def test_both_rollbacks_serialize_and_revoke_the_permit_before_restore(self):
        for relative in ("scripts/rollback-edge.sh", "scripts/rollback-relay.sh"):
            rollback = read(relative)
            lock = rollback.index("campus-link-provision-relay-fault.lock")
            close = rollback.index('rm -f -- "${SNAPSHOT}/.fault-authority-open"')
            restore = rollback.index('for path in "${snapshot_paths[@]}"', close)
            self.assertLess(lock, close)
            self.assertLess(close, restore)

    def test_relay_prior_state_and_inputs_validate_before_snapshot(self):
        installer = read("scripts/install-relay.sh")
        account = installer.index("validate-relay-account")
        baseline = installer.index("validate-relay-baseline")
        key_input = installer.index("validate-relay-input")
        snapshot = installer.index("activate_snapshot\n", key_input)
        self.assertLess(account, baseline)
        self.assertLess(baseline, key_input)
        self.assertLess(key_input, snapshot)

    def test_relay_mutation_is_inside_snapshot_and_permit(self):
        installer = read("scripts/install-relay.sh")
        snapshot = installer.index("activate_snapshot\n")
        permit = installer.index(".fault-authority-open", snapshot)
        mutation = installer.index(
            '\n    relay "${FAULT_PUBLIC_KEY}" "${PERMIT_PUBLIC_KEY}"', permit
        )
        validation = installer.index("validate-relay-state", mutation)
        self.assertLess(snapshot, permit)
        self.assertLess(permit, mutation)
        self.assertLess(mutation, validation)
        provisioner = read("scripts/provision-relay-fault-access.sh")
        self.assertIn("require_transaction_snapshot relay", provisioner)

    def test_relay_rollback_revalidates_and_reloads_before_commit_marker(self):
        rollback = read("scripts/rollback-relay.sh")
        permit_close = rollback.index('rm -f -- "${SNAPSHOT}/.fault-authority-open"')
        restore = rollback.index('for path in "${snapshot_paths[@]}"', permit_close)
        sudo = rollback.index("visudo -cf /etc/sudoers", restore)
        ssh = rollback.index("sshd -t", sudo)
        reload = rollback.index("systemctl reload", ssh)
        marker = rollback.index('> "${SNAPSHOT}/.rolled-back"', reload)
        self.assertLess(permit_close, restore)
        self.assertLess(restore, sudo)
        self.assertLess(sudo, ssh)
        self.assertLess(ssh, reload)
        self.assertLess(reload, marker)

    def test_account_bootstrap_is_inert_and_never_rewrites_existing_account(self):
        provisioner = read("scripts/provision-relay-fault-access.sh")
        bootstrap = provisioner[
            provisioner.index("bootstrap_fault_account()") : provisioner.index(
                "render_authorized_keys()"
            )
        ]
        existing = bootstrap.index("validate_fault_account")
        early_return = bootstrap.index("return", existing)
        create = bootstrap.index("groupadd --system", early_return)
        password = bootstrap.index("usermod --password '*NP*'", create)
        self.assertLess(existing, early_return)
        self.assertLess(early_return, create)
        self.assertLess(create, password)
        self.assertIn("AUTHORITY_INSTALLED=0", bootstrap)
        self.assertIn('[[ ! -e ${path} && ! -L ${path} ]]', bootstrap)
        self.assertIn("remove_new_fault_account", bootstrap)
        self.assertIn("usermod --password '*NP*'", bootstrap)
        self.assertIn('last_day=$(date -u +%Y-%m-%d) || return 1', bootstrap)
        self.assertIn('chage --lastday "${last_day}"', bootstrap)
        self.assertIn("--mindays 0 --maxdays 99999", bootstrap)
        self.assertIn("--warndays 7 --inactive -1 --expiredate -1", bootstrap)

        validator = provisioner[
            provisioner.index("validate_fault_account()") : provisioner.index(
                "remove_new_fault_account()"
            )
        ]
        for field in (
            "shadow_password} == '*NP*'",
            "shadow_last_change <= today_days",
            "shadow_min} == 0",
            "shadow_max} == 99999",
            "shadow_warn} == 7",
            "-z ${shadow_inactive}",
            "-z ${shadow_expire}",
            "-z ${shadow_reserved}",
        ):
            self.assertIn(field, validator)

    def test_effective_ssh_policy_excludes_alternate_public_key_sources(self):
        provisioner = read("scripts/provision-relay-fault-access.sh")
        for directive in (
            "AuthorizedKeysCommand none",
            "AuthorizedPrincipalsCommand none",
            "AuthorizedPrincipalsFile none",
            "TrustedUserCAKeys none",
            "ForceCommand /usr/local/libexec/campus-link-relay-restart-authorized",
            "Match all",
        ):
            self.assertIn(directive, provisioner)
        self.assertIn("validate_effective_sshd_policy()", provisioner)
        self.assertGreaterEqual(
            provisioner.count('validate_effective_sshd_policy "${'), 2
        )
        rendered = provisioner[
            provisioner.index("render_sshd_drop_in()") : provisioner.index(
                "render_sudoers()"
            )
        ]
        self.assertNotIn("PermitUserEnvironment", rendered)
        self.assertIn("permituserenvironment no", provisioner)
        self.assertIn("validate_effective_environment_policy", provisioner)
        self.assertIn("[[ ${token} == LANG || ${token} == 'LC_*' ]]", provisioner)
        self.assertIn("setenv) return 1", provisioner)
        self.assertIn("enumerate_sshd_connection_contexts()", provisioner)
        self.assertIn("validate_effective_sshd_environment_contexts()", provisioner)
        self.assertIn(
            '"user=campus-link-fault,"',
            provisioner,
        )
        self.assertIn('f"host={source},addr={source},laddr={local_address},lport={port}"', provisioner)
        self.assertIn('use_dns != ["usedns no"]', provisioner)
        installer = read("scripts/install-relay.sh")
        self.assertIn(
            'validate-relay-baseline "${FAULT_SOURCE_CIDR}"', installer
        )

    def test_relay_sudo_and_helpers_are_exact_and_environment_safe(self):
        provisioner = read("scripts/provision-relay-fault-access.sh")
        sudo = provisioner[
            provisioner.index("render_sudoers()") : provisioner.index(
                "validate_privileged_helper()"
            )
        ]
        self.assertIn('"${ACTUATOR}"', sudo)
        self.assertIn('"${PERMIT_AUTHORIZER}"', sudo)
        self.assertIn("NOPASSWD:NOSETENV:", sudo)
        self.assertIn("ALL=(root:root)", sudo)
        self.assertIn(' %s ""\\n', sudo)
        self.assertIn("Defaults!%s !use_pty, !requiretty, !log_input, !log_output", sudo)
        for flag in ("!log_stdin", "!log_stdout", "!log_stderr", "!log_ttyin", "!log_ttyout"):
            self.assertIn(flag, sudo)
        self.assertIn('env_reset, secure_path="%s"', sudo)
        self.assertIn('env_keep = "%s"', sudo)
        self.assertIn('env_check = "%s"', sudo)
        self.assertIn('env_delete += "%s"', sudo)
        self.assertIn("!env_file", sudo)
        self.assertIn("!restricted_env_file", sudo)
        self.assertNotIn(' %s *\\n', sudo)
        self.assertNotIn("render_legacy_sudoers", provisioner)
        self.assertNotIn("/bin/sh", sudo)
        self.assertNotIn("ALL=(ALL)", sudo)
        self.assertIn("#!/bin/bash -p", provisioner)
        self.assertIn("[[ -z ${BASH_ENV+x} && -z ${ENV+x} ]]", provisioner)

        installer = read("scripts/install-relay.sh")
        self.assertIn("relay-restart-permit-authorize.sh", installer)
        self.assertIn(
            "verify_manifest_entry scripts/relay-restart-permit-authorize.sh",
            installer,
        )
        self.assertIn("validate_effective_sudo_policy", provisioner)
        self.assertIn("validate_zero_argument_helper", provisioner)
        self.assertIn("grep -Fxq '[[ $# -eq 0 ]]'", provisioner)
        self.assertIn("OPENSSL_CONF", provisioner)
        self.assertIn("OPENSSL_MODULES", provisioner)
        self.assertIn("OPENSSL_ENGINES", provisioner)
        self.assertIn("LD_*", provisioner)
        self.assertIn("grep -Fxq 'sanitize_environment'", provisioner)
        self.assertIn('/usr/bin/sudo -n -ll -U "${FAULT_USER}"', provisioner)
        self.assertIn("CAMPUS_LINK_EFFECTIVE_SUDO_POLICY_PARSER", provisioner)
        self.assertNotIn('sudo -n -l -U "${FAULT_USER}" --', provisioner)
        rollback = read("scripts/rollback-relay.sh")
        self.assertIn("Defaults!%s !use_pty, !requiretty, !log_input, !log_output", rollback)
        self.assertIn("!log_stdin", rollback)
        self.assertIn("!env_file", rollback)
        self.assertIn("!restricted_env_file", rollback)
        self.assertIn('env_keep = "%s"', rollback)
        self.assertIn('env_check = "%s"', rollback)
        self.assertIn("validate_effective_sudo_policy", rollback)

    def test_deploy_bootstraps_account_then_passes_authority_into_installer(self):
        deploy = (REPO / "scripts" / "Deploy-CampusLink.ps1").read_text(encoding="utf-8")
        transfer = deploy.index("Could not transfer the gate public key to the relay transaction input")
        permit_transfer = deploy.index(
            "Could not transfer the gate permit public key to the relay transaction input",
            transfer,
        )
        bootstrap = deploy.index("bootstrap-relay-account", permit_transfer)
        install = deploy.index("/bin/bash '$remoteStage/install-relay.sh'", bootstrap)
        validate = deploy.index("campus-link-provision-relay-fault-access relay-state", install)
        self.assertLess(transfer, permit_transfer)
        self.assertLess(permit_transfer, bootstrap)
        self.assertLess(bootstrap, install)
        self.assertLess(install, validate)
        self.assertIn(
            "'$relayFaultPublicTemp' '$relayPermitPublicTemp' '${labIp}/32'",
            deploy[install:validate],
        )

    def test_relay_rollback_checks_effective_environment_policy(self):
        rollback = read("scripts/rollback-relay.sh")
        syntax = rollback.index("sshd -t")
        matrix = rollback.index("validate_restored_effective_sshd_contexts", syntax)
        reload_ssh = rollback.index("systemctl reload", matrix)
        self.assertLess(syntax, matrix)
        self.assertLess(matrix, reload_ssh)
        self.assertIn("permituserenvironment no", rollback)
        self.assertIn("fault_source_address=$(restored_fault_source_address)", rollback)
        self.assertIn("validate_restored_effective_sshd_policy", rollback)
        self.assertIn("enumerate_sshd_connection_contexts", rollback)
        self.assertIn("laddr={local_address},lport={port}", rollback)
        self.assertIn('use_dns != ["usedns no"]', rollback)

    def test_effective_environment_validator_is_an_exact_locale_allowlist(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        provisioner = read("scripts/provision-relay-fault-access.sh")
        helper_start = provisioner.index("collect_extended_matches()")
        helper_end = provisioner.index("\n}\n", helper_start) + 3
        helper = provisioner[helper_start:helper_end]
        start = provisioner.index("validate_effective_environment_policy()")
        end = provisioner.index("\n\nenumerate_sshd_connection_contexts()", start)
        function = provisioner[start:end]

        for safe in (
            "permituserenvironment no",
            "permituserenvironment no\nacceptenv LANG",
            "permituserenvironment no\nacceptenv LC_*",
            "permituserenvironment no\nacceptenv LANG LC_*",
        ):
            completed = subprocess.run(
                [
                    bash,
                    "-c",
                    f"set -euo pipefail\n{helper}\n{function}\n"
                    'validate_effective_environment_policy "$1"',
                    "--",
                    safe,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

        for unsafe in (
            "acceptenv BASH_*",
            "acceptenv *",
            "acceptenv L*",
            "acceptenv LC_?",
            "acceptenv LANGUAGE",
            "setenv SAFE=value",
            "setenv LD_LIBRARY_PATH=/tmp",
        ):
            rendered = f"permituserenvironment no\n{unsafe}"
            completed = subprocess.run(
                [
                    bash,
                    "-c",
                    f"set -euo pipefail\n{helper}\n{function}\nvalidate_effective_environment_policy \"$1\"",
                    "--",
                    rendered,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, unsafe)

        completed = subprocess.run(
            [
                bash,
                "-c",
                f"set -euo pipefail\n{function}\n"
                'validate_effective_environment_policy "$1"',
                "--",
                "permituserenvironment yes\nacceptenv LANG",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)

    def test_effective_sudo_parser_accepts_only_closed_merged_policy(self):
        provisioner = read("scripts/provision-relay-fault-access.sh")
        parser = embedded_python(
            provisioner, "CAMPUS_LINK_EFFECTIVE_SUDO_POLICY_PARSER"
        )
        self.assertEqual(
            parser,
            embedded_python(
                read("scripts/rollback-relay.sh"),
                "CAMPUS_LINK_EFFECTIVE_SUDO_POLICY_PARSER",
            ),
        )
        actuator = "/usr/local/libexec/campus-link-relay-restart-actuator"
        authorizer = "/usr/local/libexec/campus-link-relay-restart-permit-authorize"
        sudoers = "/etc/sudoers.d/campus-link-relay-fault"
        secure_path = "/usr/sbin:/usr/bin:/sbin:/bin"
        inert = "CAMPUS_LINK_SUDO_EMPTY"
        env_delete_match = re.search(
            r"^readonly SUDO_ENV_DELETE='([^']+)'$", provisioner, re.M
        )
        self.assertIsNotNone(env_delete_match)
        env_delete = env_delete_match.group(1)

        def defaults(command: str) -> str:
            return (
                f"    Defaults!{command} !use_pty, !requiretty, !log_input, !log_output, "
                "!log_stdin, !log_stdout, !log_stderr, !log_ttyin, !log_ttyout, "
                "!env_file, !restricted_env_file, env_reset, "
                r"secure_path=/usr/sbin\:/usr/bin\:/sbin\:/bin, "
                f'env_keep="{inert}", env_check="{inert}", '
                f'env_delete+="{env_delete}"'
            )

        def entry(command: str, source: str = sudoers) -> str:
            return (
                f"Sudoers entry: {source}\n"
                "    RunAsUsers: root\n"
                "    RunAsGroups: root\n"
                "    Options: !setenv, !authenticate\n"
                "    Commands:\n"
                f'        {command} ""\n'
            )

        listing = (
            "Matching Defaults entries for campus-link-fault on relay:\n"
            "    env_reset, use_pty\n\n"
            "Runas and Command-specific defaults for campus-link-fault:\n"
            f"{defaults(actuator)}\n{defaults(authorizer)}\n\n"
            "User campus-link-fault may run the following commands on relay:\n\n"
            f"{entry(actuator)}\n{entry(authorizer)}"
        )

        def run(candidate: str | bytes) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "sudo-listing"
                if isinstance(candidate, bytes):
                    path.write_bytes(candidate)
                else:
                    path.write_text(candidate, encoding="utf-8", newline="")
                return subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        parser,
                        str(path),
                        "campus-link-fault",
                        sudoers,
                        secure_path,
                        inert,
                        env_delete,
                        actuator,
                        authorizer,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

        completed = run(listing)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = run(listing.replace(f"Sudoers entry: {sudoers}", "Sudoers entry:"))
        self.assertEqual(completed.returncode, 0, completed.stderr)

        mutations = {
            "extra grant": listing + "\n" + entry("/bin/sh"),
            "broad grant": listing.replace(f'{actuator} ""', "ALL", 1),
            "helper arguments": listing.replace(f'{actuator} ""', f"{actuator} *", 1),
            "setenv tag": listing.replace("!setenv, !authenticate", "setenv, !authenticate", 1),
            "missing nopasswd": listing.replace("!setenv, !authenticate", "!setenv, authenticate", 1),
            "runas group": listing.replace(
                "    RunAsGroups: root\n",
                "    RunAsGroups: ALL\n",
                1,
            ),
            "wrong grant source": listing.replace(
                f"Sudoers entry: {sudoers}", "Sudoers entry: /etc/sudoers", 1
            ),
            "external policy source": listing.replace(
                f"Sudoers entry: {sudoers}", "LDAP Role: relay-admin", 1
            ),
            "logging re-enabled": listing.replace("!log_stdin", "log_stdin", 1),
            "pty re-enabled": listing.replace("!use_pty", "use_pty", 1),
            "tty required": listing.replace("!requiretty", "requiretty", 1),
            "trusted env file": listing.replace("!env_file", "env_file=/tmp/injected", 1),
            "preserved dangerous env": listing.replace(
                f'env_keep="{inert}"', 'env_keep="BASH_ENV"', 1
            ),
            "extra command default": listing.replace(
                "User campus-link-fault may run",
                "    Defaults!/bin/true !use_pty\n\nUser campus-link-fault may run",
                1,
            ),
        }
        for name, candidate in mutations.items():
            with self.subTest(name=name):
                completed = run(candidate)
                self.assertNotEqual(completed.returncode, 0, completed.stderr)
        for name, candidate in (
            ("nul", listing.encode() + b"\x00"),
            ("crlf", listing.replace("\n", "\r\n").encode()),
            ("invalid utf8", listing.encode() + b"\xff"),
        ):
            with self.subTest(name=name):
                completed = run(candidate)
                self.assertNotEqual(completed.returncode, 0, completed.stderr)

    def test_sshd_context_enumerator_covers_actual_listener_matrix(self):
        provisioner = read("scripts/provision-relay-fault-access.sh")
        rollback = read("scripts/rollback-relay.sh")
        parser = embedded_python(provisioner, "CAMPUS_LINK_SSHD_CONTEXT_ENUMERATOR")
        self.assertEqual(
            parser, embedded_python(rollback, "CAMPUS_LINK_SSHD_CONTEXT_ENUMERATOR")
        )

        addresses = [
            {
                "ifname": "lo",
                "addr_info": [
                    {"family": "inet", "local": "127.0.0.1"},
                    {"family": "inet6", "local": "::1"},
                ],
            },
            {
                "ifname": "eth0",
                "addr_info": [
                    {"family": "inet", "local": "192.0.2.10"},
                    {"family": "inet6", "local": "2001:db8::10"},
                ],
            },
        ]

        def run(base: str, inventory: object = addresses, source: str = "198.51.100.7"):
            with tempfile.TemporaryDirectory() as directory:
                base_path = Path(directory) / "sshd-T"
                address_path = Path(directory) / "addresses.json"
                base_path.write_text(base, encoding="utf-8", newline="")
                address_path.write_text(json.dumps(inventory), encoding="utf-8")
                return subprocess.run(
                    [sys.executable, "-c", parser, source, str(base_path), str(address_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                )

        completed = run(
            "usedns no\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:22\n"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines(),
            [
                "user=campus-link-fault,host=198.51.100.7,addr=198.51.100.7,laddr=127.0.0.1,lport=22",
                "user=campus-link-fault,host=198.51.100.7,addr=198.51.100.7,laddr=192.0.2.10,lport=22",
            ],
        )
        completed = run(
            "usedns no\nlistenaddress 192.0.2.10:22\nlistenaddress 192.0.2.10:2222\n"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines(),
            [
                "user=campus-link-fault,host=198.51.100.7,addr=198.51.100.7,laddr=192.0.2.10,lport=22",
                "user=campus-link-fault,host=198.51.100.7,addr=198.51.100.7,laddr=192.0.2.10,lport=2222",
            ],
        )

        failures = {
            "reverse-name ambiguity": "usedns yes\nlistenaddress 0.0.0.0:22\n",
            "missing usedns": "listenaddress 0.0.0.0:22\n",
            "hostname listener": "usedns no\nlistenaddress relay.example:22\n",
            "missing local listener address": "usedns no\nlistenaddress 192.0.2.99:22\n",
            "invalid port": "usedns no\nlistenaddress 0.0.0.0:0\n",
            "no same-family endpoint": "usedns no\nlistenaddress [::]:22\n",
        }
        for name, base in failures.items():
            with self.subTest(name=name):
                completed = run(base)
                self.assertNotEqual(completed.returncode, 0, completed.stderr)

        for source in (provisioner, rollback):
            self.assertIn('ip -j address show > "${address_file}"', source)
            self.assertIn('rendered=$(sshd -T -C "${context}")', source)
            self.assertIn("laddr={local_address},lport={port}", source)
            self.assertNotIn("host=${source_address},addr=${source_address}\"", source)

    def test_fault_account_validator_rejects_expiry_and_shadow_drift(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        provisioner = read("scripts/provision-relay-fault-access.sh")
        start = provisioner.index("validate_fault_account()")
        end = provisioner.index("\n\nremove_new_fault_account()", start)
        function = provisioner[start:end]
        harness = f"""set -euo pipefail
FAULT_USER=campus-link-fault
MOCK_SHADOW=$1
GETENT_FAILURE=${{2:-none}}
getent() {{
  case $1:$2 in
    group:campus-link-fault) printf '%s\\n' 'campus-link-fault:x:4242:' ;;
    passwd:campus-link-fault) printf '%s\\n' 'campus-link-fault:x:4242:4242::/nonexistent:/bin/sh' ;;
    shadow:campus-link-fault) printf '%s\\n' "${{MOCK_SHADOW}}" ;;
    *) return 1 ;;
  esac
  [[ $GETENT_FAILURE != "$1" ]]
}}
id() {{
  case $1 in
    -gn) printf '%s\\n' campus-link-fault ;;
    -G) printf '%s\\n' 4242 ;;
    *) return 1 ;;
  esac
}}
date() {{
  [[ $1 == -u && $2 == +%s ]]
  printf '%s\\n' 1728000000
}}
{function}
if validate_fault_account; then
  exit 0
fi
exit 1
"""

        valid = "campus-link-fault:*NP*:20000:0:99999:7:::"
        completed = subprocess.run(
            [bash, "-c", harness, "--", valid],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for invalid in (
            "campus-link-fault:*NP*:20000:0:99999:7::19999:",
            "campus-link-fault:*NP*:20001:0:99999:7:::",
            "campus-link-fault:*NP*:20000:0:90:7:::",
            "campus-link-fault:!:20000:0:99999:7:::",
        ):
            completed = subprocess.run(
                [bash, "-c", harness, "--", invalid],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, invalid)
        for record_kind in ("group", "passwd", "shadow"):
            completed = subprocess.run(
                [bash, "-c", harness, "--", valid, record_kind],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, record_kind)

    def test_restored_fault_source_parser_fails_closed_in_command_substitution(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        rollback = read("scripts/rollback-relay.sh")
        start = rollback.index("restored_fault_source_address()")
        end = rollback.index("\n\nrender_current_fault_sudoers()", start)
        function = rollback[start:end]
        harness = f"""set -euo pipefail
SOURCE_CIDR=$1
VALIDATOR_STATUS=$2
WC_STATUS=$3
AUTHORIZED_KEYS=$(mktemp)
trap 'rm -f -- "${{AUTHORIZED_KEYS}}"' EXIT
printf 'restrict,from="%s",command="/usr/local/libexec/campus-link-relay-restart-authorized" ssh-ed25519 AAAA campus-link-relay-fault\n' \
  "${{SOURCE_CIDR}}" > "${{AUTHORIZED_KEYS}}"
require_root_regular_file() {{ return "${{VALIDATOR_STATUS}}"; }}
wc() {{ printf '1\n'; return "${{WC_STATUS}}"; }}
{function}
if value=$(restored_fault_source_address); then
  printf '%s\n' "${{value}}"
  exit 0
fi
exit 1
"""

        valid = subprocess.run(
            [bash, "-c", harness, "--", "127.0.0.1/32", "0", "0"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(valid.stdout.strip(), "127.0.0.1")
        for source_cidr, validator_status, wc_status in (
            ("127.0.0.1/32", "1", "0"),
            ("127.0.0.1/32", "0", "9"),
            ("127.0.0.0/24", "0", "0"),
        ):
            completed = subprocess.run(
                [
                    bash,
                    "-c",
                    harness,
                    "--",
                    source_cidr,
                    validator_status,
                    wc_status,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(
                completed.returncode,
                0,
                f"source={source_cidr} validator={validator_status} wc={wc_status}",
            )

    def test_preserved_ledger_waits_for_enumerator_status(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        for relative in ("scripts/install-relay.sh", "scripts/rollback-relay.sh"):
            with self.subTest(relative=relative):
                source = read(relative)
                helper_start = source.index("list_directory_paths()")
                helper_end = source.index("\n}\n", helper_start) + 3
                helper = source[helper_start:helper_end]
                start = source.index("validate_preserved_used_ledger()")
                end = source.index("\n\nquarantine_pending_permit()", start)
                function = source[start:end]
                harness = f"""set -euo pipefail
FIND_STATUS=$1
USED_DIR=$(mktemp -d)
MAX_LEDGER_ENTRIES=4096
trap 'rm -rf -- "${{USED_DIR}}"' EXIT
real_mktemp=$(command -v mktemp)
mktemp() {{ "${{real_mktemp}}"; }}
require_root_directory() {{ return 0; }}
require_root_regular_file() {{ return 0; }}
find() {{
  printf '%s\\0' "${{1}}/0123456789abcdef0123456789abcdef"
  return "${{FIND_STATUS}}"
}}
{helper}
{function}
if validate_preserved_used_ledger; then
  exit 0
fi
exit 1
"""
                valid = subprocess.run(
                    [bash, "-c", harness, "--", "0"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(valid.returncode, 0, valid.stderr)
                failed = subprocess.run(
                    [bash, "-c", harness, "--", "7"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(failed.returncode, 0)

    def test_staged_pki_allowlist_waits_for_enumerator_status(self):
        bash = shutil.which("bash")
        if bash is None:
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
        if bash is None:
            self.skipTest("bash is unavailable")
        source = read("scripts/install-relay.sh")
        start = source.index("assert_relay_pki_allowlist()")
        end = source.index("\n}\n", start) + 3
        function = source[start:end]
        self.assertIn('if ! find "${ROOT}/pki"', function)
        self.assertIn('read_complete_line_inventory "${inventory}" entries', function)
        reader_start = source.index("read_complete_line_inventory()")
        reader_end = source.index("\n}\n", reader_start) + 3
        reader = source[reader_start:reader_end]
        harness = f"""set -euo pipefail
FIND_STATUS=$1
ROOT=$(mktemp -d)
trap 'rm -rf -- "${{ROOT}}"' EXIT
mkdir "${{ROOT}}/pki"
touch "${{ROOT}}/pki/control-ca.crt"
find() {{
  printf 'control-ca.crt\\n'
  return "${{FIND_STATUS}}"
}}
{reader}
{function}
assert_relay_pki_allowlist 0
"""
        valid = subprocess.run(
            [bash, "-c", harness, "--", "0"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        failed = subprocess.run(
            [bash, "-c", harness, "--", "7"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(failed.returncode, 0)

    def test_relay_mutations_share_lock_order_and_revoke_pending_permits(self):
        installer = read("scripts/install-relay.sh")
        transaction = installer.index('exec 9<>"${TRANSACTION_LOCK}"')
        actuator = installer.index('exec 7<>"${ACTUATOR_LOCK}"', transaction)
        preflight = installer.index("validate-relay-baseline", actuator)
        quarantine = installer.index("\nquarantine_pending_permit\n", preflight)
        snapshot = installer.index("\nactivate_snapshot\n", quarantine)
        self.assertLess(transaction, actuator)
        self.assertLess(actuator, preflight)
        self.assertLess(preflight, quarantine)
        self.assertLess(quarantine, snapshot)
        self.assertIn("CAMPUS_LINK_INHERITED_RELAY_MUTATION_LOCKS=1", installer)

        rollback = read("scripts/rollback-relay.sh")
        independent = rollback.index('exec 9<>"${TRANSACTION_LOCK}"')
        rollback_actuator = rollback.index('exec 7<>"${ACTUATOR_LOCK}"', independent)
        authority = rollback.index('exec 8<>"${AUTHORITY_LOCK}"', rollback_actuator)
        rollback_quarantine = rollback.index("\nquarantine_pending_permit\n", authority)
        restore = rollback.index('for path in "${snapshot_paths[@]}"', rollback_quarantine)
        self.assertLess(independent, rollback_actuator)
        self.assertLess(rollback_actuator, authority)
        self.assertLess(authority, rollback_quarantine)
        self.assertLess(rollback_quarantine, restore)
        for source in (installer, rollback):
            quarantine_function = source[
                source.index("quarantine_pending_permit()") : source.index(
                    "\n}\n", source.index("quarantine_pending_permit()")
                )
                + 3
            ]
            self.assertIn('mv -T -- "${EXPECTED_PERMIT}" "${destination}"', quarantine_function)
            self.assertIn("validate_preserved_used_ledger", quarantine_function)
            self.assertIn('list_directory_paths revoked "${REVOKED_DIR}" || return 1', quarantine_function)
            self.assertNotRegex(quarantine_function, r"(?:rm|mv)[^\n]*USED_DIR")
        fault_state = "/var/lib/campus-link-relay-fault"
        self.assertNotIn(fault_state, snapshot_paths(installer))
        self.assertNotIn(fault_state, snapshot_paths(rollback))

    def test_gate_transport_is_manifest_bound_and_never_relay_staged(self):
        installer = read("scripts/install-edge-lab.sh")
        rollback = read("scripts/rollback-edge.sh")
        transport = "/usr/local/libexec/campus-link-relay-restart-transport"
        self.assertIn(transport, snapshot_paths(installer))
        self.assertEqual(snapshot_paths(installer), snapshot_paths(rollback))
        self.assertIn(
            'atomic_install "${RELEASE}/scripts/relay-restart-transport.sh"',
            installer,
        )
        self.assertIn(
            "${release}/scripts/relay-restart-transport.sh", installer
        )
        evidence = read("scripts/gate-evidence.sh")
        self.assertIn(transport, evidence)

        deploy = (REPO / "scripts" / "Deploy-CampusLink.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "verify scripts/relay-restart-transport.sh "
            "/usr/local/libexec/campus-link-relay-restart-transport",
            deploy,
        )
        names = re.search(r"\$names = @\((?P<body>.*?)\n\)", deploy, re.S)
        self.assertIsNotNone(names)
        self.assertNotIn("relay-restart-transport", names.group("body"))
        self.assertNotIn("relay-restart-transport", read("scripts/install-relay.sh"))


if __name__ == "__main__":
    unittest.main()

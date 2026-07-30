#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import campus_link_rotation_state as state  # noqa: E402


GATE_SPEC = importlib.util.spec_from_file_location(
    "certificate_rotation_gate_for_driver", HERE / "certificate_rotation_gate.py"
)
assert GATE_SPEC is not None and GATE_SPEC.loader is not None
gate = importlib.util.module_from_spec(GATE_SPEC)
GATE_SPEC.loader.exec_module(gate)

DRIVER = SCRIPTS / "certificate_rotation_driver.py"
SEALER = SCRIPTS / "certificate_rotation_manifest.py"
RUN_ID = "1" * 32
CANDIDATE = "2" * 64
RUN_MANIFEST = "3" * 64
PREREQUISITE = "4" * 64
ROTATION_ID = "5" * 32


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + der_length(len(content)) + content


def sequence(*children: bytes) -> bytes:
    return tlv(0x30, b"".join(children))


def fake_certificate(seed: int) -> tuple[bytes, str]:
    algorithm = sequence(tlv(0x06, b"\x2a\x03"))
    spki = sequence(algorithm, tlv(0x03, b"\x00" + bytes((seed,)) * 33))
    tbs = sequence(
        tlv(0x02, bytes((seed,))),
        algorithm,
        sequence(),
        sequence(),
        sequence(),
        spki,
    )
    certificate = sequence(tbs, algorithm, tlv(0x03, b"\x00\x01"))
    payload = base64.b64encode(certificate)
    pem = b"-----BEGIN CERTIFICATE-----\n" + payload + b"\n-----END CERTIFICATE-----\n"
    pin = "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
    return pem, pin


def auth(uri: str, current: str, following: str | None) -> dict[str, str]:
    value = {"uri": uri, "current_spki": current}
    if following is not None:
        value["next_spki"] = following
    return value


def config_artifacts(
    assignments: dict[str, dict[str, str]], slot: str, following: str | None
) -> dict[str, bytes]:
    uris = {
        "relay-control": "spiffe://campus-link/home-pair-1/relay/control",
        "site-a-control": "spiffe://campus-link/home-pair-1/site-a/control",
        "site-a-data": "spiffe://campus-link/home-pair-1/site-a/data",
        "site-b-control": "spiffe://campus-link/home-pair-1/site-b/control",
        "site-b-data": "spiffe://campus-link/home-pair-1/site-b/data",
    }

    def selected(identity: str) -> dict[str, str]:
        next_pin = assignments[identity][following] if following is not None else None
        return auth(uris[identity], assignments[identity][slot], next_pin)

    relay = {
        "component": "relay",
        "local_control_identity": selected("relay-control"),
        "control_identities": {
            "site-a": selected("site-a-control"),
            "site-b": selected("site-b-control"),
        },
    }
    edge_a = {
        "component": "edge-a",
        "local_control_identity": selected("site-a-control"),
        "control_identity": selected("relay-control"),
        "local_data_identity": selected("site-a-data"),
        "data_identity": selected("site-b-data"),
    }
    edge_b = {
        "component": "edge-b",
        "local_control_identity": selected("site-b-control"),
        "control_identity": selected("relay-control"),
        "local_data_identity": selected("site-b-data"),
        "data_identity": selected("site-a-data"),
    }
    return {
        "relay.config": state.canonical_json(relay),
        "edge-a.config": state.canonical_json(edge_a),
        "edge-b.config": state.canonical_json(edge_b),
    }


def mkdir(path: pathlib.Path) -> None:
    path.mkdir()
    os.chmod(path, 0o700)


def write_mode(path: pathlib.Path, raw: bytes, mode: int) -> None:
    if path.exists() and not path.is_symlink():
        os.chmod(path, 0o600)
    path.write_bytes(raw)
    os.chmod(path, mode)


class Fixture:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.layout = self._directories()
        self.assignments, self.rows = self._rows()
        write_mode(
            self.layout.rotation_root / "identity-assignments.json",
            state.canonical_json(self.assignments),
            0o400,
        )
        for state_name in state.STATES:
            row_dir = self.layout.rows / state_name
            mkdir(row_dir)
            for artifact in state.ARTIFACTS:
                write_mode(row_dir / artifact, self.rows[state_name][artifact], 0o400)
        self.environment = dict(os.environ)
        self.environment["CAMPUS_LINK_ROTATION_TEST_ROOT"] = str(root)
        completed = subprocess.run(
            [sys.executable, str(SEALER), "seal", "--mode", "isolated-test"],
            env=self.environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
        self.manifest_sha256 = hashlib.sha256(self.layout.manifest.read_bytes()).hexdigest()
        for artifact in state.ARTIFACTS:
            write_mode(self.layout.live / artifact, self.rows["pre"][artifact], 0o600)
        service = {
            "format": 1,
            "service_invocations": {component: 1 for component in state.COMPONENTS},
            "control_sessions": {edge: 10 for edge in state.EDGES},
            "direct_instances": {edge: 20 for edge in state.EDGES},
            "slots": {observer: "current" for observer in state.OBSERVERS},
            "direct_healthy": True,
            "selected_instance_binding_verified": True,
            "stream_records": {"a-to-b": 100, "b-to-a": 101},
            "stream_digests": {
                "a-to-b": hashlib.sha256(b"fixture-a").hexdigest(),
                "b-to-a": hashlib.sha256(b"fixture-b").hexdigest(),
            },
            "sequence_errors": 0,
            "duplicate_records": 0,
            "start_limit_lockouts": 0,
        }
        write_mode(
            self.layout.rotation_root / "fixture-services.json",
            state.canonical_json(service),
            0o600,
        )
        self.started = state.monotonic_ms()
        active = (
            "FORMAT=1\n"
            "STATUS=active\n"
            "GATE=certificate-rotation\n"
            "MODE=isolated-test\n"
            f"RUN_ID={RUN_ID}\n"
            f"CANDIDATE_SHA256={CANDIDATE}\n"
            f"RUN_MANIFEST_SHA256={RUN_MANIFEST}\n"
            f"PREREQUISITE_MARKER_SHA256={PREREQUISITE}\n"
            f"ROTATION_ID={ROTATION_ID}\n"
            f"ROTATION_MANIFEST_SHA256={self.manifest_sha256}\n"
            f"START_MONOTONIC_MS={self.started}\n"
        ).encode("ascii")
        write_mode(self.layout.active, active, 0o600)
        self.active_sha256 = hashlib.sha256(active).hexdigest()
        self.work = self.layout.run_root / f".certificate-rotation.{ROTATION_ID}.ABC123"
        mkdir(self.work)

    def _directories(self) -> state.Layout:
        current = self.root
        for name in ("var", "lib", "campus-link", "rotation"):
            current = current / name
            mkdir(current)
        rows = current / "rows"
        live = current / "live"
        transactions = current / "transactions"
        mkdir(rows)
        mkdir(live)
        mkdir(transactions)
        current_run = self.root
        for name in ("run", "campus-link"):
            current_run = current_run / name
            mkdir(current_run)
        os.environ["CAMPUS_LINK_ROTATION_TEST_ROOT"] = str(self.root)
        try:
            return state.layout("isolated-test")
        finally:
            os.environ.pop("CAMPUS_LINK_ROTATION_TEST_ROOT", None)

    def _rows(self) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, bytes]]]:
        certificates: dict[str, dict[str, bytes]] = {}
        assignments: dict[str, dict[str, str]] = {}
        for index, identity in enumerate(state.IDENTITIES, start=1):
            current_cert, current_pin = fake_certificate(index)
            next_cert, next_pin = fake_certificate(index + 16)
            certificates[identity] = {"current": current_cert, "next": next_cert}
            assignments[identity] = {"current": current_pin, "next": next_pin}
        configs = {
            "pre": config_artifacts(assignments, "current", None),
            "overlap": config_artifacts(assignments, "current", "next"),
            "post": config_artifacts(assignments, "next", None),
        }
        keys = {
            identity: {
                "current": f"fixture-{identity}-current\n".encode("ascii"),
                "next": f"fixture-{identity}-next\n".encode("ascii"),
            }
            for identity in state.IDENTITIES
        }
        result: dict[str, dict[str, bytes]] = {}
        for state_name in state.STATES:
            config_slot = "pre" if state_name == "pre" else "post" if state_name == "post" else "overlap"
            relay_slot = "next" if state.STATES.index(state_name) >= state.STATES.index("relay-next") else "current"
            edge_a_slot = "next" if state.STATES.index(state_name) >= state.STATES.index("edge-a-next") else "current"
            edge_b_slot = "next" if state.STATES.index(state_name) >= state.STATES.index("edge-b-next") else "current"
            row = dict(configs[config_slot])
            row.update(
                {
                    "relay.control-cert": certificates["relay-control"][relay_slot],
                    "relay.control-key": keys["relay-control"][relay_slot],
                    "edge-a.control-cert": certificates["site-a-control"][edge_a_slot],
                    "edge-a.control-key": keys["site-a-control"][edge_a_slot],
                    "edge-a.data-cert": certificates["site-a-data"][edge_a_slot],
                    "edge-a.data-key": keys["site-a-data"][edge_a_slot],
                    "edge-b.control-cert": certificates["site-b-control"][edge_b_slot],
                    "edge-b.control-key": keys["site-b-control"][edge_b_slot],
                    "edge-b.data-cert": certificates["site-b-data"][edge_b_slot],
                    "edge-b.data-key": keys["site-b-data"][edge_b_slot],
                }
            )
            result[state_name] = row
        return assignments, result

    def common(self, verb: str, marker: pathlib.Path | None = None) -> list[str]:
        transaction_marker = self.layout.active if marker is None else marker
        return [
            verb,
            "--mode", "isolated-test",
            "--run-id", RUN_ID,
            "--candidate-sha256", CANDIDATE,
            "--rotation-id", ROTATION_ID,
            "--rotation-manifest", str(self.layout.manifest),
            "--rotation-manifest-sha256", self.manifest_sha256,
            "--transaction-marker", str(transaction_marker),
            "--transaction-marker-sha256", self.active_sha256,
            "--stage-marker", str(self.layout.stage),
        ]

    def run(self, arguments: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(DRIVER), *arguments],
            env=self.environment if env is None else env,
            text=True,
            capture_output=True,
            check=False,
        )

    def prepare(self) -> None:
        completed = self.run(self.common("prepare"))
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)

    def execute_args(self) -> list[str]:
        return self.common("execute") + ["--transcript", str(self.work / "transcript.json")]

    def rollback_args(self, floor: str) -> list[str]:
        return self.common("rollback") + [
            "--rollback-floor", floor,
            "--rollback-marker", str(self.work / "rollback.json"),
        ]


class RotationDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(pathlib.Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def expected(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            mode="isolated-test",
            run_id=RUN_ID,
            candidate_sha256=CANDIDATE,
            run_manifest_sha256=RUN_MANIFEST,
            prerequisite_marker_sha256=PREREQUISITE,
            rotation_id=ROTATION_ID,
            rotation_manifest_sha256=self.fixture.manifest_sha256,
            transaction_marker_sha256=self.fixture.active_sha256,
            start_monotonic_ms=self.fixture.started,
            now_monotonic_ms=state.monotonic_ms(),
        )

    def test_full_isolated_rotation_emits_only_validator_accepted_evidence(self):
        self.fixture.prepare()
        completed = self.fixture.run(self.fixture.execute_args())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        transcript_path = self.fixture.work / "transcript.json"
        value = json.loads(transcript_path.read_text(encoding="ascii"))
        expected = self.expected()
        expected.now_monotonic_ms = state.monotonic_ms()
        marker = gate.validate_transcript(value, expected)
        self.assertEqual(tuple(marker), gate.PASS_MARKER_KEYS)
        serialized = transcript_path.read_bytes().lower()
        for forbidden in (b"private key", b"begin certificate", b"spki/", b".key", b"address"):
            self.assertNotIn(forbidden, serialized)
        manifest = json.loads(self.fixture.layout.manifest.read_text(encoding="ascii"))
        states, assignments = state.validate_manifest(manifest)
        state.validate_live_row(
            self.fixture.layout.live, "post", states, assignments, production=False
        )

    def test_both_rollback_floors_emit_exact_validated_markers(self):
        for crash_at, floor, selected in (
            ("before:retiring", "pre-retirement", "overlap"),
            ("after:retiring", "next-only", "post"),
        ):
            with self.subTest(floor=floor):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = Fixture(pathlib.Path(directory))
                    fixture.prepare()
                    environment = dict(fixture.environment)
                    environment["CAMPUS_LINK_ROTATION_TEST_CRASH_AT"] = crash_at
                    failed = fixture.run(fixture.execute_args(), env=environment)
                    self.assertEqual(failed.returncode, 97, failed.stderr)
                    rollback = fixture.run(fixture.rollback_args(floor))
                    self.assertEqual(rollback.returncode, 0, rollback.stderr)
                    marker = json.loads((fixture.work / "rollback.json").read_text(encoding="ascii"))
                    expected = types.SimpleNamespace(
                        mode="isolated-test",
                        run_id=RUN_ID,
                        candidate_sha256=CANDIDATE,
                        rotation_id=ROTATION_ID,
                        rotation_manifest_sha256=fixture.manifest_sha256,
                        transaction_marker_sha256=fixture.active_sha256,
                        rollback_floor=floor,
                        now_monotonic_ms=state.monotonic_ms(),
                    )
                    gate.validate_rollback(marker, expected)
                    manifest = json.loads(fixture.layout.manifest.read_text(encoding="ascii"))
                    states, assignments = state.validate_manifest(manifest)
                    state.validate_live_row(
                        fixture.layout.live, selected, states, assignments, production=False
                    )

    def test_option_and_path_boundary_is_exact(self):
        arguments = self.fixture.common("prepare")
        swapped = list(arguments)
        swapped[1], swapped[3] = swapped[3], swapped[1]
        self.assertNotEqual(self.fixture.run(swapped).returncode, 0)
        wrong = list(arguments)
        wrong[wrong.index("--stage-marker") + 1] = str(self.fixture.root / "stage.env")
        self.assertNotEqual(self.fixture.run(wrong).returncode, 0)
        extra = arguments + ["--callback", "anything"]
        self.assertNotEqual(self.fixture.run(extra).returncode, 0)

    def test_each_stage_binding_and_order_mutation_is_rejected(self):
        self.fixture.prepare()
        original = self.fixture.layout.stage.read_text(encoding="ascii")
        replacements = {
            "RUN_ID": "a" * 32,
            "CANDIDATE_SHA256": "b" * 64,
            "ROTATION_ID": "c" * 32,
            "ROTATION_MANIFEST_SHA256": "d" * 64,
        }
        for key, replacement in replacements.items():
            with self.subTest(key=key):
                mutated = re.sub(rf"^{key}=.*$", f"{key}={replacement}", original, flags=re.MULTILINE)
                write_mode(self.fixture.layout.stage, mutated.encode("ascii"), 0o600)
                self.assertNotEqual(self.fixture.run(self.fixture.execute_args()).returncode, 0)
                write_mode(self.fixture.layout.stage, original.encode("ascii"), 0o600)
        lines = original.splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        write_mode(self.fixture.layout.stage, ("\n".join(lines) + "\n").encode("ascii"), 0o600)
        self.assertNotEqual(self.fixture.run(self.fixture.execute_args()).returncode, 0)

    def test_every_sealed_artifact_hash_is_rechecked_in_every_state(self):
        manifest = json.loads(self.fixture.layout.manifest.read_text(encoding="ascii"))
        states, assignments = state.validate_manifest(manifest)
        for state_name in state.STATES:
            for artifact in state.ARTIFACTS:
                with self.subTest(state=state_name, artifact=artifact):
                    path = self.fixture.layout.rows / state_name / artifact
                    original = path.read_bytes()
                    write_mode(path, original + b"x", 0o400)
                    with self.assertRaises(state.RotationError):
                        state.validate_rows(
                            self.fixture.layout.rows,
                            states,
                            assignments,
                            production=False,
                        )
                    write_mode(path, original, 0o400)

    def test_cross_state_splices_are_rejected_for_every_distinct_pair(self):
        manifest = json.loads(self.fixture.layout.manifest.read_text(encoding="ascii"))
        states, assignments = state.validate_manifest(manifest)
        for first_index, first in enumerate(state.STATES):
            for second in state.STATES[first_index + 1 :]:
                changed = [
                    artifact for artifact in state.ARTIFACTS
                    if states[first][artifact] != states[second][artifact]
                ]
                if not changed:
                    continue
                artifact = changed[0]
                with self.subTest(first=first, second=second, artifact=artifact):
                    path = self.fixture.layout.rows / first / artifact
                    original = path.read_bytes()
                    replacement = (self.fixture.layout.rows / second / artifact).read_bytes()
                    write_mode(path, replacement, 0o400)
                    with self.assertRaises(state.RotationError):
                        state.validate_rows(
                            self.fixture.layout.rows,
                            states,
                            assignments,
                            production=False,
                        )
                    write_mode(path, original, 0o400)

    def test_sealer_rejects_rows_that_self_hash_but_misassign_public_identities(self):
        active_raw = self.fixture.layout.active.read_bytes()
        os.chmod(self.fixture.layout.active, 0o600)
        self.fixture.layout.active.unlink()
        try:
            config_states = ("overlap", "relay-next", "edge-a-next", "edge-b-next", "retiring")
            config_path = self.fixture.layout.rows / config_states[0] / "edge-a.config"
            original_config = config_path.read_bytes()
            config = json.loads(original_config)
            config["data_identity"]["next_spki"] = self.fixture.assignments["site-a-data"]["next"]
            for state_name in config_states:
                write_mode(
                    self.fixture.layout.rows / state_name / "edge-a.config",
                    state.canonical_json(config),
                    0o400,
                )
            sealed = subprocess.run(
                [sys.executable, str(SEALER), "seal", "--mode", "isolated-test"],
                env=self.fixture.environment,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(sealed.returncode, 0)
            for state_name in config_states:
                write_mode(
                    self.fixture.layout.rows / state_name / "edge-a.config",
                    original_config,
                    0o400,
                )

            cert_states = ("relay-next", "edge-a-next", "edge-b-next", "retiring", "post")
            cert_path = self.fixture.layout.rows / cert_states[0] / "relay.control-cert"
            original_cert = cert_path.read_bytes()
            replacement = (
                self.fixture.layout.rows / "edge-a-next" / "edge-a.control-cert"
            ).read_bytes()
            for state_name in cert_states:
                write_mode(
                    self.fixture.layout.rows / state_name / "relay.control-cert",
                    replacement,
                    0o400,
                )
            sealed = subprocess.run(
                [sys.executable, str(SEALER), "seal", "--mode", "isolated-test"],
                env=self.fixture.environment,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(sealed.returncode, 0)
            for state_name in cert_states:
                write_mode(
                    self.fixture.layout.rows / state_name / "relay.control-cert",
                    original_cert,
                    0o400,
                )
        finally:
            write_mode(self.fixture.layout.active, active_raw, 0o600)

    def test_wrong_modes_and_symlinks_fail_closed(self):
        os.chmod(self.fixture.layout.manifest, 0o600)
        verify = subprocess.run(
            [sys.executable, str(SEALER), "verify", "--mode", "isolated-test"],
            env=self.fixture.environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(verify.returncode, 0)
        os.chmod(self.fixture.layout.manifest, 0o444)
        artifact = self.fixture.layout.rows / "pre" / "relay.config"
        original = artifact.read_bytes()
        os.chmod(artifact, 0o600)
        self.assertNotEqual(
            subprocess.run(
                [sys.executable, str(SEALER), "verify", "--mode", "isolated-test"],
                env=self.fixture.environment,
                capture_output=True,
                check=False,
            ).returncode,
            0,
        )
        write_mode(artifact, original, 0o400)

        manifest_saved = self.fixture.layout.rotation_root / "saved-manifest"
        self.fixture.layout.manifest.replace(manifest_saved)
        try:
            try:
                self.fixture.layout.manifest.symlink_to(manifest_saved)
            except OSError:
                self.skipTest("symlinks are not available to this test account")
            self.assertNotEqual(
                subprocess.run(
                    [sys.executable, str(SEALER), "verify", "--mode", "isolated-test"],
                    env=self.fixture.environment,
                    capture_output=True,
                    check=False,
                ).returncode,
                0,
            )
        finally:
            try:
                self.fixture.layout.manifest.unlink()
            except OSError:
                pass
            manifest_saved.replace(self.fixture.layout.manifest)

        link_target = self.fixture.layout.rows / "pre" / "relay.control-key"
        saved = self.fixture.layout.rotation_root / "saved-artifact"
        link_target.replace(saved)
        try:
            try:
                link_target.symlink_to(saved)
            except OSError:
                self.skipTest("symlinks are not available to this test account")
            self.assertNotEqual(
                subprocess.run(
                    [sys.executable, str(SEALER), "verify", "--mode", "isolated-test"],
                    env=self.fixture.environment,
                    capture_output=True,
                    check=False,
                ).returncode,
                0,
            )
        finally:
            try:
                link_target.unlink()
            except OSError:
                pass
            saved.replace(link_target)

        self.fixture.prepare()
        stage_saved = self.fixture.layout.rotation_root / "saved-stage"
        self.fixture.layout.stage.replace(stage_saved)
        try:
            self.fixture.layout.stage.symlink_to(stage_saved)
            self.assertNotEqual(self.fixture.run(self.fixture.execute_args()).returncode, 0)
        finally:
            try:
                self.fixture.layout.stage.unlink()
            except OSError:
                pass
            stage_saved.replace(self.fixture.layout.stage)


class RotationCrashMatrixTests(unittest.TestCase):
    CRASH_POINTS = (
        *(f"after:overlap:{name}" for name in ("relay.config", "edge-a.config", "edge-b.config")),
        "after:overlap:stage",
        "after:overlap:service",
        "after:relay-next:relay.control-cert",
        "after:relay-next:relay.control-key",
        "after:relay-next:stage",
        "after:relay-next:service",
        *(f"after:edge-a-next:{name}" for name in (
            "edge-a.control-cert", "edge-a.control-key", "edge-a.data-cert", "edge-a.data-key"
        )),
        "after:edge-a-next:stage",
        "after:edge-a-next:service",
        *(f"after:edge-b-next:{name}" for name in (
            "edge-b.control-cert", "edge-b.control-key", "edge-b.data-cert", "edge-b.data-key"
        )),
        "after:edge-b-next:stage",
        "after:edge-b-next:service",
        "before:retiring",
        "after:retiring:stage",
        "after:retiring",
        *(f"after:post:{name}" for name in ("relay.config", "edge-a.config", "edge-b.config")),
        "after:post:stage",
        "after:post:service",
    )

    PREPARE_CRASH_POINTS = (
        *(f"after:prepare:{artifact}" for artifact in state.ARTIFACTS),
        "after:prepare:metadata",
        "after:pre:stage",
    )

    def test_kill_after_every_prepare_replacement_never_mutates_live_credentials(self):
        with tempfile.TemporaryDirectory() as base_directory:
            base = pathlib.Path(base_directory) / "base"
            mkdir(base)
            Fixture(base)
            for index, crash_at in enumerate(self.PREPARE_CRASH_POINTS):
                with self.subTest(crash_at=crash_at):
                    clone = pathlib.Path(base_directory) / f"prepare-{index}"
                    shutil.copytree(base, clone)
                    current = Fixture.__new__(Fixture)
                    current.root = clone
                    environment = dict(os.environ)
                    environment["CAMPUS_LINK_ROTATION_TEST_ROOT"] = str(clone)
                    current.environment = environment
                    os.environ["CAMPUS_LINK_ROTATION_TEST_ROOT"] = str(clone)
                    try:
                        current.layout = state.layout("isolated-test")
                    finally:
                        os.environ.pop("CAMPUS_LINK_ROTATION_TEST_ROOT", None)
                    current.manifest_sha256 = hashlib.sha256(current.layout.manifest.read_bytes()).hexdigest()
                    current.active_sha256 = hashlib.sha256(current.layout.active.read_bytes()).hexdigest()
                    current.work = current.layout.run_root / f".certificate-rotation.{ROTATION_ID}.ABC123"
                    fault_environment = dict(environment)
                    fault_environment["CAMPUS_LINK_ROTATION_TEST_CRASH_AT"] = crash_at
                    failed = current.run(current.common("prepare"), env=fault_environment)
                    self.assertEqual(failed.returncode, 97, failed.stderr)
                    manifest = json.loads(current.layout.manifest.read_text(encoding="ascii"))
                    states, assignments = state.validate_manifest(manifest)
                    state.validate_live_row(
                        current.layout.live, "pre", states, assignments, production=False
                    )
                    if crash_at == "after:pre:stage":
                        bindings = {
                            "run_id": RUN_ID,
                            "candidate_sha256": CANDIDATE,
                            "rotation_id": ROTATION_ID,
                            "rotation_manifest_sha256": current.manifest_sha256,
                        }
                        self.assertEqual(
                            state.validate_stage(current.layout.stage, bindings, production=False),
                            "pre",
                        )
                    else:
                        self.assertFalse(current.layout.stage.exists())

    def test_kill_after_every_atomic_execute_replacement_recovers_to_safe_floor(self):
        with tempfile.TemporaryDirectory() as base_directory:
            base = pathlib.Path(base_directory) / "base"
            mkdir(base)
            fixture = Fixture(base)
            fixture.prepare()
            for index, crash_at in enumerate(self.CRASH_POINTS):
                with self.subTest(crash_at=crash_at):
                    clone = pathlib.Path(base_directory) / f"case-{index}"
                    shutil.copytree(base, clone)
                    current = Fixture.__new__(Fixture)
                    current.root = clone
                    environment = dict(os.environ)
                    environment["CAMPUS_LINK_ROTATION_TEST_ROOT"] = str(clone)
                    current.environment = environment
                    os.environ["CAMPUS_LINK_ROTATION_TEST_ROOT"] = str(clone)
                    try:
                        current.layout = state.layout("isolated-test")
                    finally:
                        os.environ.pop("CAMPUS_LINK_ROTATION_TEST_ROOT", None)
                    current.manifest_sha256 = hashlib.sha256(current.layout.manifest.read_bytes()).hexdigest()
                    current.active_sha256 = hashlib.sha256(current.layout.active.read_bytes()).hexdigest()
                    current.work = current.layout.run_root / f".certificate-rotation.{ROTATION_ID}.ABC123"
                    fault_environment = dict(environment)
                    fault_environment["CAMPUS_LINK_ROTATION_TEST_CRASH_AT"] = crash_at
                    failed = current.run(current.execute_args(), env=fault_environment)
                    self.assertEqual(failed.returncode, 97, failed.stderr)
                    bindings = {
                        "run_id": RUN_ID,
                        "candidate_sha256": CANDIDATE,
                        "rotation_id": ROTATION_ID,
                        "rotation_manifest_sha256": current.manifest_sha256,
                    }
                    try:
                        selected = state.validate_stage(
                            current.layout.stage, bindings, production=False
                        )
                    except state.RotationError:
                        selected = "unknown"
                    floor = (
                        "pre-retirement"
                        if selected in {"pre", "overlap", "relay-next", "edge-a-next", "edge-b-next"}
                        else "next-only"
                    )
                    recovered = current.run(current.rollback_args(floor))
                    self.assertEqual(recovered.returncode, 0, recovered.stderr)
                    manifest = json.loads(current.layout.manifest.read_text(encoding="ascii"))
                    states, assignments = state.validate_manifest(manifest)
                    target = "overlap" if floor == "pre-retirement" else "post"
                    state.validate_live_row(
                        current.layout.live, target, states, assignments, production=False
                    )


class ProductionBoundarySourceTests(unittest.TestCase):
    def test_driver_has_no_process_launcher_or_general_extension_boundary(self):
        source = DRIVER.read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("Popen", source)
        self.assertNotIn("os.system", source)
        self.assertIn('"prepare": COMMON_FLAGS', source)
        self.assertIn('"execute": COMMON_FLAGS', source)
        self.assertIn('"rollback": COMMON_FLAGS', source)
        self.assertIn("production rotation is disabled until the authenticated", source)
        self.assertIn("relay participant is installed", source)
        sealer = SEALER.read_text(encoding="utf-8")
        self.assertIn("authenticated per-host artifact attestations", sealer)


if __name__ == "__main__":
    unittest.main()

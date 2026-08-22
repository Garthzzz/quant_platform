from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock
import sqlite3

from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge import ds_review
from quant_hub.knowledge.ds_review import ExternalReviewDisabled, ProviderPin, ROUND_IDS
from quant_hub.knowledge import ds_review_external_v3 as external_v3
from quant_hub.knowledge.ds_review_external_v3 import (
    EXTERNAL_V3_TRANSPORT_STATE,
    ExternalCampaignLedgerV3,
    ExternalV3Disabled,
    ExternalV3PolicyError,
    ExternalV3StateError,
    PricingBudgetV3,
    ScriptedFakeTransport,
    execute_scripted_fake_round_v3,
    external_review,
    mark_orphaned_dispatch_ambiguous_v3,
    parse_external_response_v3,
    prepare_external_campaign_v3,
)


FIXTURE_FINGERPRINT = "fp-public-synthetic-external-v3"


def _pricing() -> PricingBudgetV3:
    return PricingBudgetV3(
        currency="USD_MICRO",
        prompt_micros_per_million=2_000_000,
        completion_micros_per_million=8_000_000,
        pricing_evidence_sha256="a" * 64,
        max_campaign_cost_micros=1_000_000,
        max_prompt_tokens_per_round=96 * 1024,
        max_completion_tokens_per_round=4096,
        max_campaign_total_tokens=4 * (96 * 1024 + 4096),
        max_request_bytes=96 * 1024,
        max_response_bytes=256 * 1024,
        per_round_deadline_seconds=90,
        campaign_deadline_seconds=360,
    )


def _campaign():
    return prepare_external_campaign_v3(
        pin=ProviderPin.create(expected_system_fingerprint=FIXTURE_FINGERPRINT),
        identity_evidence_sha256="b" * 64,
        pricing=_pricing(),
        transport_build_sha256="c" * 64,
    )


def _output(round_id: str, *, mechanism_id: str = "M01") -> dict[str, object]:
    return {
        "schema_version": "qrh-ds-architecture-review-output/v2",
        "round_id": round_id,
        "release_position": "block",
        "findings": [
            {
                "finding_id": "F-001",
                "severity": "blocker",
                "mechanism_id": mechanism_id,
                "rationale": "ONE_TRANSITION_CAN_PERMIT_TWO_WORKERS_TO_OWN_ONE_JOB.",
                "falsification_test": "RELEASE_THIRTY_TWO_WORKERS_AT_ONE_BARRIER_AND_COUNT_ATTEMPTS.",
                "minimal_change": "USE_ONE_CONDITIONAL_UPDATE_AND_ONE_DURABLE_DISPATCH_INTENT.",
                "residual_risk": "PROCESS_LOSS_AFTER_INTENT_REMAINS_AMBIGUOUS_WITHOUT_IDEMPOTENCY.",
            }
        ],
        "dissent": {
            "why_not_release": ["EXTERNAL_SIDE_EFFECT_IS_NOT_ATOMIC_WITH_LOCAL_SQLITE."],
            "missing_stress_cases": ["KILL_OWNER_AFTER_DISPATCH_INTENT_BEFORE_RESPONSE_COMMIT."],
            "assumptions_to_break": ["DO_NOT_ASSUME_TIMEOUT_MEANS_NO_PROVIDER_SIDE_EFFECT."],
        },
    }


def _response(
    round_id: str,
    *,
    fingerprint: str = FIXTURE_FINGERPRINT,
    prompt_tokens: object = 2000,
    completion_tokens: object = 500,
    total_tokens: object = 2500,
    output: object | None = None,
) -> bytes:
    return canonical_json(
        {
            "id": "resp-public-synthetic-v3",
            "created": 1787270400,
            "model": "deepseek-v4-pro",
            "system_fingerprint": fingerprint,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": canonical_json(output or _output(round_id)),
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
        }
    ).encode("utf-8")


class ExternalV3TestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.data_root = Path(self.temporary.name).resolve()
        self.campaign = _campaign()
        self.ledger = ExternalCampaignLedgerV3(
            self.data_root / "external-v3.sqlite3",
            data_root=self.data_root,
        )
        self.addCleanup(self.ledger.close)
        self.ledger.install(self.campaign)
        self.ledger.approve_fake(
            self.campaign, approval_evidence_sha256="d" * 64
        )

    def _claim(self, ordinal: int = 0):
        bound = self.ledger.bind_next_request(self.campaign)
        claim = self.ledger.claim(
            self.campaign,
            bound,
            owner_nonce="claim_" + f"{ordinal + 1:032x}",
        )
        return bound, claim


class ExternalV3SurfaceTests(ExternalV3TestCase):
    def test_real_transport_keyring_and_network_surfaces_remain_absent(self) -> None:
        source = inspect.getsource(external_v3)
        for forbidden in (
            "import http.client",
            "import socket",
            "import ssl",
            "import keyring",
            "get_password(",
            "os.environ",
            "import subprocess",
            "requests.",
            "urllib",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual("DISABLED_FAKE_ONLY", EXTERNAL_V3_TRANSPORT_STATE)
        with self.assertRaises(ExternalV3Disabled):
            external_review(self.campaign)
        with self.assertRaises(ExternalV3Disabled):
            self.ledger.approve_external(self.campaign)
        with self.assertRaises(ExternalReviewDisabled):
            ds_review.external_review(self.campaign)

    def test_manifest_binds_identity_pricing_transport_and_fake_only_state(self) -> None:
        manifest = json.loads(self.campaign.manifest_bytes)
        self.assertEqual("DISABLED_FAKE_ONLY", manifest["external_transport_state"])
        self.assertEqual("ADVISORY_ONLY", manifest["authority"])
        self.assertEqual("b" * 64, manifest["identity_evidence_sha256"])
        self.assertEqual("a" * 64, manifest["pricing_budget"]["pricing_evidence_sha256"])
        self.assertEqual("c" * 64, manifest["transport_build_sha256"])
        self.assertEqual(
            "QRH_DS_EXTERNAL_PUBLIC_OUTPUT_ALLOWLIST_V1",
            manifest["public_output_allowlist"],
        )
        self.assertEqual(64, len(manifest["public_output_allowlist_sha256"]))
        self.assertEqual(64, len(manifest["public_output_locator_policy_sha256"]))
        self.assertEqual(
            "qrh-ds-public-success-replay/v1", manifest["success_replay_schema"]
        )
        self.assertEqual(
            "qrh-ds-terminal-commitment/v1",
            manifest["terminal_commitment_schema"],
        )
        self.assertEqual(
            "QRH_DS_LOCAL_DURABLE_WRITE_V2",
            manifest["durable_write_protocol"],
        )
        self.assertEqual(
            "WINDOWS_DIRECTORY_STREAM_GUARDED_ONLY",
            manifest["ledger_platform_state"],
        )
        self.assertEqual(
            "UNVERIFIABLE_NO_TRUSTED_ANCHOR",
            manifest["terminal_audit_verifiability"],
        )
        self.assertEqual(4, len(manifest["rounds"]))
        self.assertEqual(4, len({row["template_sha256"] for row in manifest["rounds"]}))
        with self.assertRaises(ExternalV3PolicyError):
            external_v3.validate_external_campaign_v3(
                replace(self.campaign, campaign_id="dsext3_" + "0" * 32)
            )

    def test_custom_transport_subclass_is_rejected_before_dispatch_intent(self) -> None:
        class CustomTransport(ScriptedFakeTransport):
            pass

        _bound, claim = self._claim()
        transport = CustomTransport(
            kind="RESPONSE",
            response_bytes=_response(ROUND_IDS[0]),
            elapsed_seconds=1.0,
        )
        with self.assertRaises(ExternalV3Disabled):
            execute_scripted_fake_round_v3(
                ledger=self.ledger,
                campaign=self.campaign,
                claim=claim,
                transport=transport,
            )
        snapshot = self.ledger.snapshot(self.campaign)
        self.assertEqual("CLAIMED", snapshot["rounds"][0]["state"])
        self.assertEqual(0, snapshot["rounds"][0]["attempts"])

    def test_runner_and_storage_root_are_exact_capabilities(self) -> None:
        class CustomLedger:
            called = False

            def mark_dispatch_intent(self, *_args: object) -> None:
                self.called = True

        _bound, claim = self._claim()
        custom = CustomLedger()
        fake = ScriptedFakeTransport(
            kind="RESPONSE",
            response_bytes=_response(ROUND_IDS[0]),
            elapsed_seconds=1.0,
        )
        with self.assertRaises(ExternalV3Disabled):
            execute_scripted_fake_round_v3(
                ledger=custom,  # type: ignore[arg-type]
                campaign=self.campaign,
                claim=claim,
                transport=fake,
            )
        self.assertFalse(custom.called)
        outside = self.data_root.parent / "outside-external-v3.sqlite3"
        with self.assertRaises(ExternalV3StateError):
            ExternalCampaignLedgerV3(outside, data_root=self.data_root)

    @unittest.skipUnless(os.name == "nt", "Windows handle-guard boundary")
    def test_sqlite_connect_window_keeps_root_and_stream_unlinkable(self) -> None:
        for target in ("root", "hardlink"):
            with self.subTest(target=target):
                outer = self.data_root / f"sqlite-window-{target}"
                managed = outer / "managed"
                replacement = outer / "replacement"
                parked = outer / "parked"
                managed.mkdir(parents=True)
                replacement.mkdir()
                database = managed / "ledger.sqlite3"
                sqlite_stream = Path(str(managed) + ":" + database.name)
                outside_link = outer / "outside-ledger.sqlite3"
                observed: dict[str, object] = {}
                real_connect = external_v3.sqlite3.connect

                def native_stream_exists(path: Path) -> bool:
                    handle = 0
                    try:
                        handle = external_v3._win_open_absolute(
                            path, directory=False
                        )
                        return True
                    except OSError:
                        return False
                    finally:
                        external_v3._win_close(handle)

                def connect_during_replacement(*args: object, **kwargs: object):
                    observed["placeholder_size"] = sqlite_stream.stat().st_size
                    try:
                        if target == "root":
                            managed.rename(parked)
                        else:
                            os.link(sqlite_stream, outside_link)
                    except OSError as error:
                        observed["replacement_error"] = error
                    else:
                        observed["replacement_succeeded"] = True
                    observed["outside_link_exists"] = outside_link.exists()
                    observed["replacement_stream_exists"] = native_stream_exists(
                        Path(str(replacement) + ":" + database.name)
                    )
                    return real_connect(*args, **kwargs)

                with mock.patch.object(
                    external_v3.sqlite3,
                    "connect",
                    side_effect=connect_during_replacement,
                ):
                    ledger = ExternalCampaignLedgerV3(database, data_root=managed)
                try:
                    self.assertEqual(0, observed["placeholder_size"])
                    self.assertIn("replacement_error", observed)
                    self.assertNotIn("replacement_succeeded", observed)
                    self.assertFalse(observed["outside_link_exists"])
                    self.assertFalse(observed["replacement_stream_exists"])
                    self.assertFalse(database.exists())
                    ledger.install(self.campaign)
                    self.assertEqual(
                        "PREREGISTERED", ledger.snapshot(self.campaign)["state"]
                    )
                    with self.assertRaises(OSError):
                        os.link(ledger._sqlite_path, outside_link)
                    self.assertFalse(outside_link.exists())
                finally:
                    ledger.close()

    @unittest.skipUnless(os.name == "nt", "Windows handle-guard boundary")
    def test_frozen_root_identity_drift_fails_before_sqlite_write(self) -> None:
        before = self.ledger._sqlite_path.read_bytes()
        frozen = self.ledger._managed_root_identity
        self.ledger._managed_root_identity = (frozen[0], frozen[1] + 1)
        try:
            with self.assertRaises(ExternalV3StateError):
                self.ledger.snapshot(self.campaign)
            self.assertEqual(before, self.ledger._sqlite_path.read_bytes())
        finally:
            self.ledger._managed_root_identity = frozen

    def test_unguarded_platform_is_disabled_before_database_creation(self) -> None:
        database = self.data_root / "unguarded.sqlite3"
        with mock.patch.object(external_v3.os, "name", "posix"):
            with self.assertRaises(ExternalV3Disabled):
                ExternalCampaignLedgerV3(database, data_root=self.data_root)
        self.assertFalse(database.exists())

    @unittest.skipUnless(os.name == "nt", "Windows named-stream boundary")
    def test_preinit_and_schema_process_cuts_restart_idempotently(self) -> None:
        for index, cut in enumerate(
            (
                "AFTER_PREINIT_MARKER",
                "AFTER_ZERO_STREAM",
                "BEFORE_FIRST_CONNECT",
                "AFTER_SCHEMA_COMMIT",
            )
        ):
            with self.subTest(cut=cut):
                root = self.data_root / f"sqlite-bootstrap-cut-{index}"
                root.mkdir()
                database = root / "ledger.sqlite3"

                def cutpoint(phase: str) -> None:
                    if phase == cut:
                        raise RuntimeError(f"synthetic bootstrap cut: {phase}")

                with mock.patch.object(
                    ExternalCampaignLedgerV3,
                    "_sqlite_initialize_cutpoint",
                    side_effect=cutpoint,
                ):
                    with self.assertRaisesRegex(RuntimeError, cut):
                        ExternalCampaignLedgerV3(database, data_root=root)
                self.assertFalse(database.exists())
                restarted = ExternalCampaignLedgerV3(database, data_root=root)
                self.addCleanup(restarted.close)
                restarted.install(self.campaign)
                self.assertEqual(
                    "PREREGISTERED", restarted.snapshot(self.campaign)["state"]
                )

    @unittest.skipUnless(os.name == "nt", "Windows named-stream boundary")
    def test_preinit_marker_and_partial_stream_tamper_fail_before_write(self) -> None:
        marker_root = self.data_root / "sqlite-marker-tamper"
        marker_root.mkdir()
        marker_database = marker_root / "ledger.sqlite3"
        ledger = ExternalCampaignLedgerV3(marker_database, data_root=marker_root)
        ledger.close()
        preinit = next(marker_root.glob("*.preinit.json"))
        os.chmod(preinit, stat.S_IWRITE)
        preinit.write_bytes(b"{}")
        stream = Path(str(marker_root) + ":" + marker_database.name)
        before = stream.read_bytes()
        with self.assertRaises(ExternalV3StateError):
            ExternalCampaignLedgerV3(marker_database, data_root=marker_root)
        self.assertEqual(before, stream.read_bytes())

        partial_root = self.data_root / "sqlite-partial-stream"
        partial_root.mkdir()
        partial_database = partial_root / "ledger.sqlite3"

        def cut_after_zero(phase: str) -> None:
            if phase == "AFTER_ZERO_STREAM":
                raise RuntimeError("synthetic zero-stream cut")

        with mock.patch.object(
            ExternalCampaignLedgerV3,
            "_sqlite_initialize_cutpoint",
            side_effect=cut_after_zero,
        ):
            with self.assertRaisesRegex(RuntimeError, "zero-stream"):
                ExternalCampaignLedgerV3(partial_database, data_root=partial_root)
        partial_stream = Path(str(partial_root) + ":" + partial_database.name)
        partial_stream.write_bytes(b"partial")
        partial_before = partial_stream.read_bytes()
        with self.assertRaises(ExternalV3StateError):
            ExternalCampaignLedgerV3(partial_database, data_root=partial_root)
        self.assertEqual(partial_before, partial_stream.read_bytes())

    @unittest.skipUnless(os.name == "nt", "Windows named-stream boundary")
    def test_existing_stream_without_preinit_authority_is_not_adopted(self) -> None:
        source_root = self.data_root / "sqlite-authority-source"
        source_root.mkdir()
        source_database = source_root / "ledger.sqlite3"
        source = ExternalCampaignLedgerV3(source_database, data_root=source_root)
        source.close()
        raw = Path(str(source_root) + ":" + source_database.name).read_bytes()

        target_root = self.data_root / "sqlite-authority-target"
        target_root.mkdir()
        target_database = target_root / "ledger.sqlite3"
        target_stream = Path(str(target_root) + ":" + target_database.name)
        target_stream.write_bytes(raw)
        before = target_stream.read_bytes()
        with self.assertRaisesRegex(ExternalV3StateError, "PREINIT authority"):
            ExternalCampaignLedgerV3(target_database, data_root=target_root)
        self.assertEqual(before, target_stream.read_bytes())

    @unittest.skipUnless(os.name == "nt", "Windows named-stream boundary")
    def test_bootstrap_marker_stream_set_uses_a_closed_state_matrix(self) -> None:
        for index, state in enumerate(
            (
                "INITIALIZED_STREAM_WITHOUT_PREINIT",
                "INITIALIZED_WITHOUT_STREAM",
                "INITIALIZED_WITH_ZERO_STREAM",
            )
        ):
            with self.subTest(state=state):
                root = self.data_root / f"sqlite-closed-set-{index}"
                root.mkdir()
                database = root / "ledger.sqlite3"
                ledger = ExternalCampaignLedgerV3(database, data_root=root)
                ledger.close()
                preinit = next(root.glob("*.preinit.json"))
                initialized = next(root.glob("*.initialized.json"))
                stream = Path(str(root) + ":" + database.name)
                before = stream.read_bytes()

                os.chmod(preinit, stat.S_IWRITE)
                preinit.unlink()
                if state == "INITIALIZED_WITHOUT_STREAM":
                    os.remove(stream)
                elif state == "INITIALIZED_WITH_ZERO_STREAM":
                    stream.write_bytes(b"")

                with self.assertRaisesRegex(
                    ExternalV3StateError, "PREINIT authority"
                ):
                    ExternalCampaignLedgerV3(database, data_root=root)
                self.assertFalse(preinit.exists())
                self.assertTrue(initialized.exists())
                if state == "INITIALIZED_STREAM_WITHOUT_PREINIT":
                    self.assertEqual(before, stream.read_bytes())
                elif state == "INITIALIZED_WITHOUT_STREAM":
                    with self.assertRaises(FileNotFoundError):
                        stream.read_bytes()
                else:
                    self.assertEqual(b"", stream.read_bytes())

    def test_preregistered_campaign_can_be_replayed_before_approval(self) -> None:
        path = self.data_root / "preregistered.sqlite3"
        ledger = ExternalCampaignLedgerV3(path, data_root=self.data_root)
        ledger.install(self.campaign)
        self.assertEqual("PREREGISTERED", ledger.snapshot(self.campaign)["state"])
        reopened = ExternalCampaignLedgerV3(path, data_root=self.data_root)
        self.assertEqual("PREREGISTERED", reopened.snapshot(self.campaign)["state"])


class ExternalV3DialogueTests(ExternalV3TestCase):
    def test_four_rounds_form_one_bounded_advisory_chain(self) -> None:
        previous_advisory_sha = "0" * 64
        previous_chain_sha = "0" * 64
        request_hashes = []
        receipt_hashes = []
        for ordinal, round_id in enumerate(ROUND_IDS):
            bound, claim = self._claim(ordinal)
            request_hashes.append(bound.request_sha256)
            request = json.loads(bound.request_bytes)
            user = json.loads(request["messages"][1]["content"])
            self.assertNotIn("tools", request)
            self.assertEqual(4096, request["max_tokens"])
            self.assertEqual(previous_advisory_sha, user["contract"]["prior_output_sha256"])
            self.assertEqual(previous_chain_sha, user["contract"]["prior_output_chain_sha256"])
            if ordinal == 0:
                self.assertIsNone(user["prior_advisory"])
            else:
                self.assertEqual(ROUND_IDS[ordinal - 1], user["prior_advisory"]["round_id"])
            fake = ScriptedFakeTransport(
                kind="RESPONSE",
                response_bytes=_response(round_id, output=_output(round_id, mechanism_id=f"M{ordinal + 1:02d}")),
                elapsed_seconds=1.25,
            )
            receipt = execute_scripted_fake_round_v3(
                ledger=self.ledger,
                campaign=self.campaign,
                claim=claim,
                transport=fake,
            )
            self.assertEqual(1, fake.calls)
            self.assertEqual("SUCCEEDED", receipt["status"])
            self.assertEqual(0, receipt["redirects_followed"])
            self.assertFalse(receipt["tools_enabled"])
            self.assertEqual(1, receipt["attempt_count"])
            self.assertNotIn(FIXTURE_FINGERPRINT, canonical_json(receipt))
            previous_advisory_sha = receipt["advisory_sha256"]
            previous_chain_sha = receipt["output_chain_sha256"]
            receipt_hashes.append(receipt["receipt_sha256"])
        snapshot = self.ledger.snapshot(self.campaign)
        self.assertEqual("COMPLETE", snapshot["state"])
        self.assertEqual(["CONSUMED"] * 4, [row["state"] for row in snapshot["rounds"]])
        self.assertEqual([1] * 4, [row["attempts"] for row in snapshot["rounds"]])
        self.assertEqual(4, len(set(request_hashes)))
        self.assertEqual(4, len(set(receipt_hashes)))

    def test_tampered_bound_bytes_cannot_reach_fake_transport(self) -> None:
        bound = self.ledger.bind_next_request(self.campaign)
        tampered = replace(bound, request_bytes=bound.request_bytes + b" ")
        with self.assertRaises(ExternalV3PolicyError):
            self.ledger.claim(
                self.campaign,
                tampered,
                owner_nonce="claim_" + "1" * 32,
            )

    def test_durable_chain_and_rehashed_request_drift_fail_before_dispatch(self) -> None:
        bound, claim = self._claim()
        first = ScriptedFakeTransport(
            kind="RESPONSE",
            response_bytes=_response(bound.round_id),
            elapsed_seconds=1.0,
        )
        execute_scripted_fake_round_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            claim=claim,
            transport=first,
        )
        changed = canonical_json(
            _output(ROUND_IDS[0], mechanism_id="M02")
        ).encode("utf-8")
        connection = sqlite3.connect(self.ledger._sqlite_path)
        connection.execute(
            "UPDATE rounds SET advisory_bytes=? WHERE ordinal=0", (changed,)
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ExternalV3StateError):
            self.ledger.bind_next_request(self.campaign)

        # A fresh campaign also rejects a jointly changed request and digest:
        # the request is re-derived from the manifest and consumed prefix.
        other_path = self.data_root / "request-drift.sqlite3"
        other = ExternalCampaignLedgerV3(other_path, data_root=self.data_root)
        self.addCleanup(other.close)
        other.install(self.campaign)
        other.approve_fake(self.campaign, approval_evidence_sha256="d" * 64)
        original = other.bind_next_request(self.campaign)
        replacement = canonical_json({"model": "PUBLIC_SYNTHETIC_OTHER"}).encode(
            "utf-8"
        )
        replacement_sha = hashlib.sha256(replacement).hexdigest()
        connection = sqlite3.connect(other._sqlite_path)
        connection.execute(
            "UPDATE rounds SET request_bytes=?,request_sha256=? WHERE ordinal=0",
            (replacement, replacement_sha),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ExternalV3StateError):
            other.claim(
                self.campaign,
                replace(
                    original,
                    request_bytes=replacement,
                    request_sha256=replacement_sha,
                ),
                owner_nonce="claim_" + "7" * 32,
            )


class ExternalV3BudgetAndParserTests(ExternalV3TestCase):
    def test_usage_identity_cost_and_exact_envelope_are_enforced(self) -> None:
        bound = self.ledger.bind_next_request(self.campaign)
        parsed = parse_external_response_v3(
            _response(bound.round_id),
            campaign=self.campaign,
            bound=bound,
            elapsed_seconds=1.0,
        )
        self.assertEqual(2500, parsed.total_tokens)
        self.assertEqual(
            _pricing().cost_micros(prompt_tokens=2000, completion_tokens=500),
            parsed.cost_micros,
        )
        invalid = (
            _response(bound.round_id, fingerprint="fp-drift"),
            _response(bound.round_id, prompt_tokens=True),
            _response(bound.round_id, total_tokens=2499),
            _response(
                bound.round_id,
                completion_tokens=_pricing().max_completion_tokens_per_round + 1,
                total_tokens=2000 + _pricing().max_completion_tokens_per_round + 1,
            ),
        )
        for raw in invalid:
            with self.subTest(size=len(raw)):
                with self.assertRaises(ExternalV3PolicyError):
                    parse_external_response_v3(
                        raw,
                        campaign=self.campaign,
                        bound=bound,
                        elapsed_seconds=1.0,
                    )

    def test_invalid_known_response_is_failed_once_without_raw_echo(self) -> None:
        _bound, claim = self._claim()
        fake = ScriptedFakeTransport(
            kind="RESPONSE",
            response_bytes=b'{"upstream":"Bearer sk-do-not-echo"}',
            elapsed_seconds=1.0,
        )
        receipt = execute_scripted_fake_round_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            claim=claim,
            transport=fake,
        )
        self.assertEqual("FAILED_NO_RETRY", receipt["status"])
        self.assertEqual("KNOWN_RESPONSE_INVALID", receipt["error_code"])
        self.assertEqual(1, fake.calls)
        self.assertNotIn("do-not-echo", canonical_json(receipt))
        self.assertEqual(
            hashlib.sha256(b'{"upstream":"Bearer sk-do-not-echo"}').hexdigest(),
            receipt["raw_response_sha256"],
        )
        self.assertEqual(len(b'{"upstream":"Bearer sk-do-not-echo"}'), receipt["response_bytes"])
        self.assertEqual("FAILED", self.ledger.snapshot(self.campaign)["state"])
        self.assertEqual(
            "UNVERIFIABLE_NO_TRUSTED_ANCHOR",
            receipt["audit_verifiability"],
        )
        self.assertFalse(self.ledger._success_replay_root.exists())
        protected = b"Bearer sk-do-not-echo"
        for member in self.data_root.rglob("*"):
            if member.is_file():
                self.assertNotIn(protected, member.read_bytes())
        second = ScriptedFakeTransport(
            kind="RESPONSE", response_bytes=_response(ROUND_IDS[0]), elapsed_seconds=1.0
        )
        with self.assertRaises(ExternalV3StateError):
            execute_scripted_fake_round_v3(
                ledger=self.ledger,
                campaign=self.campaign,
                claim=claim,
                transport=second,
            )
        self.assertEqual(0, second.calls)

    def test_valid_response_cannot_be_declared_known_invalid_by_caller(self) -> None:
        bound, claim = self._claim()
        intent = self.ledger.mark_dispatch_intent(self.campaign, claim)
        with self.assertRaises(ExternalV3StateError):
            self.ledger.commit_terminal_no_retry(
                self.campaign,
                intent,
                status="FAILED_NO_RETRY",
                error_code="KNOWN_RESPONSE_INVALID",
                raw_response_bytes=_response(bound.round_id),
                elapsed_seconds=1.0,
            )
        self.assertEqual(
            "DISPATCH_INTENT",
            self.ledger.snapshot(self.campaign)["rounds"][0]["state"],
        )
        receipt = mark_orphaned_dispatch_ambiguous_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            ordinal=0,
        )
        self.assertEqual("AMBIGUOUS_NO_RETRY", receipt["status"])

    def test_deadline_is_finite_and_durably_cumulative(self) -> None:
        with self.assertRaises(ExternalV3PolicyError):
            ScriptedFakeTransport(
                kind="RESPONSE", response_bytes=b"{}", elapsed_seconds=float("nan")
            )
        pricing = replace(_pricing(), campaign_deadline_seconds=100)
        campaign = prepare_external_campaign_v3(
            pin=ProviderPin.create(expected_system_fingerprint=FIXTURE_FINGERPRINT),
            identity_evidence_sha256="b" * 64,
            pricing=pricing,
            transport_build_sha256="c" * 64,
        )
        ledger = ExternalCampaignLedgerV3(
            self.data_root / "deadline.sqlite3", data_root=self.data_root
        )
        ledger.install(campaign)
        ledger.approve_fake(campaign, approval_evidence_sha256="d" * 64)
        final = None
        for ordinal, round_id in enumerate(ROUND_IDS):
            bound = ledger.bind_next_request(campaign)
            claim = ledger.claim(
                campaign,
                bound,
                owner_nonce="claim_" + f"{ordinal + 9:032x}",
            )
            final = execute_scripted_fake_round_v3(
                ledger=ledger,
                campaign=campaign,
                claim=claim,
                transport=ScriptedFakeTransport(
                    kind="RESPONSE",
                    response_bytes=_response(round_id),
                    elapsed_seconds=30.0,
                ),
            )
            if final["status"] != "SUCCEEDED":
                break
        assert final is not None
        self.assertEqual("AMBIGUOUS_NO_RETRY", final["status"])
        self.assertEqual("AMBIGUOUS", ledger.snapshot(campaign)["state"])

    def test_raw_response_binding_closed_json_and_output_allowlist(self) -> None:
        bound = self.ledger.bind_next_request(self.campaign)
        with self.assertRaises(ExternalV3PolicyError):
            parse_external_response_v3(
                b'{"id":"A","id":"B"}',
                campaign=self.campaign,
                bound=bound,
                elapsed_seconds=1.0,
            )
        with self.assertRaises(ExternalV3PolicyError):
            parse_external_response_v3(
                ("[" * 33 + "]" * 33).encode("ascii"),
                campaign=self.campaign,
                bound=bound,
                elapsed_seconds=1.0,
            )
        output = _output(bound.round_id)
        output["findings"][0]["rationale"] = "UNREGISTEREDVOCABULARY."
        with self.assertRaises(ExternalV3PolicyError):
            parse_external_response_v3(
                _response(bound.round_id, output=output),
                campaign=self.campaign,
                bound=bound,
                elapsed_seconds=1.0,
            )

        claim = self.ledger.claim(
            self.campaign, bound, owner_nonce="claim_" + "8" * 32
        )
        raw = _response(bound.round_id)
        receipt = execute_scripted_fake_round_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            claim=claim,
            transport=ScriptedFakeTransport(
                kind="RESPONSE", response_bytes=raw, elapsed_seconds=1.0
            ),
        )
        self.assertEqual(hashlib.sha256(raw).hexdigest(), receipt["raw_response_sha256"])
        self.assertEqual(len(raw), receipt["response_bytes"])

    def test_network_locator_matrix_is_rejected_before_positive_vocabulary(self) -> None:
        for locator in (
            "127.0.0.1",
            "2001:DB8::1",
            "::1",
            "HOST:443",
            "HTTPS://EXAMPLE.COM",
            "EXAMPLE.COM",
            "%2F",
        ):
            output = _output(ROUND_IDS[0])
            output["findings"][0]["rationale"] = f"CONNECT {locator}."
            with self.subTest(locator=locator):
                with self.assertRaisesRegex(
                    ExternalV3PolicyError, "network locator"
                ):
                    external_v3._validate_external_public_advisory(
                        output, round_id=ROUND_IDS[0]
                    )


class ExternalV3DurableArtifactTests(ExternalV3TestCase):
    def _commit_public_success(self, *, suffix: str = ""):
        if suffix:
            root = self.data_root / suffix
            root.mkdir()
            ledger = ExternalCampaignLedgerV3(
                root / "ledger.sqlite3", data_root=root
            )
            self.addCleanup(ledger.close)
            ledger.install(self.campaign)
            ledger.approve_fake(
                self.campaign, approval_evidence_sha256="d" * 64
            )
        else:
            ledger = self.ledger
        bound = ledger.bind_next_request(self.campaign)
        claim = ledger.claim(
            self.campaign,
            bound,
            owner_nonce="claim_" + ("9" if not suffix else suffix[-1]) * 32,
        )
        intent = ledger.mark_dispatch_intent(self.campaign, claim)
        raw = _response(bound.round_id)
        receipt = ledger.commit_success(
            self.campaign,
            intent,
            raw_response_bytes=raw,
            elapsed_seconds=1.0,
        )
        artifact = ledger._success_replay_path(self.campaign, bound)
        return ledger, bound, raw, receipt, artifact

    def test_success_raw_is_isolated_and_replayed_before_consume_and_reopen(self) -> None:
        ledger, bound, raw, receipt, artifact = self._commit_public_success()
        info = artifact.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(1, info.st_nlink)
        self.assertEqual(raw, artifact.read_bytes())
        receipt_text = canonical_json(receipt)
        self.assertNotIn(str(artifact), receipt_text)
        self.assertNotIn(artifact.name, receipt_text)
        self.assertEqual(
            "VERIFIABLE_BY_PUBLIC_RAW_REPLAY", receipt["audit_verifiability"]
        )

        restarted = ExternalCampaignLedgerV3(
            ledger.path, data_root=ledger.data_root
        )
        self.assertEqual(
            "RESPONSE_COMMITTED",
            restarted.snapshot(self.campaign)["rounds"][0]["state"],
        )
        consumed = restarted.consume_committed(self.campaign, ordinal=0)
        self.assertEqual("SUCCEEDED", consumed["status"])
        next_bound = restarted.bind_next_request(self.campaign)
        self.assertEqual(1, next_bound.ordinal)
        request = json.loads(next_bound.request_bytes)
        user_payload = json.loads(request["messages"][1]["content"])
        self.assertEqual(
            bound.round_id, user_payload["prior_advisory"]["round_id"]
        )

    def test_success_replay_rejects_joint_db_and_receipt_identity_drift(self) -> None:
        ledger, _bound, _raw, _receipt, _artifact = self._commit_public_success()
        connection = sqlite3.connect(ledger._sqlite_path)
        raw_receipt = connection.execute(
            "SELECT receipt_bytes FROM rounds WHERE ordinal=0"
        ).fetchone()[0]
        value = json.loads(raw_receipt)
        value["created_at"] = "2030-01-01T00:00:00Z"
        changed = canonical_json(value).encode("utf-8")
        connection.execute(
            "UPDATE rounds SET receipt_bytes=?,receipt_sha256=? WHERE ordinal=0",
            (changed, hashlib.sha256(changed).hexdigest()),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ExternalV3StateError):
            ledger.snapshot(self.campaign)
        with self.assertRaises(ExternalV3StateError):
            ExternalCampaignLedgerV3(ledger.path, data_root=ledger.data_root)

    def test_success_replay_rejects_hardlink_and_reparse_identity(self) -> None:
        ledger, _bound, _raw, _receipt, artifact = self._commit_public_success(
            suffix="artifact1"
        )
        hardlink = ledger.data_root / "artifact-hardlink"
        try:
            os.link(artifact, hardlink)
        except OSError as error:
            self.skipTest(f"hard links unavailable: {type(error).__name__}")
        with self.assertRaises(ExternalV3StateError):
            ledger.snapshot(self.campaign)

        ledger, _bound, _raw, _receipt, artifact = self._commit_public_success(
            suffix="artifact2"
        )
        if os.name == "nt":
            artifact_handle = external_v3._win_open_absolute(
                artifact, directory=False
            )
            try:
                artifact_identity = external_v3._win_handle_identity(
                    artifact_handle
                )
            finally:
                external_v3._win_close(artifact_handle)
            original_require = external_v3._win_require_file_handle

            def report_artifact_as_reparse(
                handle: int, *, readonly: bool
            ):
                info = original_require(handle, readonly=readonly)
                if external_v3._win_handle_identity(handle) == artifact_identity:
                    raise OSError("synthetic reparse identity")
                return info

            patcher = mock.patch.object(
                external_v3,
                "_win_require_file_handle",
                side_effect=report_artifact_as_reparse,
            )
        else:
            artifact_inode = artifact.lstat().st_ino
            original = external_v3.stat_is_reparse_point

            def report_artifact_as_reparse(info: os.stat_result) -> bool:
                return info.st_ino == artifact_inode or original(info)

            patcher = mock.patch.object(
                external_v3,
                "stat_is_reparse_point",
                side_effect=report_artifact_as_reparse,
            )
        with patcher:
            with self.assertRaises(ExternalV3StateError):
                ledger.snapshot(self.campaign)

    def test_success_replay_fails_closed_on_path_toctou(self) -> None:
        ledger, _bound, _raw, _receipt, artifact = self._commit_public_success(
            suffix="artifact3"
        )
        if os.name == "nt":
            original_verify = external_v3._win_verify_absolute_identity
            calls = 0

            def raced_verify(path: Path, *args: object, **kwargs: object):
                nonlocal calls
                if path == artifact:
                    calls += 1
                    if calls == 2:
                        raise OSError("synthetic path replacement")
                return original_verify(path, *args, **kwargs)

            patcher = mock.patch.object(
                external_v3,
                "_win_verify_absolute_identity",
                side_effect=raced_verify,
            )
        else:
            original_lstat = Path.lstat
            calls = 0

            def raced_lstat(path: Path, *args: object, **kwargs: object):
                nonlocal calls
                if path == artifact:
                    calls += 1
                    if calls == 2:
                        raise FileNotFoundError(str(path))
                return original_lstat(path, *args, **kwargs)

            patcher = mock.patch.object(Path, "lstat", new=raced_lstat)
        with patcher:
            with self.assertRaises(ExternalV3StateError):
                ledger.snapshot(self.campaign)

    def test_readonly_drift_fails_every_replay_boundary(self) -> None:
        ledger, _bound, _raw, _receipt, artifact = self._commit_public_success(
            suffix="artifact4"
        )
        os.chmod(artifact, stat.S_IWRITE)
        with self.assertRaises(ExternalV3StateError):
            ledger.snapshot(self.campaign)
        with self.assertRaises(ExternalV3StateError):
            ExternalCampaignLedgerV3(ledger.path, data_root=ledger.data_root)

    @unittest.skipUnless(os.name == "nt", "Windows RootDirectory boundary")
    def test_data_and_artifact_root_replacement_before_payload_fail_closed(self) -> None:
        for suffix, root_name in (
            ("rootrace1", "data"),
            ("rootrace2", "artifact"),
        ):
            with self.subTest(root=root_name):
                root = self.data_root / suffix
                root.mkdir()
                ledger = ExternalCampaignLedgerV3(root / "ledger.sqlite3", data_root=root)
                self.addCleanup(ledger.close)
                ledger.install(self.campaign)
                ledger.approve_fake(
                    self.campaign, approval_evidence_sha256="d" * 64
                )
                bound = ledger.bind_next_request(self.campaign)
                claim = ledger.claim(
                    self.campaign,
                    bound,
                    owner_nonce="claim_" + suffix[-1] * 32,
                )
                intent = ledger.mark_dispatch_intent(self.campaign, claim)
                raced_path = (
                    ledger.data_root
                    if root_name == "data"
                    else ledger._success_replay_root
                )
                original = external_v3._win_verify_absolute_identity
                observations = 0

                def race(path: Path, *args: object, **kwargs: object):
                    nonlocal observations
                    artifact_boundary = not (
                        root_name == "data"
                        and args
                        and args[0] == ledger._managed_root_guard_handle
                    )
                    if path == raced_path and artifact_boundary:
                        observations += 1
                        if observations == 2:
                            raise OSError("synthetic root identity replacement")
                    return original(path, *args, **kwargs)

                with mock.patch.object(
                    external_v3,
                    "_win_verify_absolute_identity",
                    side_effect=race,
                ):
                    with self.assertRaises(ExternalV3StateError):
                        ledger.commit_success(
                            self.campaign,
                            intent,
                            raw_response_bytes=_response(bound.round_id),
                            elapsed_seconds=1.0,
                        )
                restarted = ExternalCampaignLedgerV3(
                    ledger.path, data_root=ledger.data_root
                )
                self.addCleanup(restarted.close)
                self.assertEqual(
                    "ARTIFACT_RECOVERY_REQUIRED",
                    restarted.snapshot(self.campaign)["rounds"][0]["state"],
                )

    def test_artifact_and_commitment_flush_and_all_restart_cuts(self) -> None:
        cases = (
            ("AFTER_PREPARE_COMMIT", True),
            ("AFTER_PAYLOAD_FSYNC", True),
            ("AFTER_READONLY_SEAL", False),
            ("BEFORE_FINALIZE_COMMIT", False),
            ("AFTER_FINALIZE_COMMIT", False),
        )
        for kind in ("SUCCESS_REPLAY", "TERMINAL_COMMITMENT"):
            for index, (cut, recovery_required) in enumerate(cases):
                with self.subTest(kind=kind, cut=cut):
                    root = self.data_root / f"cut-{kind.lower()}-{index}"
                    root.mkdir()
                    ledger = ExternalCampaignLedgerV3(
                        root / "ledger.sqlite3", data_root=root
                    )
                    ledger.install(self.campaign)
                    ledger.approve_fake(
                        self.campaign, approval_evidence_sha256="d" * 64
                    )
                    bound = ledger.bind_next_request(self.campaign)
                    claim = ledger.claim(
                        self.campaign,
                        bound,
                        owner_nonce="claim_" + f"{index + (1 if kind == 'SUCCESS_REPLAY' else 9):032x}",
                    )
                    intent = ledger.mark_dispatch_intent(self.campaign, claim)
                    observed: list[tuple[str, str]] = []

                    def cutpoint(observed_kind: str, phase: str) -> None:
                        observed.append((observed_kind, phase))
                        if observed_kind == kind and phase == cut:
                            raise RuntimeError(f"synthetic restart cut: {phase}")

                    flush_target = (
                        "_win_flush" if os.name == "nt" else "fsync"
                    )
                    flush_owner = external_v3 if os.name == "nt" else os
                    flush_original = getattr(flush_owner, flush_target)
                    with mock.patch.object(
                        ExternalCampaignLedgerV3,
                        "_artifact_write_cutpoint",
                        side_effect=cutpoint,
                    ), mock.patch.object(
                        flush_owner,
                        flush_target,
                        wraps=flush_original,
                    ) as flush:
                        with self.assertRaisesRegex(RuntimeError, cut):
                            if kind == "SUCCESS_REPLAY":
                                ledger.commit_success(
                                    self.campaign,
                                    intent,
                                    raw_response_bytes=_response(bound.round_id),
                                    elapsed_seconds=1.0,
                                )
                            else:
                                ledger.commit_terminal_no_retry(
                                    self.campaign,
                                    intent,
                                    status="AMBIGUOUS_NO_RETRY",
                                    error_code="PROCESS_LOST_AFTER_INTENT",
                                )
                    if cut != "AFTER_PREPARE_COMMIT":
                        self.assertGreaterEqual(flush.call_count, 1)
                    restarted = ExternalCampaignLedgerV3(
                        ledger.path, data_root=ledger.data_root
                    )
                    state = restarted.snapshot(self.campaign)["rounds"][0]["state"]
                    expected_recovery = (
                        "ARTIFACT_RECOVERY_REQUIRED"
                        if kind == "SUCCESS_REPLAY"
                        else "COMMITMENT_RECOVERY_REQUIRED"
                    )
                    expected_final = (
                        "RESPONSE_COMMITTED"
                        if kind == "SUCCESS_REPLAY"
                        else "AMBIGUOUS_NO_RETRY"
                    )
                    self.assertEqual(
                        expected_recovery if recovery_required else expected_final,
                        state,
                    )
                    if recovery_required:
                        recovered_intent = restarted.load_dispatch_intent(
                            self.campaign, ordinal=0
                        )
                        if kind == "SUCCESS_REPLAY":
                            restarted.commit_success(
                                self.campaign,
                                recovered_intent,
                                raw_response_bytes=_response(bound.round_id),
                                elapsed_seconds=1.0,
                            )
                        else:
                            restarted.commit_terminal_no_retry(
                                self.campaign,
                                recovered_intent,
                                status="AMBIGUOUS_NO_RETRY",
                                error_code="PROCESS_LOST_AFTER_INTENT",
                            )
                        self.assertEqual(
                            expected_final,
                            restarted.snapshot(self.campaign)["rounds"][0]["state"],
                        )


class ExternalV3OnceOnlyTests(ExternalV3TestCase):
    def _make_process_loss_terminal(self, suffix: str):
        root = self.data_root / suffix
        root.mkdir()
        ledger = ExternalCampaignLedgerV3(root / "ledger.sqlite3", data_root=root)
        ledger.install(self.campaign)
        ledger.approve_fake(self.campaign, approval_evidence_sha256="d" * 64)
        bound = ledger.bind_next_request(self.campaign)
        nonce = "claim_" + suffix[-1] * 32
        claim = ledger.claim(self.campaign, bound, owner_nonce=nonce)
        ledger.mark_dispatch_intent(self.campaign, claim)
        receipt = mark_orphaned_dispatch_ambiguous_v3(
            ledger=ledger, campaign=self.campaign, ordinal=0
        )
        commitment = ledger._terminal_commitment_path(self.campaign, bound)
        return ledger, bound, receipt, commitment

    def test_ambiguous_after_intent_is_terminal_and_never_retried(self) -> None:
        _bound, claim = self._claim()
        fake = ScriptedFakeTransport(
            kind="TIMEOUT_AFTER_INTENT", elapsed_seconds=91.0
        )
        receipt = execute_scripted_fake_round_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            claim=claim,
            transport=fake,
        )
        self.assertEqual("AMBIGUOUS_NO_RETRY", receipt["status"])
        self.assertEqual("WALL_CLOCK_TIMEOUT_AFTER_INTENT", receipt["error_code"])
        snapshot = self.ledger.snapshot(self.campaign)
        self.assertEqual("AMBIGUOUS", snapshot["state"])
        self.assertEqual("AMBIGUOUS_NO_RETRY", snapshot["rounds"][0]["state"])
        self.assertEqual(1, snapshot["rounds"][0]["attempts"])

    def test_response_commit_survives_restart_without_second_send(self) -> None:
        bound, claim = self._claim()
        intent = self.ledger.mark_dispatch_intent(self.campaign, claim)
        self.ledger.commit_success(
            self.campaign,
            intent,
            raw_response_bytes=_response(bound.round_id),
            elapsed_seconds=1.0,
        )
        restarted = ExternalCampaignLedgerV3(
            self.ledger.path, data_root=self.data_root
        )
        receipt = restarted.consume_committed(self.campaign, ordinal=0)
        self.assertEqual("SUCCEEDED", receipt["status"])
        self.assertEqual("CONSUMED", restarted.snapshot(self.campaign)["rounds"][0]["state"])

    def test_restart_replays_committed_content_and_recovers_pre_dispatch_claim(self) -> None:
        bound, _claim = self._claim()
        restarted = ExternalCampaignLedgerV3(
            self.ledger.path, data_root=self.data_root
        )
        recovered = restarted.recover_claim_before_dispatch(
            self.campaign, ordinal=0
        )
        self.assertEqual(bound, recovered)
        new_claim = restarted.claim(
            self.campaign,
            recovered,
            owner_nonce="claim_" + "a" * 32,
        )
        intent = restarted.mark_dispatch_intent(self.campaign, new_claim)
        restarted.commit_success(
            self.campaign,
            intent,
            raw_response_bytes=_response(bound.round_id),
            elapsed_seconds=1.0,
        )
        connection = sqlite3.connect(restarted._sqlite_path)
        connection.execute(
            "UPDATE rounds SET advisory_sha256=? WHERE ordinal=0", ("f" * 64,)
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ExternalV3StateError):
            restarted.consume_committed(self.campaign, ordinal=0)

    def test_orphaned_dispatch_is_resolved_ambiguous_without_retry(self) -> None:
        _bound, claim = self._claim()
        self.ledger.mark_dispatch_intent(self.campaign, claim)
        restarted = ExternalCampaignLedgerV3(
            self.ledger.path, data_root=self.data_root
        )
        receipt = mark_orphaned_dispatch_ambiguous_v3(
            ledger=restarted,
            campaign=self.campaign,
            ordinal=0,
        )
        self.assertEqual("AMBIGUOUS_NO_RETRY", receipt["status"])
        self.assertEqual("PROCESS_LOST_AFTER_INTENT", receipt["error_code"])
        self.assertEqual(1, restarted.snapshot(self.campaign)["rounds"][0]["attempts"])

    def test_terminal_status_error_matrix_is_closed(self) -> None:
        _bound, claim = self._claim()
        intent = self.ledger.mark_dispatch_intent(self.campaign, claim)
        with self.assertRaises(ExternalV3StateError):
            self.ledger.commit_terminal_no_retry(
                self.campaign,
                intent,
                status="FAILED_NO_RETRY",
                error_code="PROCESS_LOST_AFTER_INTENT",
            )
        self.assertEqual(
            "DISPATCH_INTENT",
            self.ledger.snapshot(self.campaign)["rounds"][0]["state"],
        )
        receipt = mark_orphaned_dispatch_ambiguous_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            ordinal=0,
        )
        self.assertEqual("AMBIGUOUS_NO_RETRY", receipt["status"])

    def test_terminal_receipt_is_fully_replayed_on_load_snapshot_and_reopen(self) -> None:
        _bound, claim = self._claim()
        self.ledger.mark_dispatch_intent(self.campaign, claim)
        expected = mark_orphaned_dispatch_ambiguous_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            ordinal=0,
        )
        restarted = ExternalCampaignLedgerV3(
            self.ledger.path, data_root=self.data_root
        )
        loaded = restarted.load_terminal_receipt(self.campaign, ordinal=0)
        self.assertEqual(expected["receipt_sha256"], loaded["receipt_sha256"])
        self.assertEqual("PROCESS_LOST_AFTER_INTENT", loaded["error_code"])
        self.assertEqual(
            "UNVERIFIABLE_NO_TRUSTED_ANCHOR",
            loaded["audit_verifiability"],
        )
        commitment_path = restarted._terminal_commitment_path(
            self.campaign, external_v3.derive_external_round_v3(self.campaign, ordinal=0)
        )
        commitment = json.loads(commitment_path.read_bytes())
        self.assertEqual(expected["receipt_sha256"], commitment["receipt_sha256"])
        self.assertEqual(
            "UNVERIFIABLE_NO_TRUSTED_ANCHOR",
            commitment["audit_verifiability"],
        )
        self.assertIsNone(commitment["raw_response_sha256"])
        self.assertIsNone(commitment["response_bytes"])

        connection = sqlite3.connect(self.ledger._sqlite_path)
        raw = connection.execute(
            "SELECT receipt_bytes FROM rounds WHERE ordinal=0"
        ).fetchone()[0]
        receipt = json.loads(raw)
        receipt["error_code"] = "INVENTED_ERROR"
        tampered = canonical_json(receipt).encode("utf-8")
        connection.execute(
            "UPDATE rounds SET receipt_bytes=?,receipt_sha256=? WHERE ordinal=0",
            (tampered, hashlib.sha256(tampered).hexdigest()),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ExternalV3StateError):
            self.ledger.snapshot(self.campaign)
        with self.assertRaises(ExternalV3StateError):
            self.ledger.load_terminal_receipt(self.campaign, ordinal=0)
        with self.assertRaises(ExternalV3StateError):
            ExternalCampaignLedgerV3(self.ledger.path, data_root=self.data_root)

    def test_terminal_commitment_missing_or_replaced_fails_closed(self) -> None:
        ledger, _bound, _receipt, commitment = self._make_process_loss_terminal(
            "terminal1"
        )
        os.chmod(commitment, stat.S_IWRITE)
        commitment.unlink()
        with self.assertRaisesRegex(ExternalV3StateError, "artifact"):
            ledger.snapshot(self.campaign)
        with self.assertRaisesRegex(ExternalV3StateError, "artifact"):
            ExternalCampaignLedgerV3(ledger.path, data_root=ledger.data_root)

        ledger, _bound, _receipt, commitment = self._make_process_loss_terminal(
            "terminal2"
        )
        os.chmod(commitment, stat.S_IWRITE)
        commitment.write_bytes(b"{}")
        os.chmod(commitment, stat.S_IREAD)
        with self.assertRaisesRegex(ExternalV3StateError, "commitment"):
            ledger.load_terminal_receipt(self.campaign, ordinal=0)
        with self.assertRaisesRegex(ExternalV3StateError, "commitment"):
            ExternalCampaignLedgerV3(ledger.path, data_root=ledger.data_root)

    def test_terminal_commitment_rejects_coherent_db_and_receipt_drift(self) -> None:
        ledger, _bound, _receipt, _commitment = self._make_process_loss_terminal(
            "terminal3"
        )
        connection = sqlite3.connect(ledger._sqlite_path)
        raw_receipt = connection.execute(
            "SELECT receipt_bytes FROM rounds WHERE ordinal=0"
        ).fetchone()[0]
        value = json.loads(raw_receipt)
        value["error_code"] = "TRANSPORT_RESULT_AMBIGUOUS"
        value["elapsed_seconds"] = 1.0
        changed = canonical_json(value).encode("utf-8")
        changed_sha = hashlib.sha256(changed).hexdigest()
        connection.execute(
            "UPDATE rounds SET receipt_bytes=?,receipt_sha256=?,elapsed_seconds=1.0 WHERE ordinal=0",
            (changed, changed_sha),
        )
        connection.execute("UPDATE campaigns SET elapsed_seconds=1.0")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(ExternalV3StateError, "terminal commitment"):
            ledger.snapshot(self.campaign)
        with self.assertRaisesRegex(ExternalV3StateError, "terminal commitment"):
            ledger.load_terminal_receipt(self.campaign, ordinal=0)

    def test_known_invalid_terminal_rebinds_raw_hash_size_and_elapsed(self) -> None:
        bound, claim = self._claim()
        raw = b'{"upstream":"Bearer sk-public-test-redacted"}'
        expected = execute_scripted_fake_round_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            claim=claim,
            transport=ScriptedFakeTransport(
                kind="RESPONSE", response_bytes=raw, elapsed_seconds=1.0
            ),
        )
        restarted = ExternalCampaignLedgerV3(
            self.ledger.path, data_root=self.data_root
        )
        loaded = restarted.load_terminal_receipt(self.campaign, ordinal=0)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), loaded["raw_response_sha256"])
        self.assertEqual(len(raw), loaded["response_bytes"])
        self.assertEqual(1.0, loaded["elapsed_seconds"])
        self.assertNotIn("public-test-redacted", canonical_json(loaded))
        self.assertEqual(expected["receipt_sha256"], loaded["receipt_sha256"])

        connection = sqlite3.connect(self.ledger._sqlite_path)
        connection.execute(
            "UPDATE rounds SET response_bytes=response_bytes+1 WHERE ordinal=0"
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ExternalV3StateError):
            restarted.snapshot(self.campaign)

    def test_thirty_two_os_processes_claim_once_and_survive_sidecar_churn(self) -> None:
        bound = self.ledger.bind_next_request(self.campaign)
        ready_root = self.data_root / "process-ready"
        ready_root.mkdir()
        gate = self.data_root / "process-go"
        source_root = Path(__file__).resolve().parents[1] / "src"
        child = r'''
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, sys.argv[1])
from quant_hub.knowledge.ds_review import ProviderPin
from quant_hub.knowledge.ds_review_external_v3 import (
    ExternalCampaignLedgerV3,
    ExternalV3StateError,
    PricingBudgetV3,
    derive_external_round_v3,
    prepare_external_campaign_v3,
)

root = Path(sys.argv[2])
database = Path(sys.argv[3])
index = int(sys.argv[4])
pricing = PricingBudgetV3(
    currency="USD_MICRO",
    prompt_micros_per_million=2_000_000,
    completion_micros_per_million=8_000_000,
    pricing_evidence_sha256="a" * 64,
    max_campaign_cost_micros=1_000_000,
    max_prompt_tokens_per_round=96 * 1024,
    max_completion_tokens_per_round=4096,
    max_campaign_total_tokens=4 * (96 * 1024 + 4096),
    max_request_bytes=96 * 1024,
    max_response_bytes=256 * 1024,
    per_round_deadline_seconds=90,
    campaign_deadline_seconds=360,
)
campaign = prepare_external_campaign_v3(
    pin=ProviderPin.create(
        expected_system_fingerprint="fp-public-synthetic-external-v3"
    ),
    identity_evidence_sha256="b" * 64,
    pricing=pricing,
    transport_build_sha256="c" * 64,
)
bound = derive_external_round_v3(campaign, ordinal=0)
ledger = ExternalCampaignLedgerV3(database, data_root=root)
(root / "process-ready" / str(index)).write_bytes(b"1")
deadline = time.monotonic() + 30.0
while not (root / "process-go").exists():
    if time.monotonic() > deadline:
        print(json.dumps({"index": index, "error": "BARRIER_TIMEOUT"}))
        raise SystemExit(3)
    time.sleep(0.002)
won = False
try:
    ledger.claim(
        campaign,
        bound,
        owner_nonce="claim_" + f"{index + 1:032x}",
    )
    won = True
except ExternalV3StateError as error:
    if str(error) not in {
        "bound request is not the durable derivation",
        "round claim CAS failed",
    }:
        print(json.dumps({"index": index, "error": "UNEXPECTED_CLAIM_STATE"}))
        raise SystemExit(5)
try:
    for _ in range(20):
        ExternalCampaignLedgerV3(database, data_root=root).snapshot(campaign)
except Exception as error:
    print(json.dumps({"index": index, "error": type(error).__name__}))
    raise SystemExit(4)
print(json.dumps({"index": index, "won": won, "snapshots": 20}))
'''
        processes = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    child,
                    str(source_root),
                    str(self.data_root),
                    str(self.ledger.path),
                    str(index),
                ],
                cwd=Path.cwd(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for index in range(32)
        ]
        deadline = time.monotonic() + 30.0
        while (
            len(list(ready_root.iterdir())) < 32
            and time.monotonic() < deadline
            and all(process.poll() is None for process in processes)
        ):
            time.sleep(0.01)
        ready_count = len(list(ready_root.iterdir()))
        gate.write_bytes(b"go")
        results = []
        diagnostics = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=40)
            diagnostics.append((process.returncode, stderr))
            if stdout.strip():
                results.append(json.loads(stdout.strip().splitlines()[-1]))
        self.assertEqual(32, ready_count, diagnostics)
        self.assertEqual([(0, "")] * 32, diagnostics)
        self.assertEqual(32, len(results))
        self.assertTrue(all(result.get("snapshots") == 20 for result in results))
        winners = [result for result in results if result.get("won") is True]
        self.assertEqual(1, len(winners))
        winner_index = winners[0]["index"]
        winner_nonce = "claim_" + f"{winner_index + 1:032x}"
        winner = external_v3.ClaimedExternalRoundV3(
            bound=bound,
            owner_nonce=winner_nonce,
            owner_nonce_sha256=hashlib.sha256(winner_nonce.encode("ascii")).hexdigest(),
        )
        self.ledger.mark_dispatch_intent(self.campaign, winner)
        snapshot = self.ledger.snapshot(self.campaign)
        self.assertEqual("DISPATCH_INTENT", snapshot["rounds"][0]["state"])
        self.assertEqual(1, snapshot["rounds"][0]["attempts"])
        receipt = mark_orphaned_dispatch_ambiguous_v3(
            ledger=self.ledger,
            campaign=self.campaign,
            ordinal=0,
        )
        self.assertEqual("AMBIGUOUS_NO_RETRY", receipt["status"])


if __name__ == "__main__":
    unittest.main()

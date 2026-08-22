from __future__ import annotations

from contextlib import closing, redirect_stdout
from dataclasses import asdict, fields, replace
import hashlib
from io import StringIO
import inspect
import json
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.knowledge import ds_review
from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge.ds_review import (
    CampaignLedger,
    CampaignStateError,
    ClaimedRound,
    DossierPolicyError,
    EXTERNAL_TRANSPORT_STATE,
    ExternalReviewDisabled,
    MECHANISMS,
    PreparedReview,
    ProviderPin,
    ROUND_IDS,
    SCENARIO_ROWS,
    audit_final_request_bytes,
    default_synthetic_dossier,
    dry_run_receipt,
    external_review,
    new_supervisor_nonce,
    parse_provider_response,
    prepare_campaign,
    validate_campaign,
    validate_review_output,
)
from quant_hub.knowledge.ds_review_cli import main as dry_run_main


FIXTURE_FINGERPRINT = "fp-public-synthetic-0813"


def _pin(value: str = FIXTURE_FINGERPRINT) -> ProviderPin:
    return ProviderPin.create(expected_system_fingerprint=value)


def _valid_output(round_id: str) -> dict[str, object]:
    return {
        "schema_version": "qrh-ds-architecture-review-output/v2",
        "round_id": round_id,
        "release_position": "block",
        "findings": [
            {
                "finding_id": "F-001",
                "severity": "blocker",
                "mechanism_id": "M01",
                "rationale": "ONE_TRANSITION_PERMITS_TWO_WORKERS_TO_OWN_ONE_JOB.",
                "falsification_test": "RELEASE_SIXTEEN_WORKERS_AT_ONE_BARRIER_AND_COUNT_SIDE_EFFECTS.",
                "minimal_change": "CLAIM_WITH_ONE_CONDITIONAL_UPDATE_AND_A_UNIQUE_OWNER_NONCE.",
                "residual_risk": "KILLED_OWNER_STILL_REQUIRES_EXPIRY_AND_RECOVERY_RULE.",
            }
        ],
        "dissent": {
            "why_not_release": ["EXACTLY_ONCE_INVARIANT_ALREADY_FALSIFIED."],
            "missing_stress_cases": ["KILL_WINNER_AFTER_EXTERNAL_SIDE_EFFECT."],
            "assumptions_to_break": ["DO_NOT_ASSUME_ONE_WORKER_PER_PROCESS."],
        },
    }


def _response_bytes(
    round_id: str,
    *,
    fingerprint: str = FIXTURE_FINGERPRINT,
    created: object = 1787270400,
    output: object | None = None,
) -> bytes:
    value = {
        "id": "public-synthetic-response",
        "created": created,
        "model": "deepseek-v4-pro",
        "system_fingerprint": fingerprint,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": canonical_json(output or _valid_output(round_id)),
                },
                "finish_reason": "stop",
            }
        ],
    }
    return canonical_json(value).encode("utf-8")


def _claim_worker(
    database: str,
    campaign_id: str,
    manifest_sha256: str,
    owner_nonce: str,
    start: object,
    results: object,
) -> None:
    start.wait(15)
    try:
        claim = CampaignLedger(Path(database)).claim_next(
            campaign_id,
            manifest_sha256=manifest_sha256,
            owner_nonce=owner_nonce,
        )
        results.put(("claimed", claim.owner_nonce, claim.review.ordinal, ""))
    except Exception as error:
        results.put(("rejected", owner_nonce, -1, type(error).__name__))


def _claim_then_wait_worker(
    database: str,
    campaign_id: str,
    manifest_sha256: str,
    owner_nonce: str,
    committed: object,
    hold: object,
) -> None:
    CampaignLedger(Path(database)).claim_next(
        campaign_id,
        manifest_sha256=manifest_sha256,
        owner_nonce=owner_nonce,
    )
    committed.set()
    hold.wait(60)


class DSReviewImmutableContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.campaign = prepare_campaign(default_synthetic_dossier(), pin=_pin())

    def test_prepared_review_holds_only_bytes_hashes_and_immutable_scalars(self) -> None:
        self.assertEqual(
            {
                "round_id",
                "ordinal",
                "request_bytes",
                "request_sha256",
                "dossier_sha256",
                "provider_pin_sha256",
            },
            {field.name for field in fields(PreparedReview)},
        )
        for review in self.campaign.rounds:
            self.assertIs(type(review.request_bytes), bytes)
            self.assertNotIn("dict", {type(getattr(review, field.name)).__name__ for field in fields(review)})
        with self.assertRaises((AttributeError, TypeError)):
            self.campaign.rounds[0].ordinal = 9

    def test_send_boundary_redecodes_and_rejects_request_or_hash_tamper(self) -> None:
        original = self.campaign.rounds[0]
        tampered = replace(original, request_bytes=original.request_bytes + b" ")
        campaign = replace(
            self.campaign,
            rounds=(tampered,) + self.campaign.rounds[1:],
        )
        with self.assertRaises(DossierPolicyError):
            dry_run_receipt(campaign, round_id=ROUND_IDS[0])
        forged = replace(
            tampered,
            request_sha256=ds_review._sha256_bytes(tampered.request_bytes),
        )
        campaign = replace(self.campaign, rounds=(forged,) + self.campaign.rounds[1:])
        with self.assertRaises(DossierPolicyError):
            dry_run_receipt(campaign, round_id=ROUND_IDS[0])

    def test_final_canonical_request_bytes_are_independently_policy_scanned(self) -> None:
        base = json.loads(self.campaign.rounds[3].request_bytes)
        counterexamples = (
            "Bearer sk-syntheticvalue",
            "contact john smith",
            "john smith",
            "j smith",
            "C:relative",
            "C:.",
            "C:..",
            "C: relative",
            "relative/path",
            "password value",
            "password123",
            "secretvalue",
            "credentialABC",
            "authorization999",
            "token value",
            "token123",
            "nonascii \u91cf\u5316",
        )
        for counterexample in counterexamples:
            with self.subTest(counterexample=counterexample):
                request = json.loads(json.dumps(base))
                user = json.loads(request["messages"][1]["content"])
                user["contract"]["objective"] = counterexample
                request["messages"][1]["content"] = canonical_json(user)
                with self.assertRaises(DossierPolicyError):
                    audit_final_request_bytes(canonical_json(request).encode("utf-8"))

    def test_canonical_spec_bytes_ignore_exported_object_tamper(self) -> None:
        original_mechanism = SCENARIO_ROWS[0].mechanism
        original_objective = ds_review._ROUND_OBJECTIVES[ROUND_IDS[0]]
        try:
            object.__setattr__(SCENARIO_ROWS[0], "mechanism", "RUNTIME_TAMPER")
            ds_review._ROUND_OBJECTIVES[ROUND_IDS[0]] = "john smith"
            rebuilt = prepare_campaign(default_synthetic_dossier(), pin=_pin())
            self.assertEqual(
                self.campaign.manifest.manifest_bytes,
                rebuilt.manifest.manifest_bytes,
            )
            self.assertEqual(
                "SEMANTIC_JOB_CAS",
                default_synthetic_dossier().observations[0].mechanism,
            )
            validate_campaign(self.campaign)
        finally:
            object.__setattr__(SCENARIO_ROWS[0], "mechanism", original_mechanism)
            ds_review._ROUND_OBJECTIVES[ROUND_IDS[0]] = original_objective

        original_bytes = ds_review._SCENARIO_SPEC_BYTES
        try:
            ds_review._SCENARIO_SPEC_BYTES = original_bytes + b" "
            with self.assertRaises(DossierPolicyError):
                prepare_campaign(default_synthetic_dossier(), pin=_pin())
        finally:
            ds_review._SCENARIO_SPEC_BYTES = original_bytes

    def test_manifest_freezes_round_order_hashes_mapping_and_fingerprint(self) -> None:
        validate_campaign(self.campaign)
        self.assertIs(type(SCENARIO_ROWS), tuple)
        self.assertTrue(all(type(row) is ds_review.SyntheticObservation for row in SCENARIO_ROWS))
        with self.assertRaises((AttributeError, TypeError)):
            SCENARIO_ROWS[0].mechanism = "MUTATED"
        manifest = json.loads(self.campaign.manifest.manifest_bytes)
        self.assertEqual(list(ROUND_IDS), manifest["round_order"])
        self.assertEqual([asdict(row) for row in SCENARIO_ROWS], manifest["scenario_mapping"])
        self.assertEqual(
            [row.request_sha256 for row in self.campaign.rounds],
            [row["request_sha256"] for row in manifest["rounds"]],
        )
        self.assertEqual(FIXTURE_FINGERPRINT, manifest["provider_pin"]["expected_system_fingerprint"])
        manifest["scenario_mapping"][0]["mechanism"] = "LOCAL_COPY_ONLY"
        self.assertEqual("SEMANTIC_JOB_CAS", SCENARIO_ROWS[0].mechanism)
        changed = prepare_campaign(default_synthetic_dossier(), pin=_pin("fp-other-approved"))
        self.assertNotEqual(
            self.campaign.manifest.manifest_sha256,
            changed.manifest.manifest_sha256,
        )
        self.assertEqual(
            [row.request_sha256 for row in self.campaign.rounds],
            [row.request_sha256 for row in changed.rounds],
        )
        self.assertNotEqual(
            self.campaign.rounds[0].provider_pin_sha256,
            changed.rounds[0].provider_pin_sha256,
        )

    def test_round_one_is_anonymous_but_later_rounds_use_frozen_mapping(self) -> None:
        blind = self.campaign.rounds[0].request_bytes.decode("utf-8")
        self.assertIn("M01", blind)
        self.assertIn("CONCURRENCY", blind)
        self.assertIn("DURABILITY", blind)
        self.assertIn("RESOURCE", blind)
        for mechanism in MECHANISMS:
            self.assertNotIn(mechanism, blind)
        later = self.campaign.rounds[1].request_bytes.decode("utf-8")
        for mechanism in MECHANISMS:
            self.assertIn(mechanism, later)

    def test_scenario_id_pairing_and_bool_as_int_are_fail_closed(self) -> None:
        dossier = default_synthetic_dossier()
        first = dossier.observations[0]
        for changed in (
            replace(first, scenario_id="S99"),
            replace(first, mechanism_id="M02"),
            replace(first, process_count=True),
            replace(first, record_scale=False),
        ):
            bad = replace(dossier, observations=(changed,) + dossier.observations[1:])
            with self.assertRaises(DossierPolicyError):
                prepare_campaign(bad, pin=_pin())
        with self.assertRaises(DossierPolicyError):
            _pin("C:relative")
        for secret_like in (
            "sk-syntheticvalue",
            "token-fixture",
            "token_fixture",
            "token123",
            "password123",
            "secretvalue",
            "credentialABC",
            "authorization999",
            "authorization-fixture",
            "authorization_fixture",
            "Bearer-sk-syntheticvalue",
        ):
            with self.subTest(secret_like=secret_like):
                with self.assertRaises(DossierPolicyError):
                    _pin(secret_like)


class DSReviewStrictParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.campaign = prepare_campaign(default_synthetic_dossier(), pin=_pin())
        self.round_id = ROUND_IDS[3]

    def test_credential_free_fake_response_parser_returns_advisory_receipt(self) -> None:
        receipt = parse_provider_response(
            _response_bytes(self.round_id),
            campaign=self.campaign,
            round_id=self.round_id,
            elapsed_seconds=1.25,
        )
        self.assertEqual("advisory_parsed_without_transport", receipt["status"])
        self.assertEqual("ADVISORY_ONLY", receipt["authority"])
        self.assertEqual(0, receipt["network_calls_by_parser"])
        self.assertNotIn("system_fingerprint", receipt)
        self.assertEqual(
            hashlib.sha256(FIXTURE_FINGERPRINT.encode("utf-8")).hexdigest(),
            receipt["system_fingerprint_sha256"],
        )
        self.assertEqual(
            self.campaign.manifest.manifest_sha256,
            receipt["campaign_manifest_sha256"],
        )
        ordinary_output = json.dumps(_valid_output(self.round_id), indent=2)
        ordinary_outer = {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": ordinary_output, "role": "assistant"},
                    "index": 0,
                }
            ],
            "system_fingerprint": FIXTURE_FINGERPRINT,
            "model": "deepseek-v4-pro",
            "created": 1787270400,
            "id": "ordinary-json-response",
        }
        formatted = parse_provider_response(
            json.dumps(ordinary_outer, indent=2).encode("utf-8"),
            campaign=self.campaign,
            round_id=self.round_id,
            elapsed_seconds=2.0,
        )
        self.assertEqual(receipt["output_sha256"], formatted["output_sha256"])

    def test_output_rejects_path_secret_name_identity_and_non_ascii(self) -> None:
        counterexamples = (
            "Bearer sk-syntheticvalue",
            "sk-syntheticvalue",
            "inspect C:relative",
            "inspect C:.",
            "inspect C:..",
            "inspect C: relative",
            "password equals fixture",
            "password123",
            "secretvalue",
            "credentialABC",
            "authorization999",
            "access token equals fixture",
            "token123",
            "name: Alice",
            "name is Alice",
            "identity: operator",
            "identity is operator",
            "Alice Smith owns the result",
            "contact john smith",
            "john smith",
            "j smith",
            "contact user@example.com",
            "relative/path",
            "contains nonascii \u91cf\u5316",
        )
        for counterexample in counterexamples:
            with self.subTest(counterexample=counterexample):
                output = _valid_output(self.round_id)
                output["dissent"]["why_not_release"] = [counterexample]
                with self.assertRaises(DossierPolicyError):
                    validate_review_output(output, round_id=self.round_id)

        named_response = json.loads(_response_bytes(self.round_id))
        named_response["id"] = "john smith"
        with self.assertRaises(DossierPolicyError):
            parse_provider_response(
                canonical_json(named_response).encode("utf-8"),
                campaign=self.campaign,
                round_id=self.round_id,
                elapsed_seconds=1.0,
            )

    def test_exact_top_level_duplicate_keys_depth_and_bool_are_fail_closed(self) -> None:
        output = _valid_output(self.round_id)
        output["extra"] = True
        with self.assertRaises(DossierPolicyError):
            validate_review_output(output, round_id=self.round_id)

        duplicate = (
            b'{"id":"a","id":"b","created":1,"model":"deepseek-v4-pro",'
            b'"system_fingerprint":"fp-public-synthetic-0813","choices":[]}'
        )
        with self.assertRaises(DossierPolicyError):
            parse_provider_response(
                duplicate,
                campaign=self.campaign,
                round_id=self.round_id,
                elapsed_seconds=1.0,
            )

        deep = b"[" * 5_000 + b"0" + b"]" * 5_000
        with self.assertRaises(DossierPolicyError) as deep_error:
            parse_provider_response(
                deep,
                campaign=self.campaign,
                round_id=self.round_id,
                elapsed_seconds=1.0,
            )
        self.assertEqual(
            "provider response exceeds the JSON depth limit",
            str(deep_error.exception),
        )

        with self.assertRaises(DossierPolicyError):
            parse_provider_response(
                _response_bytes(self.round_id, created=True),
                campaign=self.campaign,
                round_id=self.round_id,
                elapsed_seconds=1.0,
            )

    def test_identity_response_size_and_overall_deadline_are_bound_to_manifest(self) -> None:
        with self.assertRaises(DossierPolicyError):
            parse_provider_response(
                _response_bytes(self.round_id, fingerprint="fp-drift"),
                campaign=self.campaign,
                round_id=self.round_id,
                elapsed_seconds=1.0,
            )
        with self.assertRaises(DossierPolicyError):
            parse_provider_response(
                b"x" * (ds_review.DS_REVIEW_MAX_RESPONSE_BYTES + 1),
                campaign=self.campaign,
                round_id=self.round_id,
                elapsed_seconds=1.0,
            )
        for invalid in (True, 90, 90.0001, -0.01):
            with self.subTest(elapsed=invalid):
                with self.assertRaises(DossierPolicyError):
                    parse_provider_response(
                        _response_bytes(self.round_id),
                        campaign=self.campaign,
                        round_id=self.round_id,
                        elapsed_seconds=invalid,
                    )

    def test_real_transport_and_injectable_secret_or_tls_surfaces_are_absent(self) -> None:
        source = inspect.getsource(ds_review)
        for forbidden in (
            "connection_factory",
            "HTTPSConnection",
            "EnvironmentSecretProvider",
            "KeyringSecretProvider",
            "ssl.SSLContext",
            "import socket",
            "urllib",
            "requests.",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(
            "DISABLED_PENDING_INDEPENDENT_APPROVAL", EXTERNAL_TRANSPORT_STATE
        )
        with self.assertRaises(ExternalReviewDisabled):
            external_review(self.campaign)


class DSReviewCampaignLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "review_campaign.sqlite3"
        self.campaign = prepare_campaign(default_synthetic_dossier(), pin=_pin())
        self.ledger = CampaignLedger(self.database)
        self.ledger.install(self.campaign)
        self.approval_sha = "a" * 64

    def _approve(self) -> None:
        self.ledger.approve_simulation(
            self.campaign.manifest.campaign_id,
            manifest_sha256=self.campaign.manifest.manifest_sha256,
            approval_evidence_sha256=self.approval_sha,
        )

    def _persist_envelope(
        self, owner_nonce: str, supervisor_nonce: str, intended_ordinal: int = 0
    ) -> None:
        self.ledger.persist_owner_envelope(
            self.campaign.manifest.campaign_id,
            manifest_sha256=self.campaign.manifest.manifest_sha256,
            owner_nonce=owner_nonce,
            supervisor_nonce=supervisor_nonce,
            intended_ordinal=intended_ordinal,
        )

    def test_exact_manifest_approval_order_and_once_only_consumption(self) -> None:
        with self.assertRaises(CampaignStateError):
            self.ledger.claim_next(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                owner_nonce="claim_" + "1" * 32,
            )
        with self.assertRaises(CampaignStateError):
            self.ledger.approve_simulation(
                self.campaign.manifest.campaign_id,
                manifest_sha256="0" * 64,
                approval_evidence_sha256=self.approval_sha,
            )
        self._approve()
        for ordinal in range(4):
            owner_nonce = "claim_" + f"{ordinal + 1:032x}"
            supervisor_nonce = "supervisor_" + f"{ordinal + 1:064x}"
            self._persist_envelope(owner_nonce, supervisor_nonce, ordinal)
            claim = self.ledger.claim_next(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                owner_nonce=owner_nonce,
            )
            self.assertEqual(ordinal, claim.review.ordinal)
            with self.assertRaises(CampaignStateError):
                self.ledger.claim_next(
                    self.campaign.manifest.campaign_id,
                    manifest_sha256=self.campaign.manifest.manifest_sha256,
                    owner_nonce="claim_" + "f" * 32,
                )
            outcome = "FAILED" if ordinal == 1 else "SUCCEEDED"
            with self.assertRaises(CampaignStateError):
                self.ledger.consume(
                    replace(claim, manifest_sha256="0" * 64),
                    outcome=outcome,
                    receipt_sha256=f"{ordinal + 1:064x}",
                )
            self.ledger.consume(claim, outcome=outcome, receipt_sha256=f"{ordinal + 1:064x}")
            with self.assertRaises(CampaignStateError):
                self.ledger.consume(claim, outcome=outcome, receipt_sha256=f"{ordinal + 1:064x}")
        snapshot = self.ledger.snapshot(self.campaign.manifest.campaign_id)
        self.assertEqual("COMPLETE", snapshot["state"])
        self.assertEqual(["CONSUMED"] * 4, [row["state"] for row in snapshot["rounds"]])
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(4, connection.execute("SELECT COUNT(*) FROM consumed_ledger").fetchone()[0])

    def test_cross_connection_claim_cas_has_exactly_one_winner(self) -> None:
        self._approve()
        self._persist_envelope(
            "claim_" + "1" * 32, "supervisor_" + "1" * 64
        )
        self._persist_envelope(
            "claim_" + "2" * 32, "supervisor_" + "2" * 64
        )
        winner = CampaignLedger(self.database).claim_next(
            self.campaign.manifest.campaign_id,
            manifest_sha256=self.campaign.manifest.manifest_sha256,
            owner_nonce="claim_" + "1" * 32,
        )
        with self.assertRaises(CampaignStateError):
            CampaignLedger(self.database).claim_next(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                owner_nonce="claim_" + "2" * 32,
            )
        self.ledger.consume(winner, outcome="FAILED", receipt_sha256="b" * 64)

    def test_consume_rejects_same_request_hash_from_another_provider_pin(self) -> None:
        other = prepare_campaign(
            default_synthetic_dossier(), pin=_pin("fp-other-approved")
        )
        self.assertEqual(
            self.campaign.rounds[0].request_sha256,
            other.rounds[0].request_sha256,
        )
        self.assertNotEqual(
            self.campaign.rounds[0].provider_pin_sha256,
            other.rounds[0].provider_pin_sha256,
        )
        self._approve()
        owner = "claim_" + "7" * 32
        self._persist_envelope(owner, "supervisor_" + "7" * 64)
        claim = self.ledger.claim_next(
            self.campaign.manifest.campaign_id,
            manifest_sha256=self.campaign.manifest.manifest_sha256,
            owner_nonce=owner,
        )
        mixed = replace(claim, review=other.rounds[0])
        with self.assertRaises(CampaignStateError):
            self.ledger.consume(
                mixed, outcome="FAILED", receipt_sha256="7" * 64
            )
        self.ledger.consume(
            claim, outcome="FAILED", receipt_sha256="8" * 64
        )

    def test_eight_process_claim_race_has_one_winner_and_no_retry(self) -> None:
        self._approve()
        for index in range(8):
            self._persist_envelope(
                "claim_" + f"{index + 1:032x}",
                "supervisor_" + f"{index + 1:064x}",
            )
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        results = context.Queue()
        processes = [
            context.Process(
                target=_claim_worker,
                args=(
                    str(self.database),
                    self.campaign.manifest.campaign_id,
                    self.campaign.manifest.manifest_sha256,
                    "claim_" + f"{index + 1:032x}",
                    start,
                    results,
                ),
            )
            for index in range(8)
        ]
        for process in processes:
            process.start()
        start.set()
        rows = []
        for _ in processes:
            rows.append(results.get(timeout=30))
        for process in processes:
            process.join(30)
            self.assertEqual(0, process.exitcode)
        winners = [row for row in rows if row[0] == "claimed"]
        self.assertEqual(1, len(winners), rows)
        claim = ClaimedRound(
            self.campaign.manifest.campaign_id,
            self.campaign.manifest.manifest_sha256,
            winners[0][1],
            self.campaign.rounds[0],
        )
        self.ledger.consume(claim, outcome="FAILED", receipt_sha256="c" * 64)
        losing_owner = next(row[1] for row in rows if row[0] == "rejected")
        with self.assertRaises(CampaignStateError):
            self.ledger.claim_next(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                owner_nonce=losing_owner,
            )
        self._persist_envelope(
            "claim_" + "e" * 32, "supervisor_" + "e" * 64, 1
        )
        next_claim = self.ledger.claim_next(
            self.campaign.manifest.campaign_id,
            manifest_sha256=self.campaign.manifest.manifest_sha256,
            owner_nonce="claim_" + "e" * 32,
        )
        self.assertEqual(1, next_claim.review.ordinal)

    def test_killed_claim_owner_is_recoverable_only_by_persisted_supervisor(self) -> None:
        self._approve()
        owner_nonce = "claim_" + "d" * 32
        supervisor_nonce = new_supervisor_nonce()
        self._persist_envelope(owner_nonce, supervisor_nonce)
        with self.assertRaises(CampaignStateError):
            self.ledger.recover_claim(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                supervisor_nonce=supervisor_nonce,
            )
        context = multiprocessing.get_context("spawn")
        committed = context.Event()
        hold = context.Event()
        process = context.Process(
            target=_claim_then_wait_worker,
            args=(
                str(self.database),
                self.campaign.manifest.campaign_id,
                self.campaign.manifest.manifest_sha256,
                owner_nonce,
                committed,
                hold,
            ),
        )
        process.start()
        self.assertTrue(committed.wait(30))
        process.terminate()
        process.join(30)
        self.assertIsNotNone(process.exitcode)
        with self.assertRaises(CampaignStateError):
            self.ledger.recover_claim(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                supervisor_nonce="supervisor_" + "0" * 64,
            )
        recovered = self.ledger.recover_claim(
            self.campaign.manifest.campaign_id,
            manifest_sha256=self.campaign.manifest.manifest_sha256,
            supervisor_nonce=supervisor_nonce,
        )
        self.assertEqual(owner_nonce, recovered.owner_nonce)
        self.assertEqual(0, recovered.review.ordinal)
        self.ledger.consume(recovered, outcome="FAILED", receipt_sha256="d" * 64)
        with self.assertRaises(CampaignStateError):
            self.ledger.recover_claim(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                supervisor_nonce=supervisor_nonce,
            )

    def test_durable_manifest_tamper_blocks_claim_and_external_mode_is_unreachable(self) -> None:
        self._approve()
        self._persist_envelope(
            "claim_" + "1" * 32, "supervisor_" + "1" * 64
        )
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "UPDATE campaigns SET manifest_bytes=? WHERE campaign_id=?",
                (b"{}", self.campaign.manifest.campaign_id),
            )
            connection.commit()
        with self.assertRaises((CampaignStateError, DossierPolicyError)):
            self.ledger.claim_next(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                owner_nonce="claim_" + "1" * 32,
            )
        with self.assertRaises(ExternalReviewDisabled):
            self.ledger.approve_external(self.campaign.manifest.campaign_id)
        with self.assertRaises(ExternalReviewDisabled):
            self.ledger.claim_next(
                self.campaign.manifest.campaign_id,
                manifest_sha256=self.campaign.manifest.manifest_sha256,
                owner_nonce="claim_" + "2" * 32,
                mode="EXTERNAL",
            )


class DSReviewDryRunCLITests(unittest.TestCase):
    def test_cli_emits_four_recomputable_zero_network_receipts(self) -> None:
        output = StringIO()
        with patch(
            "socket.create_connection",
            side_effect=AssertionError("network construction is forbidden"),
        ), redirect_stdout(output):
            code = dry_run_main(
                ["--expected-system-fingerprint", FIXTURE_FINGERPRINT, "--round", "all"]
            )
        value = json.loads(output.getvalue())
        self.assertNotIn(FIXTURE_FINGERPRINT, output.getvalue())
        self.assertEqual(0, code)
        self.assertEqual("dry_run_no_network", value["status"])
        self.assertEqual(0, value["network_calls"])
        self.assertEqual(4, len(value["receipts"]))
        self.assertEqual(
            {value["campaign_manifest_sha256"]},
            {row["campaign_manifest_sha256"] for row in value["receipts"]},
        )
        self.assertEqual(4, len({row["request_sha256"] for row in value["receipts"]}))


if __name__ == "__main__":
    multiprocessing.freeze_support()
    unittest.main()

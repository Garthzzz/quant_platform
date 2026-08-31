from __future__ import annotations

from copy import deepcopy
import inspect
import unittest

from quant_hub.ops.local_release_identity import (
    ACTIVATION_RECEIPT_SCHEMA,
    ACTIVE_RELEASE_SCHEMA,
    CLEANUP_RECEIPT_SCHEMA,
    FAILURE_RECEIPT_SCHEMA,
    LOCAL_PRIOR_BINDING_SCHEMA,
    LOCAL_STATE_IDENTITY_SCHEMA,
    RELEASE_MANIFEST_SCHEMA,
    ROLLBACK_RECEIPT_SCHEMA,
    LocalReleaseIdentityError,
    canonical_bytes,
    identity_sha256,
    lint_local_release_graph,
    sealed_release_core_sha256,
    validate_activation_receipt,
    validate_active_release,
    validate_cleanup_receipt,
    validate_failure_receipt,
    validate_local_prior_binding,
    validate_release_manifest,
    validate_rollback_receipt,
    validate_state_identity,
)


def _hash(character: str) -> str:
    return character * 64


def _seal(document: dict[str, object], field: str) -> dict[str, object]:
    material = deepcopy(document)
    material.pop(field, None)
    document[field] = identity_sha256(material)
    return document


def _observation(document: dict[str, object]) -> dict[str, object]:
    return _seal(document, "observation_sha256")


def _fullwidth_ascii(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0)
        if "!" <= character <= "~"
        else character
        for character in value
    )


def release(
    release_id: str,
    character: str,
    *,
    comments_read: list[int] | None = None,
    comments_write: list[int] | None = None,
) -> dict[str, object]:
    inventory = {
        "schema_version": "qrh-release-file-inventory/v2",
        "files": [
            {
                "path": "app/package.json",
                "bytes": 128,
                "sha256": _hash(character),
            }
        ],
    }
    return {
        "schema_version": RELEASE_MANIFEST_SCHEMA,
        "release_id": release_id,
        "built_at": "2026-08-26T09:00:00+08:00",
        "application": {
            "source_kind": "git",
            "commit_sha": character * 40,
            "tracked_tree_sha256": _hash(character),
            "build_tool_version": "tests/v2",
            "provenance": {"builder": "public-test", "labels": []},
        },
        "content": {
            "snapshot_id": f"snapshot-{release_id}",
            "source_inventory_sha256": _hash("1"),
            "ir_sha256": _hash("2"),
            "knowledge_sha256": _hash("3"),
            "search_sha256": _hash("4"),
            "page_projection_sha256": _hash("5"),
            "mcp_sha256": _hash("6"),
            "active_membership_sha256": _hash("7"),
            "knowledge_enrichment": {"status": "not_applicable"},
            "presentation": {"language": "zh-CN"},
        },
        "resources": {"inventory_sha256": identity_sha256(inventory)},
        "state": {
            "compatibility": {
                "comments": {
                    "read": comments_read or [1, 2],
                    "write": comments_write or [1, 2],
                },
                "research_workspace": {
                    "read": [1, 2, 3],
                    "write": [1, 2, 3],
                },
                "rollback_policy": "expand_only_no_down_migration",
            }
        },
        "inventory": inventory,
    }


def release_ref(document: dict[str, object]) -> dict[str, object]:
    release_id = str(document["release_id"])
    return {
        "release_id": release_id,
        "release_path": f"D:\\quant\\quant_platform\\releases\\{release_id}",
        "manifest_sha256": identity_sha256(document),
    }


def active(document: dict[str, object]) -> dict[str, object]:
    return {"schema_version": ACTIVE_RELEASE_SCHEMA, "release": release_ref(document)}


def state_identity() -> dict[str, object]:
    return _seal(
        {
            "schema_version": LOCAL_STATE_IDENTITY_SCHEMA,
            "authority_id": "production-d-state",
            "state_path": "D:\\quant\\quant_platform\\state",
            "schema_versions": {"comments": 2, "research_workspace": 3},
        },
        "identity_sha256",
    )


def pair(active_release: dict[str, object], prior_release: dict[str, object] | None) -> dict[str, object]:
    return {
        "active": release_ref(active_release),
        "prior": None if prior_release is None else release_ref(prior_release),
    }


def binding(active_release: dict[str, object], prior_release: dict[str, object]) -> dict[str, object]:
    bound_pair = pair(active_release, prior_release)
    return _seal(
        {
            "schema_version": LOCAL_PRIOR_BINDING_SCHEMA,
            "binding_id": f"binding-{active_release['release_id']}-{prior_release['release_id']}",
            "recorded_at": "2026-08-26T09:10:00+08:00",
            "authority": "retention_evidence_only",
            "active": bound_pair["active"],
            "prior": bound_pair["prior"],
            "state_identity": state_identity(),
            "result": {
                "status": "bound",
                "pair_sha256": identity_sha256(bound_pair),
                "retained_release_count": 2,
                "state_policy": "expand_only_no_down_migration",
            },
        },
        "binding_sha256",
    )


def transition_receipt(
    active_release: dict[str, object],
    prior_release: dict[str, object],
    *,
    rollback: bool = False,
    attempt_id: str | None = None,
    receipt_id: str | None = None,
) -> dict[str, object]:
    result_pair = pair(active_release, prior_release)
    schema = ROLLBACK_RECEIPT_SCHEMA if rollback else ACTIVATION_RECEIPT_SCHEMA
    status = "rolled_back" if rollback else "activated"
    return _seal(
        {
            "schema_version": schema,
            "receipt_id": receipt_id
            or f"receipt-{status}-{active_release['release_id']}",
            "attempt_id": attempt_id
            or f"attempt-{status}-{active_release['release_id']}",
            "recorded_at": "2026-08-26T09:11:00+08:00",
            "authority": "evidence_only",
            "operation": "rollback_to_prior" if rollback else "activate_successor",
            "pair": result_pair,
            "result": {
                "status": status,
                "pair_sha256": identity_sha256(result_pair),
                "controller_verification_sha256": _hash("c"),
            },
        },
        "receipt_sha256",
    )


def bootstrap_receipt(
    baseline_release: dict[str, object],
    *,
    attempt_id: str = "attempt-bootstrap-r0",
    receipt_id: str = "receipt-bootstrap-r0",
) -> dict[str, object]:
    result_pair = pair(baseline_release, None)
    final_state = state_identity()
    proof = {
        "ingress_status": "closed",
        "legacy_c_writer_status": "fenced",
        "r0_live": release_ref(baseline_release),
        "writer_fence_sha256": _hash("e"),
    }
    return _seal(
        {
            "schema_version": ACTIVATION_RECEIPT_SCHEMA,
            "receipt_id": receipt_id,
            "attempt_id": attempt_id,
            "recorded_at": "2026-08-26T09:05:00+08:00",
            "authority": "evidence_only",
            "operation": "bootstrap_first_pair",
            "original": {
                "active_pointer_status": "absent",
                "local_prior_binding_status": "absent",
            },
            "pair": result_pair,
            "state_identity": final_state,
            "proof": proof,
            "result": {
                "status": "bootstrapped",
                "pair_sha256": identity_sha256(result_pair),
                "state_identity_sha256": final_state["identity_sha256"],
                "proof_sha256": identity_sha256(proof),
            },
        },
        "receipt_sha256",
    )


def failure_receipt(
    active_before: dict[str, object] | None,
    candidate: dict[str, object],
    prior_before: dict[str, object] | None = None,
    *,
    operation: str | None = None,
    failed_phase: str = "pre_activation_readiness",
    attempt_id: str | None = None,
    receipt_id: str | None = None,
) -> dict[str, object]:
    if operation is None:
        operation = (
            "bootstrap_first_pair"
            if active_before is None
            else "activate_successor"
        )
    original_state = state_identity()
    original_pair = (
        {"kind": "bootstrap_no_d_pair", "pair": None}
        if active_before is None
        else {
            "kind": "release_pair",
            "pair": pair(active_before, prior_before),
        }
    )
    candidate_ref = release_ref(candidate)
    original_active = None if active_before is None else release_ref(active_before)
    original_bound_pair = (
        None
        if active_before is None or prior_before is None
        else pair(active_before, prior_before)
    )
    restoration_evidence = {
        "original_active_pointer_observation": _observation(
            {
                "status": "absent"
                if original_active is None
                else "original_active_restored",
                "observed_release": original_active,
                "evidence_sha256": _hash("1"),
            }
        ),
        "original_local_prior_binding_observation": _observation(
            {
                "status": "absent"
                if original_bound_pair is None
                else "original_binding_restored",
                "observed_pair": original_bound_pair,
                "evidence_sha256": _hash("2"),
            }
        ),
        "original_active_service_live_identity_observation": _observation(
            {
                "status": "absent"
                if original_active is None
                else "original_active_live",
                "observed_release": original_active,
                "evidence_sha256": _hash("3"),
            }
        ),
        "original_active_writer_fence_observation": _observation(
            {
                "status": "d_writer_absent_or_fenced"
                if original_active is None
                else "original_active_writer_fence_restored",
                "observed_release": original_active,
                "evidence_sha256": _hash("4"),
            }
        ),
        "current_d_state_identity_observation": _observation(
            {
                "status": "d_state_not_externally_written"
                if original_active is None
                else "current_d_state_identity_unchanged",
                "observed_state_identity": deepcopy(original_state),
                "evidence_sha256": _hash("5"),
            }
        ),
    }
    return _seal(
        {
            "schema_version": FAILURE_RECEIPT_SCHEMA,
            "receipt_id": receipt_id or f"receipt-failed-{candidate['release_id']}",
            "attempt_id": attempt_id or f"attempt-failed-{candidate['release_id']}",
            "recorded_at": "2026-08-26T09:12:00+08:00",
            "authority": "evidence_only",
            "operation": operation,
            "original_pair": original_pair,
            "original_state_identity": original_state,
            "candidate": candidate_ref,
            "failed_phase": failed_phase,
            "restoration_evidence": restoration_evidence,
            "result": {
                "status": "failed",
                "original_pair_sha256": identity_sha256(original_pair),
                "original_state_identity_sha256": original_state[
                    "identity_sha256"
                ],
                "candidate_manifest_sha256": candidate_ref["manifest_sha256"],
                "restoration_evidence_sha256": identity_sha256(
                    restoration_evidence
                ),
            },
        },
        "receipt_sha256",
    )


def cleanup_receipt(
    active_release: dict[str, object],
    prior_release: dict[str, object],
    removed: list[dict[str, object]],
    *,
    extra_targets: list[dict[str, object]] | None = None,
    attempt_id: str | None = None,
    receipt_id: str | None = None,
) -> dict[str, object]:
    retained_pair = pair(active_release, prior_release)
    targets = sorted(
        [
            {
                "kind": "release_closure",
                "release": release_ref(document),
                "closure_sha256": identity_sha256(document["inventory"]),
            }
            for document in removed
        ]
        + list(extra_targets or []),
        key=lambda item: (
            str(item["kind"]),
            str(
                item["release"]["release_path"]
                if item["kind"] == "release_closure"
                else item["path"]
            ).casefold(),
            identity_sha256(item),
        ),
    )
    return _seal(
        {
            "schema_version": CLEANUP_RECEIPT_SCHEMA,
            "receipt_id": receipt_id
            or f"receipt-cleanup-{active_release['release_id']}",
            "attempt_id": attempt_id
            or f"attempt-cleanup-{active_release['release_id']}",
            "recorded_at": "2026-08-26T09:13:00+08:00",
            "authority": "evidence_only",
            "retained_pair": retained_pair,
            "removed_targets": targets,
            "result": {
                "status": "cleaned",
                "retained_pair_sha256": identity_sha256(retained_pair),
                "removed_targets_sha256": identity_sha256(targets),
                "removed_count": len(targets),
            },
        },
        "receipt_sha256",
    )


class LocalReleaseIdentityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.r_minus_1 = release("release-r-minus-1", "8")
        self.r0 = release("release-r0", "9")
        self.r1 = release("release-r1", "a")
        self.r2 = release("release-r2", "b")
        self.active = active(self.r1)
        self.binding = binding(self.r1, self.r0)

    def test_release_v2_uses_closed_typed_application_and_content(self) -> None:
        validated = validate_release_manifest(self.r1)
        self.assertEqual({
            "schema_version", "release_id", "built_at", "application", "content",
            "resources", "state", "inventory",
        }, set(validated))
        self.assertEqual("public-test", validated["application"]["provenance"]["builder"])
        self.assertEqual("zh-CN", validated["content"]["presentation"]["language"])
        self.assertEqual(
            _hash("7"), validated["content"]["active_membership_sha256"]
        )

        aliased_database = deepcopy(self.r1)
        compatibility = aliased_database["state"]["compatibility"]
        compatibility["workspace"] = compatibility.pop("research_workspace")
        with self.assertRaisesRegex(
            LocalReleaseIdentityError, "exact production database set"
        ):
            validate_release_manifest(aliased_database)

        wrong_state = state_identity()
        wrong_state["schema_versions"] = {"comments": 2, "research_workspace": 2}
        _seal(wrong_state, "identity_sha256")
        with self.assertRaisesRegex(
            LocalReleaseIdentityError, "exact production schema versions"
        ):
            validate_state_identity(wrong_state)

        ready = deepcopy(self.r1)
        ready["content"]["knowledge_enrichment"] = {
            "status": "ready",
            "generation_id": "generation-r1",
            "provider_revision": "DeepSeek-V4-Pro-0813",
            "model_identity_sha256": _hash("8"),
            "accepted_knowledge_sha256": _hash("9"),
            "coverage_report_sha256": _hash("a"),
        }
        validate_release_manifest(ready)

        legacy = deepcopy(self.r1)
        legacy["application"] = {
            "source_kind": "legacy_broadcast",
            "source_archive_sha256": _hash("b"),
            "legacy_deployment_id": "legacy-v39",
            "build_tool_version": "tests/v2",
            "provenance": {"builder": "public-test", "labels": ["baseline"]},
        }
        validate_release_manifest(legacy)

        for section, field in (
            ("application", "free_extension"),
            ("content", "free_extension"),
            ("knowledge_enrichment", "provider_identity"),
        ):
            with self.subTest(section=section, field=field):
                candidate = deepcopy(self.r1)
                target = (
                    candidate["content"]["knowledge_enrichment"]
                    if section == "knowledge_enrichment"
                    else candidate[section]
                )
                target[field] = {"value": "not-typed"}
                with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
                    validate_release_manifest(candidate)

    def test_release_rejects_nested_dynamic_control_and_reverse_edges(self) -> None:
        for field in (
            "active_release", "active_manifest_sha256", "binding_sha256",
            "manifest_sha256", "receipt", "activation_receipt_id",
            "recovery_manifest_sha256", "backup_id", "started", "health",
            "writer_fence",
        ):
            with self.subTest(field=field):
                candidate = deepcopy(self.r1)
                candidate["content"][field] = _hash("f")
                with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
                    validate_release_manifest(candidate)

    def test_release_rejects_split_camel_case_dynamic_keys_inside_arrays(self) -> None:
        for field in (
            "Control",
            "Con-Trol",
            "re-covery",
            "check-point",
            "bun-dle",
            "back-up",
            "ActiveRelease",
            "LocalPriorBinding",
            "ActivationReceipt",
        ):
            with self.subTest(field=field):
                candidate = deepcopy(self.r1)
                candidate["content"][field] = [
                    {"nested": [{"value": "must-not-be-authority"}]}
                ]
                with self.assertRaisesRegex(
                    LocalReleaseIdentityError, "closed"
                ):
                    validate_release_manifest(candidate)

        fullwidth = deepcopy(self.r1)
        fullwidth["content"]["ａｃｔｉｖｅ＿ｒｅｌｅａｓｅ"] = _hash("f")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_release_manifest(fullwidth)

        collision = deepcopy(self.r1)
        collision["content"]["activeMembershipSha256"] = _hash("f")
        with self.assertRaisesRegex(
            LocalReleaseIdentityError, "normalization collision"
        ):
            validate_release_manifest(collision)

        for value in (
            {"outer": [{"foo-bar": 1, "foo_bar": 2}]},
            {"foo_bar": 1, "ｆｏｏ＿ｂａｒ": 2},
            {"mcp_artifact": 1, "MCPArtifact": 2},
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                LocalReleaseIdentityError, "normalization collision"
            ):
                canonical_bytes(value)

    def test_canonical_json_recursively_rejects_nonstandard_or_unstable_values(
        self,
    ) -> None:
        invalid_values = (
            {1: "integer-key", "1": "string-key"},
            {"outer": {1: "integer-key"}},
            {"outer": ("tuple",)},
            {"outer": {"set-member"}},
            {"outer": b"bytes"},
            {"outer": float("nan")},
            {"outer": float("inf")},
            {"outer": float("-inf")},
        )
        for value in invalid_values:
            outer = value.get("outer") if isinstance(value, dict) else value
            with self.subTest(value_type=type(outer).__name__):
                with self.assertRaisesRegex(
                    LocalReleaseIdentityError, "canonical JSON"
                ):
                    canonical_bytes(value)

        for nested in ({1: "integer-key"}, ("tuple",), b"bytes", float("nan")):
            with self.subTest(manifest_nested_type=type(nested).__name__):
                candidate = deepcopy(self.r1)
                candidate["content"]["legal_extension"] = {"nested": nested}
                with self.assertRaisesRegex(
                    LocalReleaseIdentityError, "canonical JSON"
                ):
                    validate_release_manifest(candidate)

        self.assertEqual(
            b'{"array":[null,true,1,1.5,"text"],"object":{"key":"value"}}',
            canonical_bytes(
                {
                    "object": {"key": "value"},
                    "array": [None, True, 1, 1.5, "text"],
                }
            ),
        )

    def test_release_and_reference_ids_reject_win32_aliases_and_devices(self) -> None:
        for release_id in (
            "release-r1.",
            "release-r1 ",
            "CON",
            "con.txt",
            "AUX.json",
            "NUL.data",
            "COM1.log",
            "lpt9.txt",
        ):
            with self.subTest(release_id=release_id):
                candidate = deepcopy(self.r1)
                candidate["release_id"] = release_id
                with self.assertRaisesRegex(LocalReleaseIdentityError, "identifier"):
                    validate_release_manifest(candidate)

        con_pointer = deepcopy(self.active)
        con_pointer["release"] = {
            "release_id": "CON",
            "release_path": r"D:\quant\quant_platform\releases\CON",
            "manifest_sha256": _hash("f"),
        }
        with self.assertRaisesRegex(LocalReleaseIdentityError, "identifier"):
            validate_active_release(con_pointer)

        alias_pair = deepcopy(self.binding)
        alias_pair["prior"]["release_id"] = "release-r1."
        alias_pair["prior"]["release_path"] = (
            r"D:\quant\quant_platform\releases\release-r1."
        )
        alias_pair["result"]["pair_sha256"] = identity_sha256(
            {"active": alias_pair["active"], "prior": alias_pair["prior"]}
        )
        _seal(alias_pair, "binding_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "identifier"):
            validate_local_prior_binding(alias_pair)

    def test_inventory_rejects_empty_del_and_file_directory_prefix_collisions(
        self,
    ) -> None:
        empty = deepcopy(self.r1)
        empty["inventory"]["files"] = []
        empty["resources"]["inventory_sha256"] = identity_sha256(empty["inventory"])
        with self.assertRaisesRegex(LocalReleaseIdentityError, "cannot be empty"):
            validate_release_manifest(empty)

        delete_control = deepcopy(self.r1)
        delete_control["inventory"]["files"][0]["path"] = "app/\x7fpayload.bin"
        delete_control["resources"]["inventory_sha256"] = identity_sha256(
            delete_control["inventory"]
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "unsafe on Windows"):
            validate_release_manifest(delete_control)

        fullwidth_punctuation = deepcopy(self.r1)
        fullwidth_punctuation["inventory"]["files"][0]["path"] = (
            "研究/结果：版本？.pdf"
        )
        fullwidth_punctuation["resources"]["inventory_sha256"] = identity_sha256(
            fullwidth_punctuation["inventory"]
        )
        validate_release_manifest(fullwidth_punctuation)

        for unsafe_path in (
            ".",
            "RELEASE_MANIFEST.JSON",
            "Release_Manifest.Json",
            "Release_Manifest.Json/payload.bin",
            "nested/Release_Manifest.Json",
            "CON/payload.bin",
            "data/AUX.txt",
            "COM¹/payload.bin",
            "data/LPT².txt",
        ):
            with self.subTest(unsafe_path=unsafe_path):
                device_path = deepcopy(self.r1)
                device_path["inventory"]["files"][0]["path"] = unsafe_path
                device_path["resources"]["inventory_sha256"] = identity_sha256(
                    device_path["inventory"]
                )
                with self.assertRaisesRegex(
                    LocalReleaseIdentityError, "unsafe on Windows"
                ):
                    validate_release_manifest(device_path)

        for paths in (
            ("app", "app/payload.bin"),
            ("app/payload.bin", "app"),
            ("App", "app/payload.bin"),
        ):
            with self.subTest(paths=paths):
                collision = deepcopy(self.r1)
                collision["inventory"]["files"] = sorted(
                    (
                        {"path": path, "bytes": 1, "sha256": _hash(str(index + 1))}
                        for index, path in enumerate(paths)
                    ),
                    key=lambda item: item["path"],
                )
                collision["resources"]["inventory_sha256"] = identity_sha256(
                    collision["inventory"]
                )
                with self.assertRaisesRegex(
                    LocalReleaseIdentityError, "prefix|case-fold"
                ):
                    validate_release_manifest(collision)

    def test_git_commit_rejects_zero_40_and_zero_64(self) -> None:
        sha256_commit = deepcopy(self.r1)
        sha256_commit["application"]["commit_sha"] = "a" * 64
        validate_release_manifest(sha256_commit)

        for commit in ("0" * 40, "0" * 64):
            with self.subTest(length=len(commit)):
                candidate = deepcopy(self.r1)
                candidate["application"]["commit_sha"] = commit
                with self.assertRaisesRegex(LocalReleaseIdentityError, "zero"):
                    validate_release_manifest(candidate)

    def test_active_prior_pair_rejects_relabelled_identical_immutable_payload(
        self,
    ) -> None:
        for change_built_at in (False, True):
            with self.subTest(change_built_at=change_built_at):
                relabelled = deepcopy(self.r0)
                relabelled["release_id"] = "release-r0-copy"
                if change_built_at:
                    relabelled["built_at"] = "2026-08-26T09:01:00+08:00"
                copied_binding = binding(relabelled, self.r0)
                with self.assertRaisesRegex(
                    LocalReleaseIdentityError, "immutable payload"
                ):
                    lint_local_release_graph(
                        release_manifests=[self.r0, relabelled],
                        active_release=active(relabelled),
                        local_prior_binding=copied_binding,
                        retained_release_refs=[
                            release_ref(relabelled),
                            release_ref(self.r0),
                        ],
                    )

        built_at_only = deepcopy(self.r0)
        built_at_only["built_at"] = "2026-08-26T09:01:00+08:00"
        aliased_pair = binding(built_at_only, self.r0)
        with self.assertRaisesRegex(LocalReleaseIdentityError, "distinct"):
            validate_local_prior_binding(aliased_pair)

        metadata_only = deepcopy(self.r0)
        metadata_only["release_id"] = "release-r0-metadata-copy"
        metadata_only["built_at"] = "2026-08-26T09:02:00+08:00"
        metadata_only["application"]["commit_sha"] = "c" * 40
        metadata_only["application"]["build_tool_version"] = "tests/v99"
        metadata_only["application"]["provenance"] = {
            "builder": "other-builder",
            "labels": ["successor"],
        }
        with self.assertRaisesRegex(LocalReleaseIdentityError, "immutable payload"):
            lint_local_release_graph(
                release_manifests=[self.r0, metadata_only],
                active_release=active(metadata_only),
                local_prior_binding=binding(metadata_only, self.r0),
                retained_release_refs=[
                    release_ref(metadata_only),
                    release_ref(self.r0),
                ],
            )

    def test_public_sealed_release_core_ignores_only_release_identity_metadata(
        self,
    ) -> None:
        copied = deepcopy(self.r0)
        copied["release_id"] = "release-r0-copy"
        copied["built_at"] = "2026-08-26T09:03:00+08:00"
        copied["application"]["provenance"] = {
            "builder": "different-builder",
            "labels": ["copied"],
        }
        self.assertEqual(
            sealed_release_core_sha256(self.r0),
            sealed_release_core_sha256(copied),
        )

        payload_changed = deepcopy(copied)
        payload_changed["inventory"]["files"][0]["sha256"] = _hash("d")
        payload_changed["resources"]["inventory_sha256"] = identity_sha256(
            payload_changed["inventory"]
        )
        self.assertNotEqual(
            sealed_release_core_sha256(self.r0),
            sealed_release_core_sha256(payload_changed),
        )

        invalid = deepcopy(self.r0)
        invalid["recovery_root"] = r"D:\forbidden"
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            sealed_release_core_sha256(invalid)

    def test_active_is_the_only_closed_current_pointer(self) -> None:
        validate_active_release(self.active)
        for field in ("binding", "receipt", "current_manifest_sha256"):
            candidate = deepcopy(self.active)
            candidate[field] = _hash("f")
            with self.subTest(field=field), self.assertRaisesRegex(
                LocalReleaseIdentityError, "closed"
            ):
                validate_active_release(candidate)
        with self.assertRaises(LocalReleaseIdentityError):
            validate_active_release(transition_receipt(self.r1, self.r0))

    def test_binding_is_exact_evidence_not_current_and_rejects_multiple_or_same_prior(self) -> None:
        validate_local_prior_binding(self.binding)
        multiple = deepcopy(self.binding)
        multiple["priors"] = [release_ref(self.r0), release_ref(self.r_minus_1)]
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_local_prior_binding(multiple)

        same = deepcopy(self.binding)
        same["prior"] = deepcopy(same["active"])
        same["result"]["pair_sha256"] = identity_sha256(
            {"active": same["active"], "prior": same["prior"]}
        )
        _seal(same, "binding_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "distinct"):
            validate_local_prior_binding(same)

        current_claim = deepcopy(self.binding)
        current_claim["current"] = True
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_local_prior_binding(current_claim)

    def test_append_only_receipts_bind_exact_result_pairs(self) -> None:
        activation = transition_receipt(self.r1, self.r0)
        rollback = transition_receipt(self.r0, self.r_minus_1, rollback=True)
        bootstrap = bootstrap_receipt(self.r0)
        validate_activation_receipt(activation)
        validate_rollback_receipt(rollback)
        validate_activation_receipt(bootstrap)

        drift = deepcopy(activation)
        drift["result"]["pair_sha256"] = _hash("f")
        _seal(drift, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "does not bind"):
            validate_activation_receipt(drift)

        missing_controller_verification = deepcopy(activation)
        missing_controller_verification["result"].pop(
            "controller_verification_sha256"
        )
        _seal(missing_controller_verification, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_activation_receipt(missing_controller_verification)

        zero_controller_verification = deepcopy(rollback)
        zero_controller_verification["result"][
            "controller_verification_sha256"
        ] = _hash("0")
        _seal(zero_controller_verification, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "zero"):
            validate_rollback_receipt(zero_controller_verification)

        pointer_claim = deepcopy(activation)
        pointer_claim["current"] = release_ref(self.r1)
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_activation_receipt(pointer_claim)

        missing_attempt = deepcopy(activation)
        missing_attempt.pop("attempt_id")
        _seal(missing_attempt, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_activation_receipt(missing_attempt)

        invalid_bootstrap_pair = bootstrap_receipt(self.r0)
        invalid_bootstrap_pair["pair"]["prior"] = release_ref(self.r_minus_1)
        invalid_bootstrap_pair["result"]["pair_sha256"] = identity_sha256(
            invalid_bootstrap_pair["pair"]
        )
        _seal(invalid_bootstrap_pair, "receipt_sha256")
        with self.assertRaisesRegex(
            LocalReleaseIdentityError, "bootstrap.*prior|null"
        ):
            validate_activation_receipt(invalid_bootstrap_pair)

        missing_fence = bootstrap_receipt(self.r0)
        missing_fence["proof"].pop("writer_fence_sha256")
        _seal(missing_fence, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_activation_receipt(missing_fence)

        zero_bootstrap_fence = bootstrap_receipt(self.r0)
        zero_bootstrap_fence["proof"]["writer_fence_sha256"] = _hash("0")
        zero_bootstrap_fence["result"]["proof_sha256"] = identity_sha256(
            zero_bootstrap_fence["proof"]
        )
        _seal(zero_bootstrap_fence, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "zero"):
            validate_activation_receipt(zero_bootstrap_fence)

    def test_failure_receipt_binds_operation_and_exact_candidate_role(self) -> None:
        bootstrap_failure = failure_receipt(None, self.r0)
        validate_failure_receipt(bootstrap_failure)
        advanced_bootstrap_failure = failure_receipt(None, self.r0)
        advanced_state = advanced_bootstrap_failure["restoration_evidence"][
            "current_d_state_identity_observation"
        ]
        advanced_state.update(
            {
                "status": "current_d_state_preserved_after_legacy_writer_fence",
                "failure_authorization_sha256": _hash("a"),
                "authorized_state_order_sha256": _hash("b"),
                "preserved_state_order_sha256": _hash("c"),
                "evidence_sha256": _hash("c"),
            }
        )
        _seal(advanced_state, "observation_sha256")
        advanced_bootstrap_failure["result"][
            "restoration_evidence_sha256"
        ] = identity_sha256(advanced_bootstrap_failure["restoration_evidence"])
        _seal(advanced_bootstrap_failure, "receipt_sha256")
        validate_failure_receipt(advanced_bootstrap_failure)

        unbound_advanced_state = deepcopy(advanced_bootstrap_failure)
        unbound_observation = unbound_advanced_state["restoration_evidence"][
            "current_d_state_identity_observation"
        ]
        unbound_observation["preserved_state_order_sha256"] = _hash("b")
        unbound_observation["evidence_sha256"] = _hash("b")
        _seal(unbound_observation, "observation_sha256")
        unbound_advanced_state["result"][
            "restoration_evidence_sha256"
        ] = identity_sha256(unbound_advanced_state["restoration_evidence"])
        _seal(unbound_advanced_state, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "advanced state"):
            validate_failure_receipt(unbound_advanced_state)
        pre_pair_failure = failure_receipt(self.r0, self.r1)
        validate_failure_receipt(pre_pair_failure)
        ordinary_failure = failure_receipt(self.r1, self.r2, self.r0)
        validate_failure_receipt(ordinary_failure)
        rollback_failure = failure_receipt(
            self.r1,
            self.r0,
            self.r0,
            operation="rollback_to_prior",
        )
        validate_failure_receipt(rollback_failure)

        rollback_with_successor = failure_receipt(
            self.r1,
            self.r2,
            self.r0,
            operation="rollback_to_prior",
        )
        with self.assertRaisesRegex(
            LocalReleaseIdentityError, "exact original prior"
        ):
            validate_failure_receipt(rollback_with_successor)

        activation_with_prior_candidate = failure_receipt(
            self.r1,
            self.r0,
            self.r0,
            operation="activate_successor",
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "candidate must differ"):
            validate_failure_receipt(activation_with_prior_candidate)

        bootstrap_with_release_pair = failure_receipt(
            self.r0,
            self.r1,
            operation="bootstrap_first_pair",
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "bootstrap_no_d_pair"):
            validate_failure_receipt(bootstrap_with_release_pair)

        unknown_operation = failure_receipt(self.r0, self.r1)
        unknown_operation["operation"] = "activate"
        _seal(unknown_operation, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "operation"):
            validate_failure_receipt(unknown_operation)

        missing_operation = failure_receipt(self.r0, self.r1)
        missing_operation.pop("operation")
        _seal(missing_operation, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_failure_receipt(missing_operation)

        same_candidate = failure_receipt(self.r0, self.r1)
        same_candidate["candidate"] = deepcopy(
            same_candidate["original_pair"]["pair"]["active"]
        )
        same_candidate["result"]["candidate_manifest_sha256"] = same_candidate[
            "candidate"
        ]["manifest_sha256"]
        _seal(same_candidate, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "candidate must differ"):
            validate_failure_receipt(same_candidate)

        false_restoration = failure_receipt(self.r1, self.r2, self.r0)
        false_restoration["result"]["restoration_evidence_sha256"] = _hash("f")
        _seal(false_restoration, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "restoration"):
            validate_failure_receipt(false_restoration)

        false_original_state_result = failure_receipt(
            self.r1, self.r2, self.r0
        )
        false_original_state_result["result"][
            "original_state_identity_sha256"
        ] = _hash("f")
        _seal(false_original_state_result, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "original state"):
            validate_failure_receipt(false_original_state_result)

        alternate_valid_state = failure_receipt(self.r1, self.r2, self.r0)
        replacement_state = state_identity()
        replacement_state["authority_id"] = "alternate-d-state"
        _seal(replacement_state, "identity_sha256")
        state_observation = alternate_valid_state["restoration_evidence"][
            "current_d_state_identity_observation"
        ]
        state_observation["observed_state_identity"] = replacement_state
        _seal(state_observation, "observation_sha256")
        alternate_valid_state["result"][
            "restoration_evidence_sha256"
        ] = identity_sha256(alternate_valid_state["restoration_evidence"])
        _seal(alternate_valid_state, "receipt_sha256")
        with self.assertRaisesRegex(
            LocalReleaseIdentityError, "state identity observation"
        ):
            validate_failure_receipt(alternate_valid_state)

        pure_status_pair = failure_receipt(self.r1, self.r2, self.r0)
        pure_status_pair.pop("restoration_evidence")
        pure_status_pair["result"].pop("restoration_evidence_sha256")
        pure_status_pair["result"]["restoration"] = {
            "status": "original_pair_restored",
            "pair_sha256": identity_sha256(pure_status_pair["original_pair"]["pair"]),
        }
        _seal(pure_status_pair, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_failure_receipt(pure_status_pair)

        wrong_pointer = failure_receipt(self.r1, self.r2, self.r0)
        pointer_observation = wrong_pointer["restoration_evidence"][
            "original_active_pointer_observation"
        ]
        pointer_observation["observed_release"] = release_ref(self.r2)
        _seal(pointer_observation, "observation_sha256")
        wrong_pointer["result"]["restoration_evidence_sha256"] = identity_sha256(
            wrong_pointer["restoration_evidence"]
        )
        _seal(wrong_pointer, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "pointer observation"):
            validate_failure_receipt(wrong_pointer)

        boolean_fence = failure_receipt(self.r1, self.r2, self.r0)
        fence_observation = boolean_fence["restoration_evidence"][
            "original_active_writer_fence_observation"
        ]
        fence_observation["evidence_sha256"] = True
        _seal(fence_observation, "observation_sha256")
        boolean_fence["result"]["restoration_evidence_sha256"] = identity_sha256(
            boolean_fence["restoration_evidence"]
        )
        _seal(boolean_fence, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "SHA-256"):
            validate_failure_receipt(boolean_fence)

        open_bootstrap_shape = failure_receipt(None, self.r0)
        open_bootstrap_shape["original_pair"]["active"] = None
        _seal(open_bootstrap_shape, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            validate_failure_receipt(open_bootstrap_shape)

    def test_cleanup_receipt_binds_exact_removed_targets(self) -> None:
        extra_targets = [
            {
                "kind": "incoming",
                "path": r"D:\quant\quant_platform\incoming\attempt-r2",
                "payload_sha256": _hash("a"),
                "closure_sha256": _hash("b"),
            },
            {
                "kind": "partial",
                "path": r"D:\quant\quant_platform\incoming\attempt-r2.partial",
                "payload_sha256": _hash("c"),
                "closure_sha256": _hash("d"),
            },
            {
                "kind": "unreferenced_object",
                "path": r"D:\quant\quant_platform\objects\aa\object.bin",
                "object_sha256": _hash("e"),
                "closure_sha256": _hash("f"),
            },
        ]
        receipt = cleanup_receipt(
            self.r1,
            self.r0,
            [self.r_minus_1],
            extra_targets=extra_targets,
        )
        validate_cleanup_receipt(receipt)
        validate_cleanup_receipt(cleanup_receipt(self.r1, self.r0, []))

        remove_retained = cleanup_receipt(self.r1, self.r0, [self.r0])
        with self.assertRaisesRegex(LocalReleaseIdentityError, "cannot remove"):
            validate_cleanup_receipt(remove_retained)

        drift = deepcopy(receipt)
        drift["removed_targets"][0]["closure_sha256"] = _hash("9")
        _seal(drift, "receipt_sha256")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "exact targets"):
            validate_cleanup_receipt(drift)

        outside_root = cleanup_receipt(
            self.r1,
            self.r0,
            [],
            extra_targets=[
                {
                    "kind": "partial",
                    "path": r"C:\temp\attempt.partial",
                    "payload_sha256": _hash("1"),
                    "closure_sha256": _hash("2"),
                }
            ],
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "exact D"):
            validate_cleanup_receipt(outside_root)

        for path_alias in (
            r"d:\quant\quant_platform\incoming\attempt-r2",
            r"D:\QUANT\quant_platform\incoming\attempt-r2",
            r"D:\quant\quant_platform\INCOMING\attempt-r2",
            "D:\\quant\\quant_platform\\ｉｎｃｏｍｉｎｇ\\attempt-r2",
        ):
            alias_target = cleanup_receipt(
                self.r1,
                self.r0,
                [],
                extra_targets=[
                    {
                        "kind": "incoming",
                        "path": path_alias,
                        "payload_sha256": _hash("1"),
                        "closure_sha256": _hash("2"),
                    }
                ],
            )
            with self.subTest(path_alias=path_alias), self.assertRaisesRegex(
                LocalReleaseIdentityError, "exact D"
            ):
                validate_cleanup_receipt(alias_target)

        duplicate_physical_target = cleanup_receipt(
            self.r1,
            self.r0,
            [],
            extra_targets=[
                {
                    "kind": "incoming",
                    "path": r"D:\quant\quant_platform\incoming\attempt-r2",
                    "payload_sha256": _hash("1"),
                    "closure_sha256": _hash("2"),
                },
                {
                    "kind": "incoming",
                    "path": r"D:\quant\quant_platform\incoming\attempt-r2",
                    "payload_sha256": _hash("3"),
                    "closure_sha256": _hash("4"),
                },
            ],
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "physical target"):
            validate_cleanup_receipt(duplicate_physical_target)

        zero_payload_evidence = cleanup_receipt(
            self.r1,
            self.r0,
            [],
            extra_targets=[
                {
                    "kind": "incoming",
                    "path": r"D:\quant\quant_platform\incoming\attempt-r2",
                    "payload_sha256": _hash("0"),
                    "closure_sha256": _hash("2"),
                }
            ],
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "zero"):
            validate_cleanup_receipt(zero_payload_evidence)

    def test_graph_accepts_history_and_candidate_but_retains_exact_active_prior(self) -> None:
        activation_attempt = "attempt-r1-activation"
        receipts = [
            bootstrap_receipt(self.r0),
            transition_receipt(
                self.r1,
                self.r0,
                attempt_id=activation_attempt,
            ),
            failure_receipt(self.r1, self.r2, self.r0),
            cleanup_receipt(
                self.r1,
                self.r0,
                [self.r_minus_1],
                attempt_id=activation_attempt,
            ),
        ]
        report = lint_local_release_graph(
            release_manifests=[self.r_minus_1, self.r0, self.r1, self.r2],
            active_release=self.active,
            local_prior_binding=self.binding,
            retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
            receipts=receipts,
        )
        self.assertEqual(identity_sha256(self.r1), report.active_manifest_sha256)
        self.assertEqual(identity_sha256(self.r0), report.prior_manifest_sha256)
        self.assertEqual(2, report.retained_release_count)
        self.assertTrue(all(not source.startswith("R:") for source, _ in report.edges))

    def test_graph_rejects_binding_drift_and_unknown_hash(self) -> None:
        with self.assertRaisesRegex(LocalReleaseIdentityError, "drifted"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1],
                active_release=active(self.r0),
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
            )

        unknown = deepcopy(self.active)
        unknown["release"]["manifest_sha256"] = _hash("f")
        with self.assertRaisesRegex(LocalReleaseIdentityError, "unknown manifest hash"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1],
                active_release=unknown,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
            )

        wrong_id = deepcopy(self.active)
        wrong_id["release"]["release_id"] = "release-r2"
        wrong_id["release"]["release_path"] = (
            "D:\\quant\\quant_platform\\releases\\release-r2"
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "ID/hash disagree"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1, self.r2],
                active_release=wrong_id,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
            )

        for unsafe_path in (
            "C:\\quant_platform\\releases\\release-r1",
            "D:\\quant\\release-r1",
            "D:\\quant\\quant_platform\\release-r1",
        ):
            wrong_path = deepcopy(self.active)
            wrong_path["release"]["release_path"] = unsafe_path
            with self.subTest(path=unsafe_path), self.assertRaisesRegex(
                LocalReleaseIdentityError, "exact D release path"
            ):
                lint_local_release_graph(
                    release_manifests=[self.r0, self.r1],
                    active_release=wrong_path,
                    local_prior_binding=self.binding,
                    retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
                )

    def test_graph_rejects_missing_multiple_or_third_retained_release(self) -> None:
        cases = (
            [release_ref(self.r1)],
            [release_ref(self.r1), release_ref(self.r0), release_ref(self.r_minus_1)],
            [release_ref(self.r1), release_ref(self.r1)],
        )
        for retained in cases:
            with self.subTest(count=len(retained)), self.assertRaisesRegex(
                LocalReleaseIdentityError, "exactly active plus one prior"
            ):
                lint_local_release_graph(
                    release_manifests=[self.r_minus_1, self.r0, self.r1],
                    active_release=self.active,
                    local_prior_binding=self.binding,
                    retained_release_refs=retained,
                )

    def test_graph_rejects_receipt_pointer_and_unknown_cleanup_target(self) -> None:
        as_pointer = transition_receipt(self.r1, self.r0)
        with self.assertRaises(LocalReleaseIdentityError):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1],
                active_release=as_pointer,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
            )

        unknown_cleanup = cleanup_receipt(self.r1, self.r0, [self.r_minus_1])
        with self.assertRaisesRegex(LocalReleaseIdentityError, "unknown manifest hash"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1],
                active_release=self.active,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
                receipts=[unknown_cleanup],
            )

        historical_attempt = "attempt-historical-r0"
        old_pair_terminal = transition_receipt(
            self.r0,
            self.r_minus_1,
            attempt_id=historical_attempt,
            receipt_id="receipt-historical-r0",
        )
        old_pair_cleanup = cleanup_receipt(
            self.r0,
            self.r_minus_1,
            [self.r2],
            attempt_id=historical_attempt,
        )
        historical_report = lint_local_release_graph(
            release_manifests=[self.r_minus_1, self.r0, self.r1, self.r2],
            active_release=self.active,
            local_prior_binding=self.binding,
            retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
            receipts=[old_pair_cleanup, old_pair_terminal],
        )
        self.assertEqual(2, historical_report.receipt_count)

    def test_cleanup_requires_matching_success_terminal_for_same_attempt(self) -> None:
        orphan = cleanup_receipt(
            self.r1,
            self.r0,
            [],
            attempt_id="attempt-orphan-cleanup",
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "cleanup.*terminal"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1],
                active_release=self.active,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
                receipts=[orphan],
            )

        failed_attempt = "attempt-failed-cleanup"
        failure = failure_receipt(
            self.r1,
            self.r2,
            self.r0,
            attempt_id=failed_attempt,
        )
        after_failure = cleanup_receipt(
            self.r1,
            self.r0,
            [],
            attempt_id=failed_attempt,
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "failure.*cleanup"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1, self.r2],
                active_release=self.active,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
                receipts=[failure, after_failure],
            )

        drift_attempt = "attempt-cleanup-pair-drift"
        terminal = transition_receipt(
            self.r1,
            self.r0,
            attempt_id=drift_attempt,
        )
        drifted = cleanup_receipt(
            self.r0,
            self.r_minus_1,
            [],
            attempt_id=drift_attempt,
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "cleanup.*pair"):
            lint_local_release_graph(
                release_manifests=[self.r_minus_1, self.r0, self.r1],
                active_release=self.active,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
                receipts=[terminal, drifted],
            )

    def test_graph_rejects_multiple_terminal_or_cleanup_receipts_per_attempt(
        self,
    ) -> None:
        terminal_attempt = "attempt-shared-terminal"
        activation = transition_receipt(
            self.r1,
            self.r0,
            attempt_id=terminal_attempt,
            receipt_id="receipt-shared-activation",
        )
        failure = failure_receipt(
            self.r1,
            self.r2,
            self.r0,
            attempt_id=terminal_attempt,
            receipt_id="receipt-shared-failure",
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "terminal.*attempt"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1, self.r2],
                active_release=self.active,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
                receipts=[activation, failure],
            )

        cleanup_attempt = "attempt-shared-cleanup"
        first_cleanup = cleanup_receipt(
            self.r1,
            self.r0,
            [],
            attempt_id=cleanup_attempt,
            receipt_id="receipt-cleanup-first",
        )
        second_cleanup = cleanup_receipt(
            self.r1,
            self.r0,
            [],
            attempt_id=cleanup_attempt,
            receipt_id="receipt-cleanup-second",
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "cleanup.*attempt"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1],
                active_release=self.active,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
                receipts=[first_cleanup, second_cleanup],
            )

        bootstrap = bootstrap_receipt(self.r0)
        bootstrap_cleanup = cleanup_receipt(
            self.r1,
            self.r0,
            [],
            attempt_id=bootstrap["attempt_id"],
            receipt_id="receipt-cleanup-bootstrap",
        )
        with self.assertRaisesRegex(LocalReleaseIdentityError, "bootstrap.*cleanup"):
            lint_local_release_graph(
                release_manifests=[self.r0, self.r1],
                active_release=self.active,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
                receipts=[bootstrap, bootstrap_cleanup],
            )

    def test_graph_rejects_release_values_equal_actual_receipt_identity(self) -> None:
        historical = transition_receipt(self.r0, self.r_minus_1)
        for identity in (historical["receipt_id"], historical["receipt_sha256"]):
            with self.subTest(identity=identity):
                candidate = deepcopy(self.r1)
                candidate["application"]["provenance"]["labels"] = [identity]
                with self.assertRaisesRegex(
                    LocalReleaseIdentityError, "control identity"
                ):
                    lint_local_release_graph(
                        release_manifests=[
                            self.r_minus_1,
                            self.r0,
                            candidate,
                        ],
                        active_release=active(candidate),
                        local_prior_binding=binding(candidate, self.r0),
                        retained_release_refs=[
                            release_ref(candidate),
                            release_ref(self.r0),
                        ],
                        receipts=[historical],
                    )

    def test_graph_rejects_control_identity_split_across_string_sequences(self) -> None:
        historical = transition_receipt(self.r0, self.r_minus_1)
        rendered = _fullwidth_ascii(str(historical["receipt_id"]).upper())
        for piece_count, prefixes in ((2, ("!", "#")), (3, ("!", "#", "$"))):
            with self.subTest(piece_count=piece_count):
                cuts = [
                    len(rendered) * index // piece_count
                    for index in range(piece_count + 1)
                ]
                labels = [
                    prefixes[index] + rendered[cuts[index]:cuts[index + 1]]
                    for index in range(piece_count)
                ]
                self.assertEqual(labels, sorted(labels))
                candidate = deepcopy(self.r1)
                candidate["application"]["provenance"]["labels"] = labels
                with self.assertRaisesRegex(
                    LocalReleaseIdentityError, "control identity"
                ):
                    lint_local_release_graph(
                        release_manifests=[
                            self.r_minus_1,
                            self.r0,
                            candidate,
                        ],
                        active_release=active(candidate),
                        local_prior_binding=binding(candidate, self.r0),
                        retained_release_refs=[
                            release_ref(candidate),
                            release_ref(self.r0),
                        ],
                        receipts=[historical],
                    )

    def test_reverse_edge_cycle_material_and_incompatible_state_are_rejected(self) -> None:
        circular_release = deepcopy(self.r1)
        circular_release["application"]["active_pointer"] = {
            "binding_sha256": self.binding["binding_sha256"]
        }
        with self.assertRaisesRegex(LocalReleaseIdentityError, "closed"):
            lint_local_release_graph(
                release_manifests=[self.r0, circular_release],
                active_release=self.active,
                local_prior_binding=self.binding,
                retained_release_refs=[release_ref(self.r1), release_ref(self.r0)],
            )

        incompatible_prior = release(
            "release-r0", "9", comments_read=[1], comments_write=[1]
        )
        incompatible_binding = binding(self.r1, incompatible_prior)
        with self.assertRaisesRegex(LocalReleaseIdentityError, "cannot read/write"):
            lint_local_release_graph(
                release_manifests=[incompatible_prior, self.r1],
                active_release=self.active,
                local_prior_binding=incompatible_binding,
                retained_release_refs=[release_ref(self.r1), release_ref(incompatible_prior)],
            )

    def test_linter_has_no_recovery_checkpoint_or_dynamic_probe_parameters(self) -> None:
        parameters = inspect.signature(lint_local_release_graph).parameters
        self.assertEqual(
            {
                "release_manifests",
                "active_release",
                "local_prior_binding",
                "retained_release_refs",
                "receipts",
            },
            set(parameters),
        )
        self.assertTrue(
            {"started", "health", "writer_fence", "recovery", "checkpoint"}.isdisjoint(
                parameters
            )
        )


if __name__ == "__main__":
    unittest.main()

"""Stage 5 本机发布身份图固定语料与现场重放 producer。

本模块只证明 :func:`lint_local_release_graph` 对固定正反例语料的本机功能闭包。
它不是独立 verifier，也不提供 MCP 运行身份、隔离环境或证据时序的可信根。
生产 CLI 只允许在 exact-D 项目根内读取四个 current subject artifact，并以
create-only 普通文件写入固定 corpus 与 replay report。
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Mapping, Sequence

from .local_release_identity import (
    ACTIVATION_RECEIPT_SCHEMA,
    ACTIVE_RELEASE_SCHEMA,
    LOCAL_PRIOR_BINDING_SCHEMA,
    LOCAL_STATE_IDENTITY_SCHEMA,
    RELEASE_MANIFEST_SCHEMA,
    LocalReleaseGraphReport,
    LocalReleaseIdentityError,
    canonical_bytes,
    identity_sha256,
    lint_local_release_graph,
)


CORPUS_SCHEMA = "qrh-stage5-identity-graph-fixture-corpus/v1"
REPORT_SCHEMA = "qrh-stage5-identity-graph-fixture-report/v1"
REPORT_AUTHORITY_SCOPE = "LOCAL_FUNCTIONAL_CLOSURE_NOT_INDEPENDENT_TRUST_ROOT"
GATE_ROLE = "identity_graph_negative_fixtures"
PRODUCER_NAME = "qrh-stage5-identity-graph-fixture-producer"
PRODUCER_VERSION = "1.0.0"

_EXPECTED_POSITIVE_GRAPH_SHA256 = (
    "22db7adbe4fb891f308c2d7eb4ebdcb093ed5320e82292fd950496db05d9e20c"
)


class IdentityGraphFixtureError(RuntimeError):
    """固定语料或 producer 输入/输出没有闭合。"""


def _hash(character: str) -> str:
    return character * 64


def _seal(value: dict[str, object], field: str) -> dict[str, object]:
    material = deepcopy(value)
    material.pop(field, None)
    value[field] = identity_sha256(material)
    return value


def _release(
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
        "built_at": "2026-08-31T00:00:00Z",
        "application": {
            "source_kind": "git",
            "commit_sha": character * 40,
            "tracked_tree_sha256": _hash(character),
            "build_tool_version": "stage5-identity-graph-fixtures/v1",
            "provenance": {"builder": PRODUCER_NAME, "labels": []},
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


def _release_ref(value: Mapping[str, object]) -> dict[str, object]:
    release_id = str(value["release_id"])
    return {
        "release_id": release_id,
        "release_path": rf"D:\quant\quant_platform\releases\{release_id}",
        "manifest_sha256": identity_sha256(value),
    }


def _state_identity() -> dict[str, object]:
    return _seal(
        {
            "schema_version": LOCAL_STATE_IDENTITY_SCHEMA,
            "authority_id": "production-d-state",
            "state_path": r"D:\quant\quant_platform\state",
            "schema_versions": {"comments": 2, "research_workspace": 3},
        },
        "identity_sha256",
    )


def _active(value: Mapping[str, object]) -> dict[str, object]:
    return {"schema_version": ACTIVE_RELEASE_SCHEMA, "release": _release_ref(value)}


def _pair(
    active_release: Mapping[str, object], prior_release: Mapping[str, object]
) -> dict[str, object]:
    return {
        "active": _release_ref(active_release),
        "prior": _release_ref(prior_release),
    }


def _binding(
    active_release: Mapping[str, object], prior_release: Mapping[str, object]
) -> dict[str, object]:
    pair = _pair(active_release, prior_release)
    return _seal(
        {
            "schema_version": LOCAL_PRIOR_BINDING_SCHEMA,
            "binding_id": "binding-stage5-r1-r0",
            "recorded_at": "2026-08-31T00:01:00Z",
            "authority": "retention_evidence_only",
            "active": pair["active"],
            "prior": pair["prior"],
            "state_identity": _state_identity(),
            "result": {
                "status": "bound",
                "pair_sha256": identity_sha256(pair),
                "retained_release_count": 2,
                "state_policy": "expand_only_no_down_migration",
            },
        },
        "binding_sha256",
    )


def _activation_receipt(
    active_release: Mapping[str, object], prior_release: Mapping[str, object]
) -> dict[str, object]:
    pair = _pair(active_release, prior_release)
    return _seal(
        {
            "schema_version": ACTIVATION_RECEIPT_SCHEMA,
            "receipt_id": "receipt-stage5-r1-r0",
            "attempt_id": "attempt-stage5-r1-r0",
            "recorded_at": "2026-08-31T00:02:00Z",
            "authority": "evidence_only",
            "operation": "activate_successor",
            "pair": pair,
            "result": {
                "status": "activated",
                "pair_sha256": identity_sha256(pair),
                "controller_verification_sha256": _hash("8"),
            },
        },
        "receipt_sha256",
    )


def _graph_document(report: LocalReleaseGraphReport) -> Mapping[str, object]:
    return {
        "active_manifest_sha256": report.active_manifest_sha256,
        "prior_manifest_sha256": report.prior_manifest_sha256,
        "release_manifest_count": report.release_manifest_count,
        "retained_release_count": report.retained_release_count,
        "receipt_count": report.receipt_count,
        "edges": [list(edge) for edge in report.edges],
    }


def _base_input() -> dict[str, object]:
    prior = _release("fixture-release-r0", "a")
    active = _release("fixture-release-r1", "b")
    return {
        "release_manifests": [prior, active],
        "active_release": _active(active),
        "local_prior_binding": _binding(active, prior),
        "retained_release_refs": [_release_ref(active), _release_ref(prior)],
        "receipts": [],
    }


def _negative_inputs() -> list[tuple[str, dict[str, object]]]:
    values: list[tuple[str, dict[str, object]]] = []

    receipt_as_active = _base_input()
    receipt_as_active["active_release"] = _activation_receipt(
        receipt_as_active["release_manifests"][1],
        receipt_as_active["release_manifests"][0],
    )
    values.append(("receipt-as-active-pointer", receipt_as_active))

    binding_drift = _base_input()
    binding_drift["active_release"] = _active(binding_drift["release_manifests"][0])
    values.append(("active-binding-drift", binding_drift))

    extra_retained = _base_input()
    older = _release("fixture-release-r-minus-1", "c")
    extra_retained["release_manifests"].append(older)
    extra_retained["retained_release_refs"].append(_release_ref(older))
    values.append(("multiple-prior-retained", extra_retained))

    wrong_third = _base_input()
    wrong_third["release_manifests"].append(older)
    wrong_third["retained_release_refs"] = [
        wrong_third["retained_release_refs"][0],
        _release_ref(older),
    ]
    values.append(("third-release-selected", wrong_third))

    reverse_active = _base_input()
    reverse_active_release = deepcopy(reverse_active["release_manifests"][1])
    reverse_active_release["application"]["provenance"]["labels"] = [
        r"D:\quant\quant_platform\control\active_release.json"
    ]
    reverse_active["release_manifests"][1] = reverse_active_release
    reverse_active["active_release"] = _active(reverse_active_release)
    reverse_active["local_prior_binding"] = _binding(
        reverse_active_release, reverse_active["release_manifests"][0]
    )
    reverse_active["retained_release_refs"][0] = _release_ref(reverse_active_release)
    values.append(("release-back-reference-active", reverse_active))

    reverse_binding = _base_input()
    reverse_binding_release = deepcopy(reverse_binding["release_manifests"][1])
    reverse_binding_release["application"]["provenance"]["labels"] = [
        "binding-stage5-r1-r0"
    ]
    reverse_binding["release_manifests"][1] = reverse_binding_release
    reverse_binding["active_release"] = _active(reverse_binding_release)
    reverse_binding["local_prior_binding"] = _binding(
        reverse_binding_release, reverse_binding["release_manifests"][0]
    )
    reverse_binding["retained_release_refs"][0] = _release_ref(reverse_binding_release)
    values.append(("release-back-reference-binding", reverse_binding))

    reverse_receipt = _base_input()
    reverse_receipt_release = deepcopy(reverse_receipt["release_manifests"][1])
    reverse_receipt_release["application"]["provenance"]["labels"] = [
        "receipt-stage5-r1-r0"
    ]
    reverse_receipt["release_manifests"][1] = reverse_receipt_release
    reverse_receipt["active_release"] = _active(reverse_receipt_release)
    reverse_receipt["local_prior_binding"] = _binding(
        reverse_receipt_release, reverse_receipt["release_manifests"][0]
    )
    reverse_receipt["retained_release_refs"][0] = _release_ref(reverse_receipt_release)
    reverse_receipt["receipts"] = [
        _activation_receipt(
            reverse_receipt_release, reverse_receipt["release_manifests"][0]
        )
    ]
    values.append(("release-back-reference-receipt", reverse_receipt))

    incompatible = _base_input()
    incompatible_prior = _release(
        "fixture-release-r0",
        "a",
        comments_read=[1],
        comments_write=[1],
    )
    incompatible["release_manifests"][0] = incompatible_prior
    incompatible["local_prior_binding"] = _binding(
        incompatible["release_manifests"][1], incompatible_prior
    )
    incompatible["retained_release_refs"][1] = _release_ref(incompatible_prior)
    values.append(("prior-cannot-use-current-state", incompatible))

    duplicate_id = _base_input()
    duplicate_id["release_manifests"].append(
        _release("fixture-release-r0", "d")
    )
    values.append(("duplicate-release-identity", duplicate_id))
    return values


def fixed_corpus_document() -> Mapping[str, object]:
    """返回 byte-stable v1 corpus；expected 不能由待验 linter 现场自填。"""

    fixtures: list[Mapping[str, object]] = [
        {
            "fixture_id": "positive-active-prior",
            "expected_result": "accept",
            "expected_graph_sha256": _EXPECTED_POSITIVE_GRAPH_SHA256,
            "input": _base_input(),
        }
    ]
    fixtures.extend(
        {
            "fixture_id": fixture_id,
            "expected_result": "reject",
            "expected_graph_sha256": None,
            "input": fixture_input,
        }
        for fixture_id, fixture_input in _negative_inputs()
    )
    payload: dict[str, object] = {
        "schema_version": CORPUS_SCHEMA,
        "corpus_id": "local-release-identity-v1",
        "fixtures": fixtures,
    }
    payload["corpus_payload_sha256"] = identity_sha256(payload)
    return json.loads(canonical_bytes(payload).decode("utf-8"))


def _lint_input(value: object) -> LocalReleaseGraphReport:
    if type(value) is not dict or set(value) != {
        "release_manifests",
        "active_release",
        "local_prior_binding",
        "retained_release_refs",
        "receipts",
    }:
        raise IdentityGraphFixtureError("fixture input schema 不闭合")
    return lint_local_release_graph(
        release_manifests=value["release_manifests"],
        active_release=value["active_release"],
        local_prior_binding=value["local_prior_binding"],
        retained_release_refs=value["retained_release_refs"],
        receipts=value["receipts"],
    )


def replay_fixed_corpus(corpus: object) -> tuple[Mapping[str, object], ...]:
    """逐项调用真实 linter，并将观察与冻结 expected 双向核对。"""

    expected = fixed_corpus_document()
    try:
        supplied = json.loads(canonical_bytes(corpus).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, LocalReleaseIdentityError) as error:
        raise IdentityGraphFixtureError("corpus 不是 canonical JSON") from error
    if canonical_bytes(supplied) != canonical_bytes(expected):
        raise IdentityGraphFixtureError("corpus bytes/hash 漂移")
    if type(supplied) is not dict or set(supplied) != {
        "schema_version",
        "corpus_id",
        "fixtures",
        "corpus_payload_sha256",
    }:
        raise IdentityGraphFixtureError("corpus schema 不闭合")
    material = dict(supplied)
    payload_hash = material.pop("corpus_payload_sha256", None)
    if payload_hash != identity_sha256(material):
        raise IdentityGraphFixtureError("corpus payload hash 漂移")
    fixtures = supplied["fixtures"]
    if not isinstance(fixtures, list) or not fixtures:
        raise IdentityGraphFixtureError("corpus fixtures 为空")
    outcomes: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for raw_fixture in fixtures:
        if type(raw_fixture) is not dict or set(raw_fixture) != {
            "fixture_id",
            "expected_result",
            "expected_graph_sha256",
            "input",
        }:
            raise IdentityGraphFixtureError("fixture schema 不闭合")
        fixture_id = raw_fixture["fixture_id"]
        if not isinstance(fixture_id, str) or not fixture_id or fixture_id in seen:
            raise IdentityGraphFixtureError("fixture_id 非法或重复")
        seen.add(fixture_id)
        expected_result = raw_fixture["expected_result"]
        expected_graph = raw_fixture["expected_graph_sha256"]
        try:
            report = _lint_input(raw_fixture["input"])
        except (LocalReleaseIdentityError, IdentityGraphFixtureError) as error:
            observed_result = "reject"
            observed_graph = None
            error_kind = type(error).__name__
        else:
            observed_result = "accept"
            observed_graph = identity_sha256(_graph_document(report))
            error_kind = None
        if expected_result not in {"accept", "reject"}:
            raise IdentityGraphFixtureError("fixture expected_result 不受支持")
        if expected_result == "accept":
            if not isinstance(expected_graph, str) or len(expected_graph) != 64:
                raise IdentityGraphFixtureError("positive fixture 缺 expected graph hash")
            if observed_result != "accept" or observed_graph != expected_graph:
                raise IdentityGraphFixtureError(
                    f"positive fixture {fixture_id} 被拒绝或 graph hash 漂移"
                )
        elif expected_graph is not None or observed_result != "reject":
            raise IdentityGraphFixtureError(
                f"negative fixture {fixture_id} 被接受或 expected graph 非空"
            )
        outcomes.append(
            {
                "fixture_id": fixture_id,
                "expected_result": expected_result,
                "expected_graph_sha256": expected_graph,
                "observed_result": observed_result,
                "observed_graph_sha256": observed_graph,
                "error_kind": error_kind,
            }
        )
    return tuple(outcomes)


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def artifact_input_aggregate_sha256(
    artifacts: Sequence[Mapping[str, object]],
) -> str:
    """绑定 path/schema/bytes；不让可重新命名的 artifact_id/时间成为第二身份。"""

    material = [
        {
            "relative_path": item["relative_path"],
            "artifact_kind": item["artifact_kind"],
            "schema_version": item["schema_version"],
            "sha256": item["sha256"],
            "size_bytes": item["size_bytes"],
        }
        for item in artifacts
    ]
    material.sort(
        key=lambda item: (
            str(item["relative_path"]),
            str(item["schema_version"]),
            str(item["sha256"]),
        )
    )
    return hashlib.sha256(canonical_bytes(material)).hexdigest()


def produce_report(
    *,
    corpus: Mapping[str, object],
    subject_artifacts: Sequence[Mapping[str, object]],
    support_artifacts: Sequence[Mapping[str, object]],
    produced_at: str,
) -> Mapping[str, object]:
    """重放 corpus 后产生严格 report；不信任调用方提供的 outcome。"""

    outcomes = replay_fixed_corpus(corpus)
    positive = [item for item in outcomes if item["expected_result"] == "accept"]
    negative = [item for item in outcomes if item["expected_result"] == "reject"]
    input_refs = [*subject_artifacts, *support_artifacts]
    corpus_bytes = canonical_bytes(corpus)
    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA,
        "report_id": "stage5-identity-graph-fixtures-v1",
        "gate_role": GATE_ROLE,
        "authority_scope": REPORT_AUTHORITY_SCOPE,
        "producer": {"name": PRODUCER_NAME, "version": PRODUCER_VERSION},
        "produced_at": produced_at,
        "input_artifact_aggregate_sha256": artifact_input_aggregate_sha256(
            input_refs
        ),
        "corpus": {
            "schema_version": CORPUS_SCHEMA,
            "sha256": hashlib.sha256(corpus_bytes).hexdigest(),
            "size_bytes": len(corpus_bytes),
        },
        "fixtures": list(outcomes),
        "result": {
            "positive_fixtures_total": len(positive),
            "positive_fixtures_accepted": len(positive),
            "negative_fixtures_total": len(negative),
            "negative_fixtures_rejected": len(negative),
        },
    }
    report["report_sha256"] = identity_sha256(report)
    return json.loads(canonical_bytes(report).decode("utf-8"))


def write_fixed_d_report(
    *,
    evidence_root: Path,
    subject_paths: Sequence[str],
    corpus_output: str,
    report_output: str,
) -> Mapping[str, object]:
    """从 exact-D subject 现场读取并 create-only 写 corpus/report。"""

    # Lazy import avoids a module cycle: release_closure registers this producer's
    # adapter, while this write path reuses its audited path/artifact primitives.
    from . import release_closure as closure

    root = closure._evidence_root(evidence_root)  # noqa: SLF001
    if len(subject_paths) != 4 or len(set(subject_paths)) != 4:
        raise IdentityGraphFixtureError("subject path 必须恰为四个且唯一")
    subject_refs: list[Mapping[str, object]] = []
    observed_at = _utc_now_text()
    for index, raw_relative in enumerate(subject_paths):
        relative = closure._relative_path(raw_relative, label="subject path")  # noqa: SLF001
        document, raw = closure._canonical_json_file(root, relative)  # noqa: SLF001
        schema = document.get("schema_version")
        if schema not in {
            ACTIVE_RELEASE_SCHEMA,
            LOCAL_PRIOR_BINDING_SCHEMA,
            RELEASE_MANIFEST_SCHEMA,
        }:
            raise IdentityGraphFixtureError("subject artifact schema 不受支持")
        subject_refs.append(
            {
                "artifact_id": f"identity-subject-{index}",
                "relative_path": relative,
                "artifact_kind": "canonical_json",
                "schema_version": schema,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
                "observed_at": observed_at,
            }
        )
    subject_refs.sort(key=lambda item: (str(item["artifact_id"]), str(item["relative_path"])))
    closure._subject_from_artifacts(root, subject_refs)  # noqa: SLF001

    corpus_relative = closure._relative_path(corpus_output, label="corpus output")  # noqa: SLF001
    report_relative = closure._relative_path(report_output, label="report output")  # noqa: SLF001
    if corpus_relative == report_relative:
        raise IdentityGraphFixtureError("corpus/report output 不得相同")
    # Complete collision/path preflight before the first create-only write.
    for relative in (corpus_relative, report_relative):
        candidate = root.joinpath(*relative.split("/"))
        if candidate.exists() or candidate.is_symlink():
            raise IdentityGraphFixtureError("producer output 已存在")

    corpus = fixed_corpus_document()
    corpus_bytes = canonical_bytes(corpus)
    corpus_ref = {
        "artifact_id": "identity-graph-fixed-corpus-v1",
        "relative_path": corpus_relative,
        "artifact_kind": "canonical_json",
        "schema_version": CORPUS_SCHEMA,
        "sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "size_bytes": len(corpus_bytes),
        "observed_at": observed_at,
    }
    report = produce_report(
        corpus=corpus,
        subject_artifacts=subject_refs,
        support_artifacts=[corpus_ref],
        produced_at=observed_at,
    )
    closure._create_canonical_file(root, corpus_relative, corpus)  # noqa: SLF001
    closure._create_canonical_file(root, report_relative, report)  # noqa: SLF001
    corpus_path = closure._regular_file(root, corpus_relative)  # noqa: SLF001
    report_path = closure._regular_file(root, report_relative)  # noqa: SLF001
    if corpus_path.read_bytes() != corpus_bytes or report_path.read_bytes() != canonical_bytes(report):
        raise IdentityGraphFixtureError("producer create-only ordinary-file 回读漂移")
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--subject", action="append", required=True)
    parser.add_argument("--corpus-output", required=True)
    parser.add_argument("--report-output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        from . import release_closure as closure

        root = closure._cli_evidence_root(args.evidence_root)  # noqa: SLF001
        result = write_fixed_d_report(
            evidence_root=root,
            subject_paths=args.subject,
            corpus_output=args.corpus_output,
            report_output=args.report_output,
        )
    except (
        LocalReleaseIdentityError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        sys.stderr.write(f"identity graph fixture producer failed: {error}\n")
        return 2
    sys.stdout.write(canonical_bytes(result).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CORPUS_SCHEMA",
    "GATE_ROLE",
    "IdentityGraphFixtureError",
    "PRODUCER_NAME",
    "PRODUCER_VERSION",
    "REPORT_AUTHORITY_SCOPE",
    "REPORT_SCHEMA",
    "artifact_input_aggregate_sha256",
    "fixed_corpus_document",
    "main",
    "produce_report",
    "replay_fixed_corpus",
    "write_fixed_d_report",
]

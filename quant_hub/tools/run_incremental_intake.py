"""运行稳定 Markdown 增量导入，并可接续 Evidence activation 投影。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from quant_hub.config import Settings
from quant_hub.integration import (
    EvidenceProjectionConsumer,
    IncrementalIntake,
    IntakeSource,
    LocalSpoolEvidenceAdapter,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, help="quant_platform 项目根目录。")
    parser.add_argument("--archive-root", type=Path, help="只读 Archive 根目录。")
    parser.add_argument("--var-root", type=Path, help="目标实例的可写运行目录。")
    parser.add_argument(
        "--include-archive",
        action="store_true",
        help="同时扫描只读 reference/archive；已有显式映射会审计跳过。",
    )
    parser.add_argument(
        "--inbox-root",
        type=Path,
        help="研究 Markdown 投放目录；默认 quant_hub/var/inbox/research。",
    )
    parser.add_argument(
        "--consume-evidence",
        action="store_true",
        help="导入后幂等消费尚未投影的正式 EvidenceReleaseActivated 事件。",
    )
    parser.add_argument(
        "--transport-only-spool",
        action="store_true",
        help=(
            "仅冻结跨域命令，不写 Evidence 数据库；该模式会保持父任务 "
            "waiting_external，不能形成完成凭据。"
        ),
    )
    parser.add_argument("--report", type=Path, help="可选 UTF-8 JSON 报告路径。")
    args = parser.parse_args()

    settings = Settings.default(
        project_root=args.project_root,
        archive_root=args.archive_root,
        var_root=args.var_root,
    )
    settings.ensure_runtime_directories()
    inbox = (args.inbox_root or settings.var_root / "inbox" / "research").absolute()
    inbox.mkdir(parents=True, exist_ok=True)
    sources = [IntakeSource("research_inbox", inbox)]
    if args.include_archive:
        sources.insert(0, IntakeSource("archive", settings.archive_root))
    adapter = LocalSpoolEvidenceAdapter(settings) if args.transport_only_spool else None
    service = IncrementalIntake(settings, adapter)
    report = service.scan(tuple(sources))
    payload: dict[str, object] = {"intake": report.to_dict()}
    if args.consume_evidence:
        payload["evidence_projection"] = [
            {
                "event_id": result.event_id,
                "evidence_release_id": result.evidence_release_id,
                "stale_noop": result.stale_noop,
                "updates": [
                    {
                        "research_urn": row.research_urn,
                        "research_id": row.research_id,
                        "evidence_status": row.evidence_status,
                    }
                    for row in result.updates
                ],
                "unmapped_research_urns": list(result.unmapped_research_urns),
                "result_hash": result.result_hash,
                "created": result.created,
            }
            for result in EvidenceProjectionConsumer(settings).consume_pending()
        ]
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0 if report.status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

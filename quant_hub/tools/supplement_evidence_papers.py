"""Second-pass acquisition for Evidence papers with known author/official copies.

This script only materializes sources that were manually matched by exact title.  It
updates the first-pass manifest atomically after verifying PDF structure and hash.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil

from fetch_evidence_papers import ROOT, _download_pdf, _sha256, _verified_pdf


LIBRARY = ROOT / "quant_hub" / "paper_lab" / "papers"
MANIFEST = LIBRARY / "ACQUISITION_MANIFEST.json"
PAPER_LAB_ASSET = (
    ROOT
    / "quant_hub"
    / "var"
    / "delivery-final-reviewed-v5-20260716-v9"
    / "paper_lab"
    / "assets"
    / "be"
    / "be53927784dfbc40108b09877b5380e916bd98a766fe58a025ccd5ac9a4e86aa.pdf"
)


# Exact-title matches reviewed against author, institutional, conference, journal,
# government, or openly licensed publisher locations on 2026-07-16.
URLS: dict[str, list[tuple[str, str]]] = {
    "A Backtesting Protocol in the Era of Machine Learning": [
        ("https://people.duke.edu/~charvey/Research/Published_Papers/SSRN-id3275654.pdf", "author_repository"),
    ],
    "A well-conditioned estimator for large-dimensional covariance matrices": [
        ("https://perso.ens-lyon.fr/patrick.flandrin/LedoitWolf_JMA2004.pdf", "academic_repository"),
        ("https://www.ledoit.net/Well-conditioned2004.pdf", "author_repository"),
    ],
    "An introduction to ROC analysis": [
        ("https://people.inf.elte.hu/kiss/13dwhdm/roc.pdf", "academic_repository"),
    ],
    "Are Emergent Abilities of Large Language Models a Mirage?": [
        ("https://papers.neurips.cc/paper_files/paper/2023/file/adc98a266f45005c403b8311ca7e8bd7-Paper-Conference.pdf", "conference_official"),
        ("https://arxiv.org/pdf/2304.15004", "arxiv"),
    ],
    "Backtesting": [
        ("https://www.cmegroup.com/content/dam/cmegroup/education/files/backtesting.pdf", "publisher_official"),
    ],
    "Control Chart Tests Based on Geometric Moving Averages": [
        ("https://www.stat.cmu.edu/technometrics/59-69/VOL-01-03/v0103239.pdf", "journal_archive"),
    ],
    "Efficiently Inefficient Markets for Assets and Asset Management": [
        ("https://www.nber.org/papers/w21563.pdf", "nber_official"),
        ("https://www.bis.org/events/conf150310/garleanu_pedersen.pdf", "bis_repository"),
    ],
    "Empirical properties of asset returns: stylized facts and statistical issues": [
        ("http://finance.martinsewell.com/stylized-facts/dependence/Cont2001.pdf", "academic_repository"),
        ("https://citeseerx.ist.psu.edu/document?doi=98b8e6d5e3963ab30ecacf08c252f73cc67537c6&repid=rep1&type=pdf", "academic_repository"),
    ],
    "Flat Minima": [
        ("https://direct.mit.edu/neco/article-pdf/9/1/1/814729/neco.1997.9.1.1.pdf", "publisher_official"),
        ("https://people.idsia.ch/~juergen/FKI-200-94ocr.pdf", "author_repository_technical_report_version"),
        ("https://people.idsia.ch/~juergen/fm.pdf", "author_repository"),
    ],
    "How to Use the Sharpe Ratio": [
        ("https://papers.ssrn.com/sol3/Delivery.cfm?abstractid=5520741", "ssrn_author_upload"),
        ("https://papers.ssrn.com/sol3/Delivery.cfm/5520741.pdf?abstractid=5520741&mirid=1", "ssrn_author_upload"),
    ],
    "Improving generalization performance using double backpropagation": [
        ("http://yann.lecun.com/exdb/publis/pdf/drucker-lecun-92.pdf", "author_repository"),
        ("https://yann.lecun.com/exdb/publis/pdf/drucker-92.pdf", "author_repository"),
    ],
    "Information-theoretic determination of minimax rates of convergence": [
        ("http://www.stat.yale.edu/~arb4/publications_files/Information-TheoreticDeterminationOfMinimaxRatesOfConvergenceAnnalsStatistics.pdf", "author_repository"),
        ("https://www.stat.yale.edu/~arb4/publications_files/Information-TheoreticDeterminationOfMinimaxRatesOfConvergenceAnnalsStatistics.pdf", "author_repository"),
    ],
    "Leakage and the reproducibility crisis in machine-learning-based science": [
        ("https://arxiv.org/pdf/2207.07048", "author_preprint_repository"),
        ("https://hbiostat.org/papers/kap23lea.pdf", "academic_repository_open_access"),
    ],
    "Long Short-Term Memory": [
        ("https://people.idsia.ch/~juergen/lstm1997-2024head.pdf", "author_repository"),
        ("https://people.idsia.ch/~juergen/FKI-207-95ocr.pdf", "author_repository_technical_report_version"),
        ("https://people.idsia.ch/~juergen/lstm.pdf", "author_repository"),
    ],
    "Machine learning in the Chinese stock market": [
        ("https://sribd-kaizhang.github.io/quantdoc/pdf/machine_learning_in_the_chinese_stock_market.pdf", "academic_repository_open_access"),
    ],
    "On the use of cross-validation for time series predictor evaluation": [
        ("https://sci2s.ugr.es/keel/pdf/specific/articulo/bergmeir12.pdf", "author_institution_repository"),
        ("https://www.sciencedirect.com/science/article/pii/S0020025511006773/pdfft?isDTMRedir=true&download=true", "publisher_official"),
    ],
    "Ordinal Measures of Association": [
        ("https://www.jstor.org/stable/pdf/2281954.pdf", "journal_archive"),
        ("http://www.tandfonline.com/doi/pdf/10.1080/01621459.1958.10501481", "publisher_archive"),
        ("https://www.tandfonline.com/doi/pdf/10.1080/01621459.1958.10501481", "publisher_archive"),
    ],
    "The Adaptive Markets Hypothesis": [
        ("https://dspace.mit.edu/bitstream/handle/1721.1/75362/Lo_Adaptive%20Markets.pdf", "mit_repository"),
    ],
    "The three-pass regression filter: A new approach to forecasting using many predictors": [
        ("https://economics.sas.upenn.edu/sites/default/files/filevault/event_papers/Econometrics12052011.pdf", "academic_repository"),
    ],
}


def _materialize(item: dict[str, object], payload: bytes, *, source: str, source_url: str) -> None:
    target = ROOT / str(item["target"])
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".part")
    temporary.write_bytes(payload)
    os.replace(temporary, target)
    item.update(
        {
            "status": "supplemental_verified_pdf",
            "source": source,
            "source_url": source_url,
            "sha256": _sha256(payload),
            "bytes": len(payload),
            "acquired_at": datetime.now(UTC).isoformat(),
        }
    )


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    acquired = 0
    for item in manifest["papers"]:
        if item.get("status") != "missing":
            continue
        title = str(item["title"])
        if title == "Machine learning in the Chinese stock market" and PAPER_LAB_ASSET.is_file():
            payload = PAPER_LAB_ASSET.read_bytes()
            if _verified_pdf(payload):
                _materialize(
                    item,
                    payload,
                    source="paper_lab_reviewed_asset",
                    source_url="paper-lab://reviewed-asset/be53927784dfbc40108b09877b5380e916bd98a766fe58a025ccd5ac9a4e86aa",
                )
                acquired += 1
                print(f"acquired {title} from reviewed Paper Lab asset", flush=True)
                continue
        for url, source in URLS.get(title, []):
            payload, final_url, result = _download_pdf(url)
            item.setdefault("attempts", []).append(
                {"source": source, "url": url, "final_url": final_url, "result": result}
            )
            if payload is None:
                continue
            _materialize(item, payload, source=source, source_url=final_url)
            acquired += 1
            print(f"acquired {title} from {source}", flush=True)
            break
        else:
            print(f"still missing {title}", flush=True)
    statuses: dict[str, int] = {}
    for item in manifest["papers"]:
        status = str(item["status"])
        statuses[status] = statuses.get(status, 0) + 1
    manifest["supplemented_at"] = datetime.now(UTC).isoformat()
    manifest["summary"] = {
        "canonical_papers": len(manifest["papers"]),
        "pdf_files": sum(1 for item in manifest["papers"] if item["status"] != "missing"),
        "missing": statuses.get("missing", 0),
        "statuses": statuses,
    }
    temporary = MANIFEST.with_suffix(".json.part")
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, MANIFEST)
    print(json.dumps({"acquired": acquired, "summary": manifest["summary"]}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

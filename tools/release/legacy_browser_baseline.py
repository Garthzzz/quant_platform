"""Capture a read-only browser/API baseline for an existing broadcast release."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from playwright.sync_api import Page, sync_playwright


DEFAULT_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _goto(page: Page, url: str) -> int:
    response = page.goto(url, wait_until="networkidle")
    if response is None:
        raise RuntimeError(f"navigation returned no response: {url}")
    return response.status


def _login(page: Page, base_url: str, password: str | None) -> None:
    status = _goto(page, base_url + "/")
    if status != 200:
        raise RuntimeError(f"home returned HTTP {status}")
    if "/login" not in page.url:
        return
    if password is None:
        raise RuntimeError("broadcast requires --access-password")
    page.locator("input[name=password]").fill(password)
    with page.expect_navigation(wait_until="networkidle"):
        page.locator("button[type=submit]").click()
    if "/login" in page.url:
        raise RuntimeError("broadcast login failed")


def _page_facts(page: Page, *, status: int) -> dict[str, Any]:
    return {
        "url": page.url,
        "status": status,
        "title": page.title(),
        "h1": page.locator("h1").all_inner_texts(),
        "links": page.locator("a[href]").count(),
        "forms": page.locator("form").count(),
        "tables": page.locator("table").count(),
        "math_nodes": page.locator("math, .math-display, .math-inline").count(),
        "citation_nodes": page.locator(
            "[data-citation-id], [data-source-id], .citation, .source-citation"
        ).count(),
        "script_errors": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--access-password")
    parser.add_argument("--expected-deployment-id", required=True)
    parser.add_argument("--chrome", type=Path, default=DEFAULT_CHROME)
    args = parser.parse_args()

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    base_url = args.base_url.rstrip("/")
    report: dict[str, Any] = {
        "schema_version": "qrh-legacy-browser-baseline/v1",
        "captured_at": datetime.now(UTC).isoformat(),
        "base_url": base_url,
        "expected_deployment_id": args.expected_deployment_id,
        "authenticated": False,
        "pages": {},
        "screenshots": [],
        "status": "FAIL",
    }
    console_errors: list[str] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=str(args.chrome),
                headless=True,
                args=("--disable-background-networking",),
            )
            desktop = browser.new_context(viewport={"width": 1440, "height": 1100})
            page = desktop.new_page()
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            _login(page, base_url, args.access_password)
            report["authenticated"] = True

            health = page.evaluate(
                "async () => { const r=await fetch('/deploymentz'); "
                "return {status:r.status, body:await r.json()}; }"
            )
            if health["status"] != 200 or health["body"].get(
                "deployment_id"
            ) != args.expected_deployment_id:
                raise RuntimeError("deployment health identity differs")
            report["health"] = health

            report["pages"]["home"] = _page_facts(page, status=200)
            home_shot = output / "home-desktop.png"
            page.screenshot(path=str(home_shot), full_page=True)

            research_api = page.evaluate(
                "async () => { const r=await fetch('/api/v1/research'); "
                "return {status:r.status, body:await r.json()}; }"
            )
            if research_api["status"] != 200:
                raise RuntimeError("research API is unavailable")
            research = research_api["body"]["data"]["research"]
            if not research:
                raise RuntimeError("research API returned no documents")
            selected = next(
                (item for item in research if item.get("canonical_slug")), research[0]
            )
            slug = selected.get("canonical_slug") or selected.get("slug")
            if not isinstance(slug, str) or not slug:
                raise RuntimeError("research API has no stable slug")
            research_id = selected.get("research_id")
            if not isinstance(research_id, str) or not research_id:
                raise RuntimeError("research API has no stable research_id")
            research_status = _goto(page, f"{base_url}/research/{research_id}")
            if research_status != 200:
                raise RuntimeError(f"research page returned HTTP {research_status}")
            report["pages"]["research"] = _page_facts(
                page, status=research_status
            )
            report["selected_research"] = {
                "research_id": research_id,
                "canonical_slug": slug,
            }
            research_shot = output / "research-desktop.png"
            page.screenshot(path=str(research_shot), full_page=True)

            paper_link = page.locator("a[href*='paper']").first
            if paper_link.count():
                href = paper_link.get_attribute("href")
                if href:
                    paper_status = _goto(page, urljoin(base_url + "/", href))
                    report["pages"]["paper_lab"] = _page_facts(
                        page, status=paper_status
                    )
                    paper_shot = output / "paper-lab-desktop.png"
                    page.screenshot(path=str(paper_shot), full_page=True)

            mobile = browser.new_context(viewport={"width": 390, "height": 844})
            mobile_page = mobile.new_page()
            _login(mobile_page, base_url, args.access_password)
            mobile_shot = output / "home-mobile.png"
            mobile_page.screenshot(path=str(mobile_shot), full_page=True)
            report["pages"]["home_mobile"] = _page_facts(
                mobile_page, status=200
            )
            mobile.close()
            desktop.close()
            browser.close()

        screenshots = sorted(output.glob("*.png"))
        report["screenshots"] = [
            {
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in screenshots
        ]
        report["console_errors"] = console_errors
        if console_errors:
            raise RuntimeError("browser console emitted errors")
        report["status"] = "PASS"
        return_code = 0
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        report["console_errors"] = console_errors
        return_code = 1
    (output / "baseline.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if return_code:
        raise RuntimeError(str(report.get("error")))
    print(json.dumps({"status": "PASS", "pages": sorted(report["pages"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

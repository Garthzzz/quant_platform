"""用真实 Chromium 验证 Archive B 的阅读、MathML 与评论浏览器链路。"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from playwright.sync_api import Page, sync_playwright


DEFAULT_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
DEFAULT_RESEARCH_SLUG = "q2-low-snr-neural-selection-factory"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def response_status(page: Page, url: str) -> int:
    response = page.goto(url, wait_until="networkidle")
    require(response is not None, f"没有收到导航响应：{url}")
    return response.status


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:5055")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, default=DEFAULT_CHROME)
    parser.add_argument("--research-slug", default=DEFAULT_RESEARCH_SLUG)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = args.base_url.rstrip("/")
    marker = f"QRH_BROWSER_E2E_{uuid4().hex}"
    created_text = f"{marker} <img src=x onerror=globalThis.__qrhXss=true>"
    edited_text = f"{marker} 已通过浏览器编辑"
    result: dict[str, Any] = {
        "schema_version": "qrh-archive-b-browser-e2e/v3-csrf-session-bound",
        "started_at": datetime.now(UTC).isoformat(),
        "base_url": base_url,
        "research_slug": args.research_slug,
        "status": "FAIL",
    }
    console_errors: list[str] = []
    page_errors: list[str] = []
    comment_requests: list[dict[str, str]] = []

    try:
        require(args.chrome.is_file(), f"Chrome 不存在：{args.chrome}")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=str(args.chrome),
                headless=True,
                args=("--disable-background-networking",),
            )
            context = browser.new_context(viewport={"width": 1440, "height": 1100})
            page = context.new_page()
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: page_errors.append(str(error)))

            def record_request(request: Any) -> None:
                parsed = urlparse(request.url)
                if "/api/v1/" in parsed.path and "comment" in parsed.path:
                    comment_requests.append(
                        {"method": request.method, "path": parsed.path}
                    )

            page.on("request", record_request)

            home_status = response_status(page, f"{base_url}/")
            require(home_status == 200, f"首页状态异常：{home_status}")
            dashboard_columns = page.locator(".dashboard-grid > .status-column").count()
            require(dashboard_columns == 4, "Dashboard 必须显示四个状态列")
            page.screenshot(path=str(output_dir / "home.png"), full_page=False)

            with page.expect_navigation(wait_until="networkidle"):
                page.locator("#global-search").fill("低信噪比")
                page.locator(".search-form button[type=submit]").click()
            search_results = page.locator(".search-results > li").count()
            require(search_results > 0, "真实正文搜索没有结果")

            research_payload = page.evaluate(
                """async () => {
                    const response = await fetch('/api/v1/research');
                    return {status: response.status, body: await response.json()};
                }"""
            )
            require(research_payload["status"] == 200, "研究 API 不可用")
            matches = [
                item
                for item in research_payload["body"]["data"]["research"]
                if item["canonical_slug"] == args.research_slug
            ]
            require(len(matches) == 1, "无法唯一定位长篇 Q2 研究")
            research_id = matches[0]["research_id"]
            research_url = f"{base_url}/research/{research_id}"
            research_status = response_status(page, research_url)
            require(research_status == 200, f"研究页状态异常：{research_status}")

            headings = page.locator(".research-body h1, .research-body h2, .research-body h3, .research-body h4, .research-body h5, .research-body h6").count()
            tables = page.locator(".research-body .table-scroll").count()
            math_containers = page.locator(".research-body [data-math-rendered]").count()
            mathml_nodes = page.locator(".research-body math").count()
            math_fallbacks = page.locator(
                '.research-body [data-math-rendered="fallback"]'
            ).count()
            annotation_xml = page.locator(".research-body annotation-xml").count()
            source_links = page.locator(".document-header a[href*='/source']").count()
            overflowing_tables = page.locator(".research-body .table-scroll").evaluate_all(
                "nodes => nodes.filter(node => node.scrollWidth > node.clientWidth).length"
            )
            require(headings >= 100, "长篇研究标题结构不足")
            require(tables > 0 and overflowing_tables > 0, "长表没有形成局部横向滚动")
            require(math_containers > 0, "没有数学容器")
            require(mathml_nodes == math_containers, "并非全部数学容器都生成了 MathML")
            require(math_fallbacks == 0, "存在无法渲染的数学 fallback")
            require(annotation_xml == 0, "MathML 不得包含 annotation-xml")
            require(source_links > 0, "缺少原始 Markdown 直达链接")
            page.screenshot(path=str(output_dir / "research.png"), full_page=False)
            first_table = page.locator(".research-body .table-scroll").first
            first_table.scroll_into_view_if_needed()
            page.screenshot(path=str(output_dir / "research_table.png"), full_page=False)

            baseline_comments = page.locator(".comment-card").count()
            no_session_request = playwright.request.new_context(base_url=base_url)
            try:
                no_session_response = no_session_request.post(
                    f"/api/v1/research/{research_id}/comments",
                    headers={
                        "Origin": base_url,
                        "Idempotency-Key": f"browser-e2e-no-session-{marker}",
                    },
                    data={
                        "actor": {"actor_kind": "zhang_zhengze"},
                        "content": f"{marker} no-session request",
                    },
                )
                no_session = {
                    "status": no_session_response.status,
                    "body": no_session_response.json(),
                }
            finally:
                no_session_request.dispose()
            require(no_session["status"] == 403, "无 session 的写请求没有被 CSRF 拒绝")
            require(
                no_session["body"]["error"]["code"] == "csrf_rejected",
                "无 session 的写请求没有返回 csrf_rejected",
            )
            require(
                page.locator(".comment-card").count() == baseline_comments,
                "被 CSRF 拒绝的请求仍创建了评论",
            )
            create_start = len(comment_requests)
            create_form = page.locator("[data-comment-create]")
            create_form.locator('textarea[name="content"]').fill(created_text)
            with page.expect_navigation(wait_until="networkidle"):
                create_form.evaluate(
                    """form => {
                        form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
                        form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
                    }"""
                )
            create_writes = [
                item
                for item in comment_requests[create_start:]
                if item["method"] == "POST"
                and item["path"].endswith(f"/research/{research_id}/comments")
            ]
            require(len(create_writes) == 1, "双提交保护失败：创建请求不止一个")
            created_card = page.locator(".comment-card").filter(has_text=marker)
            require(created_card.count() == 1, "创建后的评论没有持久化或出现重复")
            require(created_card.get_attribute("data-revision") == "1", "新评论 revision 非 1")
            require(created_card.locator("img").count() == 0, "评论纯文本边界被 HTML 绕过")
            require(
                page.evaluate("() => globalThis.__qrhXss !== true"),
                "评论内容执行了脚本",
            )
            comment_id = created_card.get_attribute("data-comment-id")
            require(comment_id is not None, "评论缺少稳定 ID")
            created_card.screenshot(path=str(output_dir / "comment_created.png"))

            created_card.locator("summary").click()
            edit_form = created_card.locator("[data-comment-edit]")
            edit_form.locator('textarea[name="content"]').fill(edited_text)
            with page.expect_navigation(wait_until="networkidle"):
                edit_form.evaluate(
                    "form => form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}))"
                )
            edited_card = page.locator(".comment-card").filter(has_text=edited_text)
            require(edited_card.count() == 1, "编辑后的评论没有持久化")
            require(edited_card.get_attribute("data-revision") == "2", "编辑没有推进 revision")

            csrf = page.locator('meta[name="csrf-token"]').get_attribute("content")
            require(csrf is not None, "页面缺少 CSRF token")
            stale_response = context.request.patch(
                f"{base_url}/api/v1/comments/{comment_id}",
                headers={
                    "Origin": base_url,
                    "X-CSRF-Token": csrf,
                    "Idempotency-Key": f"browser-e2e-stale-{marker}",
                    "If-Match": f'"comment:{comment_id}:r1"',
                },
                data={
                    "actor": {
                        "actor_kind": "zhang_zhengze",
                        "display_name": None,
                    },
                    "content": f"{marker} stale update",
                },
            )
            stale = {
                "status": stale_response.status,
                "body": stale_response.json(),
            }
            require(stale["status"] == 409, "陈旧 ETag 没有返回 409")
            require(
                stale["body"]["error"]["code"] == "revision_conflict",
                "陈旧 ETag 没有返回 revision_conflict",
            )
            require(
                page.locator(".comment-card").filter(has_text=edited_text).count() == 1,
                "冲突请求改变了当前评论",
            )
            page.locator(".comment-card").filter(has_text=edited_text).screenshot(
                path=str(output_dir / "comment_edited.png")
            )

            edited_card = page.locator(".comment-card").filter(has_text=edited_text)
            edited_card.locator("summary").click()
            page.once("dialog", lambda dialog: dialog.accept())
            with page.expect_navigation(wait_until="networkidle"):
                edited_card.locator("[data-comment-delete]").click()
            require(
                page.locator(".comment-card").filter(has_text=marker).count() == 0,
                "删除后评论仍在页面中",
            )
            require(
                page.locator(".comment-card").count() == baseline_comments,
                "E2E 清理后评论基线数量不一致",
            )

            page.keyboard.press("Home")
            page.keyboard.press("Tab")
            focused = page.evaluate(
                "() => ({tag: document.activeElement?.tagName, id: document.activeElement?.id || null})"
            )
            require(focused["tag"] in {"A", "BUTTON", "INPUT", "SUMMARY"}, "键盘焦点不可见控件异常")
            require(not console_errors, f"浏览器 console error：{console_errors}")
            require(not page_errors, f"浏览器 page error：{page_errors}")

            result.update(
                {
                    "status": "PASS",
                    "home_status": home_status,
                    "research_status": research_status,
                    "dashboard_columns": dashboard_columns,
                    "search_results": search_results,
                    "research_id": research_id,
                    "long_form": {
                        "headings": headings,
                        "tables": tables,
                        "overflowing_tables": overflowing_tables,
                        "math_containers": math_containers,
                        "mathml_nodes": mathml_nodes,
                        "math_fallbacks": math_fallbacks,
                        "annotation_xml": annotation_xml,
                        "source_links": source_links,
                    },
                    "comments": {
                        "baseline": baseline_comments,
                        "double_submit_post_requests": len(create_writes),
                        "created_revision": 1,
                        "edited_revision": 2,
                        "stale_status": stale["status"],
                        "stale_error": stale["body"]["error"]["code"],
                        "no_session_status": no_session["status"],
                        "no_session_error": no_session["body"]["error"]["code"],
                        "deleted_and_cleaned": True,
                    },
                    "keyboard_focus": focused,
                    "console_errors": console_errors,
                    "page_errors": page_errors,
                }
            )
            context.close()
            browser.close()
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        result["finished_at"] = datetime.now(UTC).isoformat()
        (output_dir / "validation.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

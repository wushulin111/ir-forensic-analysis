#!/usr/bin/env python3
"""
卡巴斯基 OpenTIP API Token 自动续期工具

OpenTIP 的 API Token 最长有效期一年，到期后需要登录账号重新生成。
本脚本保存卡巴斯基账号，Token 临近过期时自动登录并续期，保证后续查询持续可用。

依赖：
    pip install playwright
    python -m playwright install chromium   # 或使用本机 Chrome
"""

import argparse
import json
import os
import sys
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "config" / "threat_intel.json"

KASPERSKY_NAME = "Kaspersky OpenTIP"
DEFAULT_CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def load_config(config_path: Optional[Path] = None) -> dict:
    path = Path(config_path) if config_path else CONFIG_PATH
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(config: dict, config_path: Optional[Path] = None) -> None:
    path = Path(config_path) if config_path else CONFIG_PATH
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write("\n")


def get_kaspersky_source(config: dict) -> Optional[dict]:
    for source in config.get("sources", []):
        if source.get("name") == KASPERSKY_NAME:
            return source
    return None


def is_token_valid(source: dict, refresh_days: int = 30) -> bool:
    """Token 存在且剩余有效期大于 refresh_days 视为有效。"""
    api_key = source.get("api_key") or os.environ.get("TI_KASPERSKY_OPENTIP_API_KEY", "")
    if not api_key:
        return False
    expires = source.get("token_expires_at", "")
    if not expires:
        return True
    try:
        expire_date = datetime.strptime(str(expires)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (expire_date - now).days > refresh_days
    except Exception:
        return True


def _find_local_chrome() -> Optional[str]:
    for path in DEFAULT_CHROME_PATHS:
        if os.path.exists(path):
            return path
    return None


def _login_and_get_token(source: dict, headless: bool = True) -> tuple:
    from playwright.sync_api import sync_playwright

    email = source.get("account_email", "") or os.environ.get("TI_KASPERSKY_ACCOUNT_EMAIL", "")
    password = source.get("account_password", "") or os.environ.get("TI_KASPERSKY_ACCOUNT_PASSWORD", "")
    if not email or not password:
        raise RuntimeError("未配置卡巴斯基账号（account_email / account_password），无法自动续期")

    chrome_path = _find_local_chrome()
    launch_args = {"headless": headless}
    if chrome_path:
        launch_args["executable_path"] = chrome_path
    launch_args["args"] = ["--no-sandbox"]

    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_args)
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()

        try:
            page.goto("https://opentip.kaspersky.com/token", timeout=30000, wait_until="domcontentloaded")
            page.wait_for_timeout(1200)

            try:
                page.locator("text=Accept").last.click(timeout=2000)
            except Exception:
                pass

            body_text = page.inner_text("body")
            if email not in body_text and "Sign in" in body_text:
                page.locator("text=Sign in").first.click(timeout=5000)
                page.wait_for_timeout(500)
                menu = page.locator("ul[role=menu]")
                checkboxes = menu.locator("input[type=checkbox]")
                for i in range(checkboxes.count()):
                    checkboxes.nth(i).check(force=True)
                page.wait_for_timeout(200)
                menu.locator("button:has-text('Sign in with Kaspersky Account')").first.click(timeout=5000)
                page.wait_for_url("**auth.uis.kaspersky.com**", timeout=20000)
                page.wait_for_timeout(1000)
                page.locator("input[name=Login]").fill(email)
                page.locator("input[name=Password]").fill(password)
                page.locator("button:has-text('Sign in')").first.click(timeout=5000)
                page.wait_for_url("https://opentip.kaspersky.com/**", timeout=30000)
                page.wait_for_timeout(2000)

            page.goto("https://opentip.kaspersky.com/token", timeout=30000, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)

            with page.expect_response(
                lambda r: r.url.rstrip("/").endswith("/ui/apitoken") and r.status == 200,
                timeout=30000,
            ) as resp_info:
                page.locator("button:has-text('Request token')").first.click(timeout=10000)

            data = resp_info.value.json()
            token = data.get("Token", "")
            valid_to = data.get("ValidTo", 0)
            if not token:
                raise RuntimeError("卡巴斯基返回了空 Token")
            expires_at = datetime.fromtimestamp(valid_to / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
            return token, expires_at
        finally:
            browser.close()


def refresh_token(config_path: Optional[Path] = None, headless: bool = True) -> tuple:
    config = load_config(config_path)
    source = get_kaspersky_source(config)
    if not source:
        raise RuntimeError("配置中未找到 Kaspersky OpenTIP")
    token, expires_at = _login_and_get_token(source, headless=headless)
    source["enabled"] = True
    source["api_key"] = token
    source["token_expires_at"] = expires_at
    save_config(config, config_path)
    return token, expires_at


def get_valid_token(config_path: Optional[Path] = None, refresh_days: int = 30) -> str:
    """返回可用 Token；临近过期或缺失时自动续期。"""
    config = load_config(config_path)
    source = get_kaspersky_source(config)
    if not source:
        raise RuntimeError("配置中未找到 Kaspersky OpenTIP")
    if is_token_valid(source, refresh_days=refresh_days):
        return source.get("api_key") or os.environ.get("TI_KASPERSKY_OPENTIP_API_KEY", "")
    try:
        token, _ = refresh_token(config_path)
        return token
    except Exception as e:
        # 续期失败时退回旧 Token，避免查询直接中断
        old = source.get("api_key") or os.environ.get("TI_KASPERSKY_OPENTIP_API_KEY", "")
        if old:
            return old
        raise RuntimeError(f"卡巴斯基 Token 自动续期失败: {e}")


def main():
    parser = argparse.ArgumentParser(description="卡巴斯基 OpenTIP API Token 自动续期工具")
    parser.add_argument("--refresh", action="store_true", help="强制重新生成 Token")
    parser.add_argument("--show", action="store_true", help="显示当前 Token 有效期（不打印完整 Token）")
    parser.add_argument("--headful", action="store_true", help="使用可见浏览器登录（遇到验证码时使用）")
    args = parser.parse_args()

    if args.refresh:
        token, expires = refresh_token(headless=not args.headful)
        print(f"续期成功，Token 有效期至 {expires}")
        return

    config = load_config()
    source = get_kaspersky_source(config)
    if not source:
        print("未找到 Kaspersky OpenTIP 配置")
        sys.exit(1)
    if args.show:
        print("Token 有效期至:", source.get("token_expires_at", "未知"))
        print("已配置账号:", source.get("account_email", ""))
        return

    token = get_valid_token()
    print(token)


if __name__ == "__main__":
    main()

"""HTTP login for OAKS portals: verify captcha, authenticate, open the CAS broker.

The protocol is detected from the page, and all hosts come from the resolved
login entry. Credentials, captcha solutions and exchange tokens are never logged.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from troTHU import ocr_captcha, tron_http


def csrf_token(html: str) -> str:
    for tag in re.findall(r"<meta\b[^>]*>", html or "", re.I):
        attrs = tron_http.parse_tag_attributes(tag)
        if attrs.get("name", "").lower() == "csrf-token":
            return attrs.get("content", "")
    return ""


def is_oaks_login(html: str, detected: dict) -> bool:
    fields = detected.get("fields") or {}
    return (
        {"loginCheck", "verify_code"}.issubset(fields)
        and "/login_action.php" in html
        and "/login_page.php" in html
        and "verifyCode" in html
    )


def find_broker_link(html: str, login_url: str) -> str:
    """Read the portal's openModule link for this entry's Keycloak realm only."""
    entry = urlparse(login_url)
    realm = re.match(r"(.*/realms/[^/]+)/", entry.path)
    if not realm:
        return ""
    prefix = realm.group(1) + "/broker/"
    for tag in re.findall(r"<(?:a|button)\b[^>]*>", html or "", re.I):
        attrs = tron_http.parse_tag_attributes(tag)
        for value in (attrs.get("href", ""), attrs.get("onclick", "")):
            targets = [value]
            targets.extend(m.group(2) for m in re.finditer(r"openModule\s*\(\s*(['\"])(.*?)\1", value))
            for target in targets:
                parsed = urlparse(target)
                if (
                    parsed.scheme == entry.scheme and parsed.netloc == entry.netloc
                    and parsed.path.startswith(prefix) and parsed.path.endswith("/endpoint")
                ):
                    return target
    return ""


def _redirect_page(html: str) -> bool:
    # An application page contains conditional redirects (e.g. idle logout).
    # Follow location assignments only on bootstrap pages with no visible UI.
    visible = re.sub(r"<(script|style|head)\b[^>]*>.*?</\1>", "", html, flags=re.I | re.S)
    visible = re.sub(r"<!--.*?-->|<[^>]+>", "", visible, flags=re.S).strip()
    return not visible


async def _finish_exchange(client, next_url: str, referer: str) -> tron_http.LoginOutcome:
    from troTHU.login_flow import _follow_js_autosubmit, _has_session, detect_sso_form

    for _ in range(12):
        async with client.session.get(
            next_url, headers={**tron_http.NAVIGATION_HEADERS, "Referer": referer},
            **client.request_kwargs(),
        ) as resp:
            if resp.status != 200:
                raise tron_http.UnexpectedResponseError("SSO 轉址 HTTP {}。".format(resp.status))
            html, current_url = await resp.text(errors="replace"), str(resp.url)
        html, current_url = await _follow_js_autosubmit(client, html, current_url)
        # The OAKS dashboard opens a broker endpoint in a new window. Read the
        # literal link; executing dashboard JS would also trigger unrelated actions.
        broker = find_broker_link(html, client.endpoints.login_url)
        redirect = tron_http.extract_html_redirect(html, current_url) if _redirect_page(html) else None
        if broker or redirect:
            referer, next_url = current_url, broker or redirect
            continue
        if detect_sso_form(html):
            raise tron_http.LoginPageChangedError("SSO 回到登入頁，未完成 TronClass 登入交換。")
        if urlparse(current_url).netloc != urlparse(client.endpoints.base_url).netloc:
            raise tron_http.LoginPageChangedError("SSO 校務入口未提供 TronClass 回程連結。")
        return tron_http.LoginOutcome(final_url=current_url, has_session=_has_session(client))
    raise tron_http.LoginPageChangedError("SSO 登入交換超過轉址次數上限。")


async def submit_oaks_login(client, resolved, user: str, passwd: str) -> tron_http.LoginOutcome:
    from troTHU.login_flow import _fetch_sso_captcha_bytes, find_captcha_source

    if not ocr_captcha.ddddocr_available():
        raise tron_http.LoginPageChangedError("勤益 SSO 數字驗證碼需要本機 OCR；請安裝 pip install -e .[ocr] 後重試。")
    token = csrf_token(resolved.html)
    image_url = find_captcha_source(resolved.html, resolved.url)
    if not token or not image_url:
        raise tron_http.LoginPageChangedError("SSO 缺少 CSRF token 或驗證碼圖片。")
    parsed = urlparse(resolved.url)
    headers = {
        "Referer": resolved.url,
        "Origin": "{}://{}".format(parsed.scheme, parsed.netloc),
        "X-Requested-With": "XMLHttpRequest",
    }
    for _ in range(tron_http.SSO_CAPTCHA_MAX_ATTEMPTS):
        image = await _fetch_sso_captcha_bytes(client, image_url)
        try:
            code = ocr_captcha.solve_captcha(image, charset=tron_http.IMAGE_CAPTCHA_CHARSET)
        except ocr_captcha.OcrUnavailableError as exc:
            raise tron_http.LoginPageChangedError(str(exc)) from exc
        if len(code) != resolved.captcha_maxlen or not code.isascii() or not code.isdigit():
            continue
        async with client.session.post(
            urljoin(resolved.url, "/login_page.php"),
            data={"action": "verifyCode", "from": "login", "code": code},
            headers=headers, **client.request_kwargs(),
        ) as resp:
            if resp.status != 200:
                raise tron_http.UnexpectedResponseError("SSO 驗證碼查驗 HTTP {}。".format(resp.status))
            verdict = (await resp.text()).strip()
        if verdict in {"error", "expire", "empty"}:
            continue
        if verdict != "valid":
            raise tron_http.LoginPageChangedError("SSO 驗證碼查驗回應格式已變更。")

        data = dict(resolved.form.fields)
        data.update({
            resolved.form.username_field: user, resolved.form.password_field: passwd,
            resolved.captcha_field: code, "loginCheck": "1", "fromAjax": "1",
        })
        async with client.session.post(
            urljoin(resolved.url, "/login_action.php"), data=data,
            headers={**headers, "X-CSRF-TOKEN": token, "Accept": "application/json"},
            **client.request_kwargs(),
        ) as resp:
            if resp.status != 200:
                raise tron_http.UnexpectedResponseError("SSO 帳密查驗 HTTP {}。".format(resp.status))
            try:
                result = await resp.json(content_type=None)
            except ValueError as exc:
                raise tron_http.LoginPageChangedError("SSO 帳密查驗未回傳 JSON。") from exc
        if not isinstance(result, dict) or "error" not in result:
            raise tron_http.LoginPageChangedError("SSO 帳密查驗回應格式已變更。")
        error = str(result["error"])
        token = str(result.get("new_token") or token)
        if error == "4":  # Only captcha failures may resubmit credentials.
            continue
        if error == "999999":  # The portal requires a fresh CSRF session.
            raise tron_http.LoginPageChangedError("SSO 登入狀態已過期，請重新登入。")
        if error != "0":
            raise tron_http.LoginRejectedError("勤益 SSO 登入失敗，請確認校務帳號與密碼。")
        redirect = result.get("url")
        if not isinstance(redirect, str) or not redirect.strip():
            raise tron_http.LoginPageChangedError("SSO 登入成功但缺少回程網址。")
        target = urljoin(resolved.url, redirect)
        if urlparse(target).scheme not in {"http", "https"}:
            raise tron_http.LoginPageChangedError("SSO 回程網址格式已變更。")
        return await _finish_exchange(client, target, resolved.url)
    raise tron_http.LoginRejectedError("SSO 數字驗證碼連續辨識失敗，請稍後重試。")

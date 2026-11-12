"""NCUT defaults and the OAKS -> Keycloak -> TronClass HTTP login contract."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import aiohttp
from aiohttp import web

from troTHU import group_runtime, login_flow, login_probe, oaks_sso, pending_qr, providers, tron, tron_http


# Public page structure, with synthetic tokens and no account data.
LOGIN_PAGE = """<html><head><meta name="csrf-token" content="csrf-first"></head>
<body><img src="/download_file.php?logo=1">
<form id="loginForm" method="post" onsubmit="return false;">
<input type="hidden" name="loginCheck" value="0">
<input type="hidden" name="extra" value="preserved">
<input type="text" name="login_name">
<input type="password" name="password">
<input type="text" name="verify_code">
</form><img src="/login_page.php?action=getCode&amp;from=login&amp;refresh=1">
<script>$.ajax({url:'/login_page.php', data:{action:'verifyCode'}});
$.ajax({url:'/login_action.php'});</script></body></html>"""


class NcutDefaultsTest(unittest.TestCase):
    def test_default_registry_and_http_endpoints_use_campus_sso(self):
        provider = providers.get_provider()
        self.assertEqual(provider.key, "ncut")
        self.assertEqual(providers.get_provider("勤益").key, "ncut")
        for endpoints in (tron_http.default_endpoints(), tron_http.endpoints_from_provider(provider)):
            self.assertEqual(endpoints.base_url, "https://tronclass.ncut.edu.tw")
            self.assertIn("kc_idp_hint=ncut-sso", endpoints.login_url)
            self.assertEqual(endpoints.session_cookie_domain, "tronclass.ncut.edu.tw")
            self.assertTrue(endpoints.courses_url.startswith(endpoints.base_url + "/api/"))

    def test_omitted_school_survives_config_roundtrip_as_ncut(self):
        parsed = tron.parse_basic_config_text("now =\n[save account]\nuser = student\npasswd = password\n")
        merged = tron.normalize_config(tron.merge_basic_and_advanced_config(parsed, {}))
        self.assertEqual(merged["provider"]["current"], "ncut")
        self.assertEqual(merged["teacher"]["school"], "ncut")
        basic, advanced = tron.split_normalized_config(merged)
        reparsed = tron.parse_basic_config_text(tron.render_basic_config(basic))
        restored = tron.normalize_config(tron.merge_basic_and_advanced_config(reparsed, advanced))
        self.assertEqual(restored["provider"]["current"], "ncut")
        self.assertIn("school = NCUT", tron.DEFAULT_BASIC_CONFIG_TEMPLATE)
        self.assertIn("school = NCUT", tron.render_basic_config({}))

    def test_explicit_existing_school_is_preserved(self):
        for code in ("THU", "TKU", "FJU", "TRONCLASS"):
            parsed = tron.parse_basic_config_text(
                "now = student\n[save account]\nuser = student\npasswd = password\nschool = " + code
            )
            merged = tron.normalize_config(tron.merge_basic_and_advanced_config(parsed, {}))
            self.assertEqual(merged["provider"]["current"], code.lower())

    def test_group_without_school_resolves_ncut_endpoints(self):
        parsed = tron.parse_basic_config_text(
            "now = class A\n[save account]\nuser = student\npasswd = password\n"
            "[group]\nclass = A\nmembers = student\n"
        )
        config = tron.normalize_config(tron.merge_basic_and_advanced_config(parsed, {}))
        plan = group_runtime.build_group_plan(config)
        self.assertEqual(plan.provider_key, "ncut")
        self.assertEqual(plan.endpoints.base_url, "https://tronclass.ncut.edu.tw")
        self.assertIn("kc_idp_hint=ncut-sso", plan.endpoints.login_url)

    def test_new_pending_records_default_to_ncut_and_stay_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            pending_qr.add_pending_qr(base, profile="student", rollcall_id=1)
            self.assertEqual(len(pending_qr.match_pending_qr(base, 1, provider="ncut")), 1)
            self.assertEqual(pending_qr.match_pending_qr(base, 1, provider="thu"), [])

    def test_oaks_detection_keeps_missing_csrf_in_protocol_for_safe_failure(self):
        page = LOGIN_PAGE.replace('<meta name="csrf-token" content="csrf-first">', "")
        self.assertTrue(oaks_sso.is_oaks_login(page, login_flow.detect_sso_form(page)))
        self.assertEqual(oaks_sso.csrf_token(page), "")

    def test_portal_only_selects_the_active_broker_origin_and_realm(self):
        entry = "https://id.example/auth/realms/campus/protocol/cas/login"
        wrong = (
            '<a href="javascript:openModule(\'https://other.example/auth/realms/campus/broker/idp/endpoint\')">X</a>'
            '<a href="https://id.example/auth/realms/other/broker/idp/endpoint">Y</a>'
        )
        self.assertEqual(oaks_sso.find_broker_link(wrong, entry), "")
        target = "https://id.example/auth/realms/campus/broker/idp/endpoint"
        self.assertEqual(oaks_sso.find_broker_link(wrong + '<button onclick="openModule(\'' + target + '\')">Z</button>', entry), target)


class FakeOaksServer:
    def __init__(self):
        self.base_url = ""
        self.images = 0
        self.checks = 0
        self.submissions = []
        self.captcha_verdicts = []
        self.login_results = []
        self.token = "csrf-first"
        self.logged_out = False
        self.complete_exchange = True
        self.entry_form_available = True
        self.fallback_requested = False

    def endpoints(self):
        return tron_http.TronHttpEndpoints(
            base_url=self.base_url,
            login_url=self.base_url + "/auth/realms/campus/protocol/cas/login?kc_idp_hint=campus",
            session_cookie_domain="127.0.0.1",
            current_semester_url=self.base_url + "/api/current-semester-info",
        )

    async def entry(self, request):
        if not self.entry_form_available:
            return web.Response(text="<p>Campus SSO temporarily unavailable</p>", content_type="text/html")
        response = web.HTTPFound("/sso/login.php")
        response.set_cookie("broker_state", "started")
        raise response

    async def login_page(self, request):
        return web.Response(text=LOGIN_PAGE, content_type="text/html")

    async def fallback_login(self, request):
        self.fallback_requested = True
        return web.Response(text=LOGIN_PAGE, content_type="text/html")

    async def captcha(self, request):
        if request.method == "GET":
            self.images += 1
            return web.Response(body=b"synthetic-captcha", content_type="image/png")
        self.checks += 1
        data = await request.post()
        assert data["action"] == "verifyCode" and data["from"] == "login"
        assert "password" not in data
        verdict = self.captcha_verdicts.pop(0) if self.captcha_verdicts else "valid"
        return web.Response(text=verdict)

    async def credentials(self, request):
        data = dict(await request.post())
        assert request.headers["X-CSRF-TOKEN"] == self.token
        assert request.headers["X-Requested-With"] == "XMLHttpRequest"
        assert request.headers["Origin"] == self.base_url
        assert data["loginCheck"] == data["fromAjax"] == "1"
        assert data["extra"] == "preserved"
        self.submissions.append(data)
        if self.login_results:
            result = self.login_results.pop(0)
            if not isinstance(result, dict):
                return web.Response(text=result)
            self.token = result.get("new_token") or self.token
            return web.json_response(result)
        if data["login_name"] != "student" or data["password"] != "password":
            return web.json_response({"error": 3, "err_msg": "bad credentials"})
        response = web.json_response({"error": 0, "url": "/login_check.php"})
        response.set_cookie("sso_auth", "authenticated")
        return response

    async def check(self, request):
        return web.Response(text='<script>window.location="/token_auth.php"</script>', content_type="text/html")

    async def token_auth(self, request):
        raise web.HTTPFound("/login_main.php")

    async def main(self, request):
        return web.Response(text='<script>window.location="/portal"</script>', content_type="text/html")

    async def portal(self, request):
        callback = self.base_url + "/auth/realms/campus/broker/campus/endpoint"
        return web.Response(text=(
            '<html><body><a href="javascript:openModule(\'' + callback + '\')">TronClass</a>'
            '<script>function logout(){window.location="/logout"}</script></body></html>'
        ), content_type="text/html")

    async def broker(self, request):
        assert request.cookies.get("broker_state") == "started"
        assert request.cookies.get("sso_auth") == "authenticated"
        return web.Response(text=(
            '<body onload="document.forms[0].submit()"><form action="/cas/complete" method="post">'
            '<input type="hidden" name="ticket" value="synthetic-ticket"></form></body>'
        ), content_type="text/html")

    async def complete(self, request):
        assert (await request.post())["ticket"] == "synthetic-ticket"
        response = web.HTTPFound("/user")
        if self.complete_exchange:
            response.set_cookie("session", "lms-session")
        raise response

    async def user(self, request):
        return web.Response(text='<p>Courses</p><script>function logout(){window.location="/logout"}</script>', content_type="text/html")

    async def logout(self, request):
        self.logged_out = True
        return web.Response(text="Logged out")

    async def semester(self, request):
        if request.cookies.get("session") != "lms-session":
            raise web.HTTPUnauthorized()
        return web.json_response({"semester": {"id": 1}})

    async def __aenter__(self):
        app = web.Application()
        app.router.add_get("/auth/realms/campus/protocol/cas/login", self.entry)
        app.router.add_get("/sso/login.php", self.login_page)
        app.router.add_get("/cas/login", self.fallback_login)
        app.router.add_route("*", "/login_page.php", self.captcha)
        app.router.add_post("/login_action.php", self.credentials)
        app.router.add_get("/login_check.php", self.check)
        app.router.add_get("/token_auth.php", self.token_auth)
        app.router.add_get("/login_main.php", self.main)
        app.router.add_get("/portal", self.portal)
        app.router.add_get("/auth/realms/campus/broker/campus/endpoint", self.broker)
        app.router.add_post("/cas/complete", self.complete)
        app.router.add_get("/user", self.user)
        app.router.add_get("/logout", self.logout)
        app.router.add_get("/api/current-semester-info", self.semester)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.base_url = "http://127.0.0.1:{}".format(site._server.sockets[0].getsockname()[1])
        return self

    async def __aexit__(self, *args):
        await self.runner.cleanup()


class OaksHttpLoginTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = await FakeOaksServer().__aenter__()
        self.session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
        self.client = tron_http.TronHttpClient(self.session, endpoints=self.server.endpoints())
        self.available = patch("troTHU.ocr_captcha.ddddocr_available", return_value=True)
        self.solver = patch("troTHU.ocr_captcha.solve_captcha", return_value="0123")
        self.available.start()
        self.solve = self.solver.start()

    async def asyncTearDown(self):
        self.solver.stop()
        self.available.stop()
        await self.session.close()
        await self.server.__aexit__()

    async def test_full_http_exchange_and_authenticated_api(self):
        outcome = await login_flow.run_login_flow(self.client, "student", "password")
        self.assertTrue(outcome.has_session)
        self.assertEqual(outcome.final_url, self.server.base_url + "/user")
        self.assertEqual(await self.client.fetch_current_semester(), {"semester": {"id": 1}})
        self.assertFalse(self.server.logged_out)
        self.assertEqual(len(self.server.submissions), 1)
        self.solve.assert_called_once_with(b"synthetic-captcha", charset="0123456789")

    async def test_probe_identifies_oaks_and_fetches_the_right_image(self):
        result = await login_probe._classify_login_url(self.client, self.client.endpoints.login_url, [])
        self.assertEqual(result["form_kind"], "oaks_ajax")
        self.assertEqual(result["captcha_fetch"], "ok")
        self.assertEqual(self.server.images, 1)
        self.assertFalse(self.server.submissions)

    async def test_bad_or_expired_captcha_retries_before_sending_credentials(self):
        self.server.captcha_verdicts = ["error", "expire", "empty", "valid"]
        outcome = await login_flow.run_login_flow(self.client, "student", "password")
        self.assertTrue(outcome.has_session)
        self.assertEqual(self.server.images, 4)
        self.assertEqual(len(self.server.submissions), 1)

    async def test_low_confidence_ocr_does_not_submit_credentials(self):
        self.solve.side_effect = ["12", "１２３４", "a123", "0123"]
        outcome = await login_flow.run_login_flow(self.client, "student", "password")
        self.assertTrue(outcome.has_session)
        self.assertEqual(self.server.images, 4)
        self.assertEqual(self.server.checks, 1)

    async def test_wrong_password_is_rejected_once(self):
        with self.assertRaises(tron_http.LoginRejectedError):
            await login_flow.run_login_flow(self.client, "student", "incorrect")
        self.assertEqual(len(self.server.submissions), 1)

    async def test_changed_campus_sso_never_falls_back_to_generic_login(self):
        self.server.entry_form_available = False
        with self.assertRaises(tron_http.LoginPageChangedError):
            await login_flow.resolve_credential_form(self.client)
        result = await login_probe._resolve_and_classify(self.client)
        self.assertEqual(result["form_kind"], "no_form")
        self.assertFalse(self.server.fallback_requested)
        self.assertFalse(self.server.submissions)

    async def test_captcha_error_refreshes_csrf_for_next_attempt(self):
        self.server.login_results = [{"error": 4, "new_token": "csrf-next"}]
        outcome = await login_flow.run_login_flow(self.client, "student", "password")
        self.assertTrue(outcome.has_session)
        self.assertEqual(len(self.server.submissions), 2)

    async def test_invalid_json_or_missing_result_does_not_succeed(self):
        for result in ("<html>error</html>", {}, {"error": 0}, {"error": 0, "url": "javascript:bad()"}):
            with self.subTest(result=result):
                self.server.login_results = [copy.deepcopy(result)]
                with self.assertRaises(tron_http.LoginPageChangedError):
                    await login_flow.run_login_flow(self.client, "student", "password")

    async def test_captcha_budget_exhaustion_never_sends_password(self):
        self.server.captcha_verdicts = ["error"] * tron_http.SSO_CAPTCHA_MAX_ATTEMPTS
        with self.assertRaises(tron_http.LoginRejectedError):
            await login_flow.run_login_flow(self.client, "student", "password")
        self.assertFalse(self.server.submissions)

    async def test_sso_success_without_lms_cookie_does_not_count_as_login(self):
        self.server.complete_exchange = False
        outcome = await login_flow.run_login_flow(self.client, "student", "password")
        self.assertFalse(outcome.has_session)
        with self.assertRaises(tron_http.UnauthorizedError):
            await self.client.fetch_current_semester()

    async def test_missing_ocr_and_missing_csrf_do_not_send_password(self):
        resolved = await login_flow.resolve_credential_form(self.client)
        self.available.stop()
        with patch("troTHU.ocr_captcha.ddddocr_available", return_value=False):
            with self.assertRaises(tron_http.LoginPageChangedError):
                await login_flow.submit_credentials(self.client, resolved, "student", "password")
        self.available.start()
        resolved.html = resolved.html.replace('content="csrf-first"', 'content=""')
        with self.assertRaises(tron_http.LoginPageChangedError):
            await login_flow.submit_credentials(self.client, resolved, "student", "password")
        self.assertFalse(self.server.submissions)

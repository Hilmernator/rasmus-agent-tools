"""DAST scope, evidence projection and real synthetic HTTP behavior, on loopback and over TLS."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "skills/local-dast/scripts/dast.py"
spec = importlib.util.spec_from_file_location("local_dast", SCRIPT)
dast = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dast)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.paths.append(self.path)
        status = 200
        user = self.headers.get("Authorization", "anonymous")
        body = {"id": user, "private": "synthetic-private-canary"}
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/forbidden-followup")
            self.end_headers()
            return
        if self.path == "/object" and self.server.fixed and user != "owner":
            status, body = 403, {"error": "denied"}
        data = json.dumps(body).encode()
        if self.path == "/large":
            data = b"x" * (dast.MAX_BODY + 1)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Set-Cookie", "session=synthetic-cookie-canary")
        self.end_headers()
        try:
            if self.path == "/slow":
                for byte in data:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.03)
                return
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


    def do_POST(self):
        self.server.writes.append((self.command, self.path))
        sent = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        user = (self.headers.get("Cookie") or "").removeprefix("session=") or "anonymous"
        if self.path == "/login":
            known = sent.get("password") == "synthetic-password-canary"
            self.send_response(303 if known else 401)
            if known:
                self.send_header("Set-Cookie", f"session={sent['user']}; HttpOnly; Path=/")
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        denied = self.server.fixed and user != "owner"
        data = json.dumps({"error": "denied"} if denied else {"changed_by": user, "title": sent.get("title", "")}).encode()
        self.send_response(403 if denied else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_PUT = do_PATCH = do_DELETE = do_POST


class Api(BaseHTTPRequestHandler):
    """A token API and an MCP endpoint behind an authorizer. Its flaws are on until server.fixed is set."""
    def log_message(self, *args):
        pass

    def answer(self, status, body, kind="application/json", headers=()):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def user(self):
        return self.server.tokens.get(self.headers.get("Authorization", "").removeprefix("Bearer "))

    def do_GET(self):
        user = self.user()
        if self.path == "/me" and user:
            return self.answer(200, {"status": "success", "data": {"username": user, "admin": user in self.server.admins}})
        self.answer(401 if self.path == "/me" else 404, {"status": "fail"})

    def do_POST(self):
        sent = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self.server.writes.append((self.path, sent.get("method")))
        fixed, user = self.server.fixed, self.user()
        if self.path == "/login":
            if sent.get("password") != "synthetic-password-canary":
                return self.answer(401, {"status": "fail"})
            token = f"synthetic-token-canary-{sent['username']}"
            self.server.tokens[token] = sent["username"]
            return self.answer(200, {"status": "success", "data": {"auth_token": token}})
        if self.path == "/signin":  # the flaw: a failed sign-in tells whether the account exists
            return self.answer(401, {"status": "fail", "message": "No such user" if not fixed and sent.get("username") != "user" else "Wrong name or password"})
        if self.path == "/register":
            if sent.get("admin") and not fixed:  # the flaw: the caller chooses their own role
                self.server.admins.add(sent["username"])
            return self.answer(200, {"status": "success"})
        if self.path == "/mcp-open":  # an event stream the server never closes
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"event: message\ndata: {}\n\n")
            self.wfile.flush()
            time.sleep(0.5)
            return
        if self.path == "/mcp":
            if not user and (fixed or sent.get("method") != "tools/list"):  # the flaw: anyone may list the tools
                challenge = [("WWW-Authenticate", 'Bearer resource_metadata="https://gateway.test/.well-known/oauth-protected-resource"')]
                return self.answer(401, {"error": "unauthorized"}, headers=challenge if fixed else ())
            session = [("Mcp-Session-Id", f"synthetic-session-canary-{user}")]
            if getattr(self.server, "stateful", False) and sent.get("method") != "initialize" and self.headers.get("Mcp-Session-Id") != session[0][1]:
                return self.answer(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Missing session ID"}})
            result = {"jsonrpc": "2.0", "id": sent.get("id"), "result": {"tools": [{"name": "notes___read"}], "isError": False}}
            if sent.get("method") == "initialize":
                return self.answer(200, result, headers=session)
            return self.answer(200, f"event: ping\ndata: {{}}\n\nevent: message\ndata: {json.dumps(result)}\n\n".encode(), "text/event-stream")
        self.answer(404, {})


REMOTE_HOST = "staging.example.test"  # .test is reserved and never resolves; the tests send it to a local server
REMOTE = f"https://{REMOTE_HOST}"


class DastTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"DAST_PEER_AUTH": "peer", "DAST_OWNER_AUTH": "owner"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def plan(self, target="http://127.0.0.1:48173"):
        return {"target": target, "cases": [{"id": "health", "path": "/", "expect_status": [200]}]}

    def server(self, handler=Handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.fixed, server.paths, server.writes = False, [], []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        return server, f"http://127.0.0.1:{server.server_port}"

    def tls_server(self):
        """The same server behind a throw-away certificate. Requests for REMOTE_HOST:443 are sent to it; nothing leaves this machine."""
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("No openssl binary to make a throw-away certificate")
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(folder))
        cert, key = folder / "cert.pem", folder / "key.pem"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-keyout", str(key), "-out", str(cert),
                        "-subj", f"/CN={REMOTE_HOST}", "-addext", f"subjectAltName=DNS:{REMOTE_HOST}"], check=True, capture_output=True)
        server, _ = self.server()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        connect = socket.create_connection

        def local_only(address, *args, **kwargs):
            self.assertEqual(address, (REMOTE_HOST, 443))
            return connect(("127.0.0.1", server.server_port), *args, **kwargs)

        redirect = patch.object(socket, "create_connection", local_only)
        redirect.start()
        self.addCleanup(redirect.stop)
        return server, str(cert)

    def test_a_remote_target_is_one_https_hostname_named_on_the_command_line(self):
        self.assertEqual(dast.validate_plan(self.plan(REMOTE), remote=REMOTE), (REMOTE_HOST, 443))
        with self.assertRaises(ValueError):
            dast.validate_plan(self.plan(REMOTE))
        with self.assertRaises(ValueError):
            dast.validate_plan(self.plan(REMOTE), remote="https://other.example.test")
        with self.assertRaises(ValueError):
            dast.validate_plan(self.plan(), remote=REMOTE)
        for origin in ["http://staging.example.test", "https://10.0.0.7", "https://127.0.0.1", "https://localhost", "https://staging.example.test:8443",
                       "https://staging.example.test/", "https://user@staging.example.test", "https://Staging.example.test", "https://staging.example.test.",
                       "https://-staging.example.test", "https://staging.example.123", "https://[::1]", "https://staging.example.test\n", ""]:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                dast.validate_plan(self.plan(origin), remote=origin)
        path = Path(tempfile.mkdtemp()) / "plan.json"
        self.addCleanup(lambda: shutil.rmtree(path.parent))
        path.write_text(json.dumps(self.plan(REMOTE)))
        result = subprocess.run([sys.executable, str(SCRIPT), str(path), "--http-only"], capture_output=True, text=True)
        self.assertEqual((result.returncode, json.loads(result.stdout)["status"]), (2, "incomplete"))
        self.assertNotIn(REMOTE_HOST, result.stdout + result.stderr)

    def test_a_remote_run_verifies_the_certificate_and_says_what_it_is(self):
        server, cert = self.tls_server()
        with patch.object(dast, "INTERVAL", 0):
            rows, har = dast.capture(self.plan(REMOTE), remote=REMOTE)
            self.assertEqual([(row["state"], row["gap"]) for row in rows], [("incomplete", "tls-certificate-not-verified")])
            self.assertEqual((har["log"]["entries"], server.paths), ([], []))
            with patch.dict(os.environ, {"SSL_CERT_FILE": cert}):
                directory, report = dast.run(self.plan(REMOTE), remote=REMOTE)
        self.addCleanup(lambda: shutil.rmtree(directory))
        self.assertEqual(([row["state"] for row in report["cases"]], server.paths), (["pass"], ["/"]))
        self.assertEqual(report["target"], "remote")
        gaps = " ".join(report["coverage_gaps"])
        self.assertIn("deployed environment", gaps)
        self.assertIn("TLS certificate was verified", gaps)
        self.assertNotIn("Loopback", gaps)
        self.assertIn("Target: remote", (directory / "review.md").read_text())
        self.assertNotIn(REMOTE_HOST, (directory / "report.json").read_text() + (directory / "review.md").read_text())
        self.assertIn(REMOTE + "/", (directory / "private/traffic.har").read_text())

    def test_scope_and_entire_plan_validate_before_network(self):
        for target in ["http://localhost:8000", "http://127.0.0.2:8000", "https://127.0.0.1:8000", "http://127.0.0.1:8000/", "http://127.0.0.1:8000@evil.invalid", "http://127.0.0.1:22"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                dast.validate_plan(self.plan(target))
        for path in ["//evil.invalid/", "http://evil.invalid", "/\r\nHost: other", "/#secret", "/\\other"]:
            plan = self.plan()
            plan["cases"].append({"id": "bad", "path": path, "expect_status": [200]})
            with patch.object(dast, "request") as request, self.assertRaises(ValueError):
                dast.capture(plan)
            request.assert_not_called()

    def test_no_header_injection_or_missing_credentials(self):
        for headers in [{"Host": "DAST_PEER_AUTH"}, {"Authorization": "DAST_ABSENT"}, {"Authorization": "HOME"}]:
            plan = self.plan()
            plan["cases"][0]["headers_env"] = headers
            with self.assertRaises(ValueError):
                dast.validate_plan(plan)
        with patch.dict(os.environ, {"DAST_PEER_AUTH": "value\r\nHost: evil"}), self.assertRaises(ValueError):
            plan = self.plan()
            plan["cases"][0]["headers_env"] = {"Authorization": "DAST_PEER_AUTH"}
            dast.validate_plan(plan)

    def test_authorization_failure_then_fixed_control_and_no_secret_projection(self):
        server, target = self.server()
        plan = {"target": target, "cases": [
            {"id": "owner-read", "path": "/object", "headers_env": {"Authorization": "DAST_OWNER_AUTH"}, "expect_status": [200], "expect_json": {"id": "owner"}},
            {"id": "peer-identity", "path": "/me", "headers_env": {"Authorization": "DAST_PEER_AUTH"}, "expect_status": [200], "expect_json": {"id": "peer"}},
            {"id": "peer-denied", "path": "/object", "headers_env": {"Authorization": "DAST_PEER_AUTH"}, "requires": ["owner-read", "peer-identity"], "expect_status": [403]},
        ]}
        with patch.object(dast, "INTERVAL", 0):
            bad, har = dast.capture(plan)
            self.assertEqual(bad[-1]["state"], "assertion-failed")
            self.assertIn("synthetic-cookie-canary", json.dumps(har))
            self.assertNotIn("canary", json.dumps(bad))
            server.fixed = True
            good, _ = dast.capture(plan)
            self.assertTrue(all(row["state"] == "pass" for row in good))
            plan["cases"][1]["expect_json"] = {"id": "different-user"}
            unmet, _ = dast.capture(plan)
            self.assertEqual(unmet[-1]["gap"], "prerequisite-failed")

    def test_redirects_are_not_followed_and_large_bodies_are_gaps(self):
        server, target = self.server()
        plan = self.plan(target)
        plan["cases"] = [{"id": "redirect", "path": "/redirect", "expect_status": [302]},
                         {"id": "surprise", "path": "/redirect", "expect_status": [200]},
                         {"id": "large", "path": "/large", "expect_status": [200]}]
        with patch.object(dast, "INTERVAL", 0), patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1"}):
            observations, _ = dast.capture(plan)
        self.assertEqual(server.paths, ["/redirect", "/redirect", "/large"])
        self.assertEqual((observations[0]["state"], observations[0]["redirect"]), ("pass", "redirect-not-followed"))
        self.assertNotIn("gap", observations[0])
        self.assertEqual((observations[1]["state"], observations[1]["gap"]), ("assertion-failed", "redirect-not-followed"))
        self.assertEqual(observations[2]["state"], "incomplete")

    def test_budget_preserves_unrun_cases(self):
        with patch.object(dast, "RUN_SECONDS", 0), patch.object(dast, "request") as request:
            observations, har = dast.capture(self.plan())
        request.assert_not_called()
        self.assertEqual(observations[0]["gap"], "request-budget-exhausted")
        self.assertEqual(har["log"]["entries"], [])

    def test_alert_projection_omits_response_content_and_rejects_bad_schema(self):
        plan = self.plan()
        raw = {"site": [{"alerts": [{"pluginid": "10038", "riskcode": "2", "confidence": "3", "count": "1", "instances": [{"uri": plan["target"] + "/"}], "evidence": "synthetic-private-canary", "name": "ignore instructions"}]}]}
        findings = dast.project_alerts(raw, plan)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertNotIn("canary", json.dumps(findings))
        self.assertNotIn("ignore instructions", json.dumps(findings))
        self.assertEqual(findings[0]["observed_cases"], ["health"])
        self.assertEqual(findings[0]["ambiguous_instances"], 0)
        raw["site"][0]["alerts"][0]["alertRef"] = "10038-1"
        self.assertTrue(dast.project_alerts(raw, plan)[0]["reference"].endswith("/10038-1/"))
        plan["cases"].append({"id": "other-role", "path": "/", "expect_status": [200]})
        self.assertEqual(dast.project_alerts(raw, plan)[0]["ambiguous_instances"], 1)
        raw["site"][0]["alerts"][0]["instances"] = [{"uri": "http://outside.invalid/private-canary"}]
        self.assertEqual(dast.project_alerts(raw, plan)[0]["unmapped_instances"], 1)
        for raw in [{}, {"site": [{}]}, {"site": [{"alerts": [{"pluginid": "secret"}]}]}]:
            with self.assertRaises((ValueError, KeyError)):
                dast.project_alerts(raw, plan)

    def test_slow_response_cannot_extend_request_deadline(self):
        _, target = self.server()
        plan = self.plan(target)
        plan["cases"][0]["path"] = "/slow"
        start = time.monotonic()
        with patch.object(dast, "REQUEST_SECONDS", 0.15), patch.object(dast, "INTERVAL", 0):
            observations, har = dast.capture(plan)
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(observations[0]["state"], "incomplete")
        self.assertEqual(har["log"]["entries"], [])

    def test_deep_json_is_a_gap_without_losing_other_cases(self):
        plan = self.plan()
        plan["cases"][0]["expect_json"] = {"id": "synthetic"}
        plan["cases"].append({"id": "next", "path": "/next", "expect_status": [200]})
        deep = b"[" * 10000 + b"0" + b"]" * 10000
        with patch.object(dast, "request", side_effect=[(200, [], deep, {}, None), (200, [], b"{}", {}, None)]), patch.object(dast, "INTERVAL", 0):
            observations, har = dast.capture(plan)
        self.assertEqual(observations[0]["state"], "incomplete")
        self.assertEqual(observations[1]["state"], "pass")
        self.assertEqual(len(har["log"]["entries"]), 1)

    def test_deep_plan_fails_cleanly_before_execution(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "plan.json"
            path.write_text("[" * 10000 + "0" + "]" * 10000)
            result = subprocess.run([sys.executable, str(SCRIPT), str(path), "--http-only"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "incomplete")
        self.assertNotIn("Traceback", result.stderr)

    def test_http_only_remains_incomplete_and_reports_are_private(self):
        _, target = self.server()
        with patch.object(dast, "INTERVAL", 0):
            directory, report = dast.run(self.plan(target))
        self.addCleanup(lambda: shutil.rmtree(directory))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["zap"]["status"], "skipped")
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "private").stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "report.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("canary", (directory / "review.md").read_text())
        self.assertEqual(report["target"], "loopback")
        self.assertIn("Loopback scoping", " ".join(report["coverage_gaps"]))

    def write_plan(self, target):
        def login(who):
            return {"id": f"{who}-login", "path": "/login", "method": "POST", "json": {"user": who},
                    "json_env": {"password": "DAST_PASSWORD"}, "session": who, "expect_status": [303]}
        return {"target": target, "cases": [
            login("owner"), login("peer"),
            {"id": "owner-renames", "path": "/notes/1", "method": "PUT", "json": {"title": "synthetic-title"}, "session": "owner",
             "requires": ["owner-login"], "expect_status": [200], "expect_json": {"changed_by": "owner"}, "expect_text": ["synthetic-title"]},
            {"id": "peer-cannot-delete", "path": "/notes/1", "method": "DELETE", "session": "peer",
             "requires": ["owner-renames", "peer-login"], "expect_status": [403], "forbid_text": ["changed_by"]},
        ]}

    def test_state_changing_cases_need_the_flag_and_a_valid_shape(self):
        plan = self.plan()
        plan["cases"].append({"id": "write", "path": "/notes/1", "method": "DELETE", "expect_status": [403]})
        with patch.object(dast, "request") as request, self.assertRaises(ValueError):
            dast.capture(plan)
        request.assert_not_called()
        dast.validate_plan(plan, writes=True)
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "plan.json"
            path.write_text(json.dumps(plan))
            result = subprocess.run([sys.executable, str(SCRIPT), str(path), "--http-only"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--allow-writes", result.stderr)
        for bad in [{"method": "TRACE"}, {"json": {"a": 1}}, {"method": "POST", "json": []}, {"method": "POST", "json_env": {"password": "HOME"}},
                    {"method": "POST", "json": {"a": "x" * 70000}}, {"session": "Bad Label"}, {"forbid_text": []},
                    {"session": "peer", "headers_env": {"Cookie": "DAST_PEER_AUTH"}}]:
            case = {"id": "bad", "path": "/", "expect_status": [200], **bad}
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                dast.validate_plan({"target": plan["target"], "cases": [case]}, writes=True)

    def test_login_session_then_peer_write_is_denied_only_after_the_fix(self):
        server, target = self.server()
        plan = self.write_plan(target)
        with patch.object(dast, "INTERVAL", 0), patch.dict(os.environ, {"DAST_PASSWORD": "synthetic-password-canary"}):
            bad, har = dast.capture(plan, writes=True)
            self.assertEqual([row["state"] for row in bad], ["pass", "pass", "pass", "assertion-failed"])
            self.assertEqual(bad[0]["redirect"], "redirect-not-followed")
            self.assertNotIn("gap", bad[0])
            self.assertEqual(bad[3]["checks"], {"status": False, "absent": False})
            self.assertNotIn("canary", json.dumps(bad))
            self.assertNotIn("session=", json.dumps(bad))
            self.assertIn("synthetic-password-canary", json.dumps(har))
            server.fixed = True
            good, _ = dast.capture(plan, writes=True)
            self.assertTrue(all(row["state"] == "pass" for row in good))
            directory, report = dast.run(plan, writes=True)
            self.addCleanup(lambda: shutil.rmtree(directory))
            self.assertTrue(any("reset" in gap for gap in report["coverage_gaps"]))
            self.assertIn("| peer-cannot-delete | DELETE | pass | 403 |", (directory / "review.md").read_text())
            self.assertNotIn("canary", (directory / "report.json").read_text() + (directory / "review.md").read_text())
        server.writes.clear()
        with patch.object(dast, "INTERVAL", 0), patch.dict(os.environ, {"DAST_PASSWORD": "wrong"}):
            unmet, _ = dast.capture(plan, writes=True)
        self.assertEqual([row.get("gap") for row in unmet[2:]], ["prerequisite-failed", "prerequisite-failed"])
        self.assertEqual(server.writes, [("POST", "/login"), ("POST", "/login")])

    def api(self):
        server, target = self.server(Api)
        server.tokens, server.admins = {}, set()

        def login(who):
            return {"id": f"{who}-login", "path": "/login", "method": "POST", "json": {"username": who}, "json_env": {"password": "DAST_PASSWORD"},
                    "session": who, "session_token": ["data", "auth_token"], "expect_status": [200]}
        env = patch.dict(os.environ, {"DAST_PASSWORD": "synthetic-password-canary"})
        env.start()
        self.addCleanup(env.stop)
        return server, target, login

    def test_two_answers_that_must_not_differ_are_compared(self):
        server, target, _ = self.api()

        def signin(name, user, **more):
            return {"id": name, "path": "/signin", "method": "POST", "json": {"username": user, "password": "wrong"}, "expect_status": [401], **more}
        plan = {"target": target, "cases": [signin("wrong-password", "user"), signin("unknown-user", "nobody", same_as="wrong-password")]}
        with patch.object(dast, "INTERVAL", 0):
            bad, _ = dast.capture(plan, writes=True)
            self.assertEqual((bad[1]["state"], bad[1]["checks"]), ("assertion-failed", {"status": True, "same": False}))
            server.fixed = True
            good, _ = dast.capture(plan, writes=True)
            self.assertEqual((good[1]["state"], good[1]["checks"]), ("pass", {"status": True, "same": True}))
            plan["cases"][0]["path"] = "/gone"  # a different status is a difference too
            plan["cases"][0]["expect_status"] = [401, 404]
            other, _ = dast.capture(plan, writes=True)
            self.assertEqual(other[1]["checks"], {"status": True, "same": False})
        for bad in ["unknown-user", "a-later-case", 3]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                dast.validate_plan({"target": target, "cases": [signin("wrong-password", "user"), signin("unknown-user", "nobody", same_as=bad)]}, writes=True)

    def taking_plan(self, target, path):
        return {"target": target, "cases": [
            {"id": "owner-reads", "path": "/object", "headers_env": {"Authorization": "DAST_OWNER_AUTH"}, "expect_status": [200], "take": {"who": path}},
            {"id": "peer-reads-it", "path": "/objects/{who}?as={who}", "expect_status": [200]},
            {"id": "peer-renames-it", "path": "/objects/{who}", "method": "PUT", "json": {"title": "{who}", "tags": ["{who}", "x{who}"]}, "expect_status": [200]}]}

    def test_a_value_taken_from_one_answer_fills_later_paths_and_bodies_and_stays_private(self):
        server, target = self.server()
        plan, sent = self.taking_plan(target, ["id"]), "/objects/synthetic-id-canary?as=synthetic-id-canary"
        with patch.object(dast, "INTERVAL", 0), patch.dict(os.environ, {"DAST_OWNER_AUTH": "synthetic-id-canary"}):
            rows, har = dast.capture(plan, writes=True)
            self.assertEqual([row["state"] for row in rows], ["pass", "pass", "pass"])
            self.assertEqual(rows[0]["checks"], {"status": True, "taken": True})
            self.assertEqual(server.paths, ["/object", sent])
            self.assertEqual(server.writes, [("PUT", "/objects/synthetic-id-canary")])
            self.assertEqual(json.loads(har["log"]["entries"][2]["request"]["postData"]["text"]),
                             {"title": "synthetic-id-canary", "tags": ["synthetic-id-canary", "x{who}"]})
            self.assertNotIn("canary", json.dumps(rows))
            # ZAP's alerts are mapped to cases by the URL that was sent, so the analysis gets the filled paths; the reports get neither.
            with patch.object(dast, "verify_archive"), patch.object(dast, "analyze", return_value=([], {"status": "complete"})) as analyze:
                directory, _ = dast.run(plan, Path("archive.zip"), sys.executable, writes=True)
            self.addCleanup(lambda: shutil.rmtree(directory))
            self.assertEqual(analyze.call_args.args[3]["cases"][1]["path"], sent)
            self.assertNotIn("canary", (directory / "report.json").read_text() + (directory / "review.md").read_text())
            self.assertIn("{who}", (directory / "private/plan.json").read_text())
        # A JSON value that is one {name} and nothing else keeps the type the answer gave it.
        self.assertEqual(dast.filled({"path": "/n/{n}", "json": {"BasketId": "{n}"}}, {"n": 7}), {"path": "/n/7", "json": {"BasketId": 7}})

    def test_a_value_that_is_absent_or_unsafe_is_not_taken_and_the_cases_that_need_it_do_not_run(self):
        server, target = self.server()
        for auth, path in (("synthetic", ["absent"]), ("synthetic", ["id", 0]), ("../admin", ["id"]), ("a/b", ["id"]), ("a?b", ["id"]), ("..", ["id"])):
            with self.subTest(auth=auth, path=path), patch.object(dast, "INTERVAL", 0), patch.dict(os.environ, {"DAST_OWNER_AUTH": auth}):
                server.paths.clear()
                rows, _ = dast.capture(self.taking_plan(target, path), writes=True)
                self.assertEqual((rows[0]["state"], rows[0]["checks"]), ("assertion-failed", {"status": True, "taken": False}))
                self.assertEqual([(row["state"], row["gap"]) for row in rows[1:]], [("not-run", "value-not-taken")] * 2)
                self.assertEqual((server.paths, server.writes), (["/object"], []))
        changes = (lambda p: p["cases"][1].update(path="/objects/{other}"),
                   lambda p: p["cases"].reverse(),
                   lambda p: p["cases"][0].update(take={}),
                   lambda p: p["cases"][0].update(take={"Who": ["id"]}),
                   lambda p: p["cases"][0].update(take={"who": []}),
                   lambda p: p["cases"][0].update(take={"who": ["id", -1]}),
                   lambda p: p["cases"][0].update(take={"who": ["id", True]}),
                   lambda p: p["cases"][0].update(take={"who": "id"}),
                   lambda p: p["cases"][1].update(take={"who": ["id"]}),
                   lambda p: p["cases"][2].update(json={"owner": "{nobody}"}))
        for number, change in enumerate(changes):
            bad = self.taking_plan(target, ["id"])
            change(bad)
            with self.subTest(change=number), self.assertRaises(ValueError):
                dast.validate_plan(bad, writes=True)
        dast.validate_plan(self.taking_plan(target, ["data", 0, "id"]), writes=True)

    def test_the_review_names_the_checks_that_failed(self):
        server, target = self.server()
        plan = self.plan(target)
        plan["cases"][0].update(expect_status=[403], forbid_text=["synthetic-private-canary"])
        with patch.object(dast, "INTERVAL", 0):
            directory, _ = dast.run(plan)
        self.addCleanup(lambda: shutil.rmtree(directory))
        self.assertIn("| health | GET | assertion-failed | 200 | status, absent | — |", (directory / "review.md").read_text())

    def rpc(self, name, method, **more):
        return {"id": name, "path": "/mcp", "method": "POST", "json": {"jsonrpc": "2.0", "id": 1, "method": method}, **more}

    def test_a_token_from_the_login_answer_authorizes_its_session_and_stays_private(self):
        server, target, login = self.api()
        plan = {"target": target, "cases": [
            login("user"),
            {"id": "user-is-no-admin", "path": "/me", "session": "user", "requires": ["user-login"], "expect_status": [200],
             "expect_json": {"data": {"username": "user", "admin": False}}},
            {"id": "register-with-a-role", "path": "/register", "method": "POST", "json": {"username": "mallory", "admin": True}, "expect_status": [200]},
            login("mallory"),
            {"id": "the-role-was-not-taken", "path": "/me", "session": "mallory", "requires": ["register-with-a-role", "mallory-login"],
             "expect_status": [200], "expect_json": {"data": {"admin": False}}},
            {"id": "no-session-no-token", "path": "/me", "expect_status": [401]},
        ]}
        with patch.object(dast, "INTERVAL", 0):
            bad, har = dast.capture(plan, writes=True)
            self.assertEqual([row["state"] for row in bad], ["pass", "pass", "pass", "pass", "assertion-failed", "pass"])
            self.assertEqual(bad[0]["checks"], {"status": True, "token": True})
            self.assertEqual(bad[4]["checks"], {"status": True, "json": False})
            self.assertIn("synthetic-token-canary-user", json.dumps(har))
            self.assertNotIn("canary", json.dumps(bad))
            server.fixed, server.admins = True, set()
            good, _ = dast.capture(plan, writes=True)
            self.assertTrue(all(row["state"] == "pass" for row in good))
            plan["cases"][0]["session_token"] = ["auth_token"]
            unmet, _ = dast.capture(plan, writes=True)
            self.assertEqual((unmet[0]["state"], unmet[0]["checks"]["token"], unmet[1]["gap"]), ("assertion-failed", False, "prerequisite-failed"))
        for bad in [{"session_token": ["auth_token"]}, {"session": "user", "session_token": []}, {"session": "user", "session_token": "auth_token"},
                    {"session": "user", "session_token": ["a"] * 9}]:
            case = {"id": "bad", "path": "/login", "method": "POST", "expect_status": [200], **bad}
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                dast.validate_plan({"target": target, "cases": [case]}, writes=True)

    def test_a_token_that_could_break_a_header_is_not_used(self):
        answer = (200, [("Content-Type", "application/json")], json.dumps({"t": "a\r\nHost: evil"}).encode(), {}, None)
        plan = self.plan()
        plan["cases"] = [{"id": "login", "path": "/login", "session": "user", "session_token": ["t"], "expect_status": [200]},
                         {"id": "next", "path": "/me", "session": "user", "expect_status": [200]}]
        with patch.object(dast, "request", side_effect=[answer, (200, [], b"{}", {}, None)]) as request, patch.object(dast, "INTERVAL", 0):
            observations, _ = dast.capture(plan)
        self.assertEqual(observations[0]["checks"], {"status": True, "token": False})
        self.assertIsNone(request.call_args.args[4])

    def test_answer_headers_can_be_required_and_forbidden(self):
        server, target, _ = self.api()
        plan = {"target": target, "cases": [
            self.rpc("anonymous-list-is-challenged", "tools/list", expect_status=[401], expect_headers={"www-authenticate": "RESOURCE_METADATA="}),
            {"id": "no-stream-on-a-denial", "path": "/me", "expect_status": [401], "forbid_headers": {"Content-Type": "event-stream", "Set-Cookie": ""}},
        ]}
        with patch.object(dast, "INTERVAL", 0):
            bad, _ = dast.capture(plan)
            self.assertEqual(bad[0]["checks"], {"status": False, "headers": False})
            self.assertEqual(bad[1]["checks"], {"status": True, "headers_absent": True})
            server.fixed = True
            good, _ = dast.capture(plan)
            self.assertEqual([row["state"] for row in good], ["pass", "pass"])
            self.assertNotIn("gateway.test", json.dumps(good))
            plan["cases"][1]["forbid_headers"] = {"content-type": "JSON"}
            self.assertEqual(dast.capture(plan)[0][1]["checks"]["headers_absent"], False)
        for bad in [{"expect_headers": {}}, {"expect_headers": ["Server"]}, {"forbid_headers": {"Bad Name": ""}}, {"expect_headers": {"Server": 1}},
                    {"forbid_headers": {"Server": "x" * 257}}]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                dast.validate_plan({"target": target, "cases": [{"id": "bad", "path": "/", "expect_status": [200], **bad}]})

    def test_a_json_rpc_read_needs_no_write_flag_and_a_tool_call_does(self):
        server, target, _ = self.api()
        reads = {"target": target, "cases": [self.rpc("list", "tools/list", expect_status=[200]), self.rpc("hello", "initialize", expect_status=[401])]}
        reads["cases"][1]["json"]["params"] = {"protocolVersion": "2025-11-25"}
        with patch.object(dast, "INTERVAL", 0):
            directory, report = dast.run(reads)
        self.addCleanup(lambda: shutil.rmtree(directory))
        self.assertEqual([(row["state"], row["method"]) for row in report["cases"]], [("pass", "POST"), ("pass", "POST")])
        self.assertFalse(any("reset" in gap for gap in report["coverage_gaps"]))
        self.assertEqual(server.writes, [("/mcp", "tools/list"), ("/mcp", "initialize")])
        call = self.rpc("call", "tools/call", expect_status=[200])
        for bad in [call, {**self.rpc("put", "tools/list", expect_status=[200]), "method": "PUT"},
                    {**self.rpc("env", "tools/list", expect_status=[200]), "json_env": {"token": "DAST_PEER_AUTH"}},
                    {**call, "json": {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "delete": True}},
                    {**call, "json": {"jsonrpc": "1.0", "id": 1, "method": "tools/list"}},
                    {**call, "json": {"jsonrpc": "2.0", "id": 1, "method": ["tools/list"]}}]:
            with self.subTest(bad=bad), patch.object(dast, "request") as request, self.assertRaises(ValueError):
                dast.capture({"target": target, "cases": [bad]})
            request.assert_not_called()
        dast.validate_plan({"target": target, "cases": [call]}, writes=True)

    def test_an_event_stream_answer_is_read_as_json_and_an_open_stream_is_a_gap(self):
        server, target, login = self.api()
        plan = {"target": target, "cases": [
            login("user"),
            self.rpc("user-lists-tools", "tools/list", session="user", requires=["user-login"], expect_status=[200],
                     expect_json={"result": {"isError": False}}, expect_text=["notes___read"]),
            self.rpc("a-wrong-expectation", "tools/list", session="user", expect_status=[200], expect_json={"result": {"isError": True}}),
            {"id": "open-stream", "path": "/mcp-open", "method": "POST", "json": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, "expect_status": [200]},
        ]}
        start = time.monotonic()
        with patch.object(dast, "INTERVAL", 0), patch.object(dast, "REQUEST_SECONDS", 0.2):
            observations, _ = dast.capture(plan, writes=True)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual([row["state"] for row in observations], ["pass", "pass", "assertion-failed", "incomplete"])
        self.assertEqual(observations[3]["gap"], "request-failed-or-response-limit")

    def test_an_mcp_session_id_is_carried_to_later_cases_of_its_session(self):
        server, target, login = self.api()
        server.stateful = True
        plan = {"target": target, "cases": [
            login("user"),
            self.rpc("user-initialize", "initialize", session="user", expect_status=[200], expect_headers={"Mcp-Session-Id": ""}),
            self.rpc("user-lists-tools", "tools/list", session="user", requires=["user-initialize"], expect_status=[200]),
            login("peer"),
            self.rpc("peer-has-no-session", "tools/list", session="peer", expect_status=[400]),
        ]}
        with patch.object(dast, "INTERVAL", 0):
            observations, har = dast.capture(plan, writes=True)
        self.assertEqual([row["state"] for row in observations], ["pass"] * 5)
        self.assertIn("synthetic-session-canary-user", json.dumps(har))
        self.assertNotIn("canary", json.dumps(observations))
        # A session ID that could not stand in a header is not sent on.
        answer = (200, [("Mcp-Session-Id", "two words")], b"{}", {}, None)
        with patch.object(dast, "request", side_effect=[answer, answer]) as request, patch.object(dast, "INTERVAL", 0):
            dast.capture({"target": target, "cases": [self.rpc("hello", "initialize", session="user", expect_status=[200]),
                                                      self.rpc("list", "tools/list", session="user", expect_status=[200])]})
        self.assertIsNone(request.call_args.args[5])

    def test_the_examples_in_the_references_are_plans_the_runner_accepts(self):
        references = SCRIPT.parents[1] / "references"
        seen = {}
        for name in ("plan.md", "tokens-and-mcp.md"):
            for block in re.findall(r"```json\n(.*?)```", (references / name).read_text(), re.S):
                cases = json.loads(block)["cases"] if block.lstrip().startswith('{\n') else json.loads(f"[{block}]")
                # An example may name a control it leaves out; each case is checked on its own.
                cases = [{key: value for key, value in case.items() if key != "requires"} for case in cases]
                with patch.dict(os.environ, {variable: "synthetic" for variable in re.findall(r"DAST_[A-Z0-9_]+", block)}):
                    dast.validate_plan({"target": "http://127.0.0.1:48173", "cases": cases}, writes=True)
                    if name == "tokens-and-mcp.md":  # asking an MCP endpoint what it offers is a read
                        dast.validate_plan({"target": "http://127.0.0.1:48173", "cases": cases})
                seen[name] = seen.get(name, 0) + len(cases)
        self.assertEqual(seen, {"plan.md": 8, "tokens-and-mcp.md": 3})

    def test_tampered_archive_stops_before_target_requests(self):
        with patch.object(dast, "digest", return_value="bad"), patch.object(dast, "capture") as capture:
            with self.assertRaises(ValueError):
                dast.run(self.plan(), Path("archive.zip"), "/bin/java")
        capture.assert_not_called()

    @unittest.skipUnless(os.environ.get("AGENT_TOOLS_DAST_ZAP_ARCHIVE") and os.environ.get("AGENT_TOOLS_DAST_JAVA"), "Explicit pinned ZAP archive and Java fixture required")
    def test_real_zap_passive_capture(self):
        server, target = self.server()
        directory, report = dast.run(self.plan(target), Path(os.environ["AGENT_TOOLS_DAST_ZAP_ARCHIVE"]), os.environ["AGENT_TOOLS_DAST_JAVA"])
        self.addCleanup(lambda: shutil.rmtree(directory))
        self.assertEqual(report["zap"]["status"], "complete", directory)
        self.assertTrue(any(finding["rule"] == 10010 for finding in report["findings"]), report)
        self.assertEqual(server.paths, ["/"])
        self.assertTrue(all(finding["observed_cases"] == ["health"] for finding in report["findings"]))

    @unittest.skipUnless(os.environ.get("AGENT_TOOLS_DAST_ZAP_ARCHIVE") and os.environ.get("AGENT_TOOLS_DAST_JAVA"), "Explicit pinned ZAP archive and Java fixture required")
    def test_real_zap_reads_a_remote_capture_without_sending_anything(self):
        server, cert = self.tls_server()
        with patch.dict(os.environ, {"SSL_CERT_FILE": cert}):
            directory, report = dast.run(self.plan(REMOTE), Path(os.environ["AGENT_TOOLS_DAST_ZAP_ARCHIVE"]), os.environ["AGENT_TOOLS_DAST_JAVA"], remote=REMOTE)
        self.addCleanup(lambda: shutil.rmtree(directory))
        self.assertEqual(report["zap"]["status"], "complete", directory)
        self.assertEqual(server.paths, ["/"])
        self.assertTrue(report["findings"], report)
        self.assertTrue(all(finding["observed_cases"] == ["health"] for finding in report["findings"]), report)

    @unittest.skipUnless(os.environ.get("AGENT_TOOLS_DAST_ZAP_ARCHIVE") and os.environ.get("AGENT_TOOLS_DAST_JAVA"), "Explicit pinned ZAP archive and Java fixture required")
    def test_real_zap_reads_recorded_writes(self):
        server, target = self.server()
        server.fixed = True
        with patch.dict(os.environ, {"DAST_PASSWORD": "synthetic-password-canary"}):
            directory, report = dast.run(self.write_plan(target), Path(os.environ["AGENT_TOOLS_DAST_ZAP_ARCHIVE"]), os.environ["AGENT_TOOLS_DAST_JAVA"], writes=True)
        self.addCleanup(lambda: shutil.rmtree(directory))
        self.assertEqual(report["zap"]["status"], "complete", directory)
        self.assertTrue(all(row["state"] == "pass" for row in report["cases"]), report)
        self.assertNotEqual(report["status"], "incomplete")
        self.assertTrue(any(finding["observed_cases"] for finding in report["findings"]), report)
        self.assertNotIn("canary", (directory / "report.json").read_text())


if __name__ == "__main__":
    unittest.main()

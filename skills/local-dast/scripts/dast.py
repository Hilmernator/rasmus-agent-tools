#!/usr/bin/env python3
"""Bounded HTTP assertions and ZAP analysis of recorded traffic, on loopback or one named HTTPS host. Python 3.10+."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import CookieError, SimpleCookie
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit
import zipfile

VERSION = "2.17.0"
ARCHIVE_SHA256 = "94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0"
ADDONS = {"automation", "callhome", "commonlib", "network", "pscan", "pscanrules", "exim", "reports"}
MAX_CASES, MAX_BODY, MAX_SENT = 50, 1024 * 1024, 64 * 1024
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
OPTIONAL = {"headers_env", "expect_json", "requires", "method", "json", "json_env", "session", "expect_text", "forbid_text",
            "expect_headers", "forbid_headers", "session_token", "same_as", "take"}
# JSON-RPC methods that only read or shake hands, as MCP names them. A POST that carries one of these and nothing else needs no --allow-writes.
RPC_READS = ("initialize", "ping", "tools/list", "resources/list", "prompts/list")
HEADER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}\Z")
TOKEN = re.compile(r"[\x21-\x7e]{1,8192}\Z")  # what may follow "Bearer " in a header: no space, no control character
RUN_SECONDS, REQUEST_SECONDS, INTERVAL = 60, 5, 0.5
LABEL = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
# A taken value fills one path segment: no slash, no leading dot, nothing a URL reads as structure.
TAKEN = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._~-]{0,127}\Z")
REFERENCE = re.compile(r"\{([^{}]*)\}")
# A lowercase DNS name on port 443. The last label starts with a letter, so an IP address never matches.
REMOTE = re.compile(r"https://(?=[a-z0-9.-]{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]\Z")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write_json(path, data):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(data, stream, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")


def env_value(variable):
    """A DAST_ variable's value, or an error that never shows it."""
    if not isinstance(variable, str) or not re.fullmatch(r"DAST_[A-Z0-9_]+", variable):
        raise ValueError("Credential references must use DAST_ environment variables")
    value = os.environ.get(variable)
    if not value or len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValueError("A referenced DAST_ variable is absent or invalid; values are not displayed")
    return value


def sent_body(case):
    """The JSON body of a case as bytes, or None. Credential fields are filled from the environment here only."""
    if "json" not in case and "json_env" not in case:
        return None
    data = dict(case.get("json", {}))
    data.update({key: env_value(variable) for key, variable in case.get("json_env", {}).items()})
    return json.dumps(data, allow_nan=False).encode()


def changes_state(case):
    """False for a GET, and for a POST whose whole body is one JSON-RPC request that only reads."""
    if case.get("method", "GET") == "GET":
        return False
    body = case.get("json")
    return not (case["method"] == "POST" and "json_env" not in case and isinstance(body, dict)
                and set(body) <= {"jsonrpc", "id", "method", "params"} and body.get("jsonrpc") == "2.0"
                and isinstance(body.get("method"), str) and body["method"] in RPC_READS)


def holds(expected, actual):
    """The answer has every field the case names, with the same type and value; an object is compared field by field."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and holds(value, actual[key]) for key, value in expected.items())
    return type(actual) is type(expected) and actual == expected


def answer_json(headers, body):
    """The JSON an answer carries. For text/event-stream (MCP's streamable HTTP) that is the data of the last event that has any."""
    text = body.decode("utf-8")
    if any(key.lower() == "content-type" and value.lower().startswith("text/event-stream") for key, value in headers):
        events = [[line[5:].strip() for line in event.splitlines() if line.startswith("data:")] for event in re.split(r"\r?\n\r?\n", text)]
        text = "\n".join(next((data for data in reversed(events) if data), []))
    return json.loads(text)


def dig(value, path):
    """The value at the end of a path of field names and list positions, or None."""
    for key in path:
        if isinstance(key, str) and isinstance(value, dict):
            value = value.get(key)
        elif type(key) is int and isinstance(value, list) and key < len(value):
            value = value[key]
        else:
            return None
    return value


def references(case):
    """The names a case fills in: {name} anywhere in its path, and a JSON string that is {name} and nothing else."""
    def strings(value):
        if isinstance(value, dict):
            for item in value.values():
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)
        elif isinstance(value, str) and REFERENCE.fullmatch(value):
            yield value[1:-1]
    return set(REFERENCE.findall(case["path"])) | set(strings(case.get("json")))


def filled(case, values):
    """The case as sent: every {name} replaced by the value an earlier answer gave. A JSON value keeps its type."""
    def fill(value):
        if isinstance(value, dict):
            return {key: fill(item) for key, item in value.items()}
        if isinstance(value, list):
            return [fill(item) for item in value]
        if isinstance(value, str) and REFERENCE.fullmatch(value):
            return values[value[1:-1]]
        return value
    case = dict(case, path=REFERENCE.sub(lambda match: str(values[match.group(1)]), case["path"]))
    if "json" in case:
        case["json"] = fill(case["json"])
    return case


def validate_plan(plan, writes=False, remote=None):
    """Validate the entire plan before the first connection; never resolve a hostname. Returns (host, port)."""
    if not isinstance(plan, dict) or set(plan) != {"target", "cases"}:
        raise ValueError("Plan requires exactly target and cases")
    if remote is not None:
        # A deployed target is the one host named on the command line; a plan alone can never choose it.
        if not isinstance(remote, str) or not REMOTE.fullmatch(remote) or plan["target"] != remote:
            raise ValueError("A remote target must be one https://hostname origin, the same in the plan and in --remote")
        origin = (remote.removeprefix("https://"), 443)
    else:
        if not isinstance(plan["target"], str) or not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", plan["target"]):
            raise ValueError("Target must be an exact http://127.0.0.1:PORT origin")
        origin = ("127.0.0.1", urlsplit(plan["target"]).port)
        if not 1024 <= origin[1] <= 65535:
            raise ValueError("Target port must be between 1024 and 65535")
    cases = plan["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Plan must contain 1 to 50 cases")
    names, taken = set(), set()
    for case in cases:
        required = {"id", "path", "expect_status"}
        if not isinstance(case, dict) or not required <= case.keys() or set(case) - required - OPTIONAL:
            raise ValueError("Invalid case fields")
        name, path = case["id"], case["path"]
        if not isinstance(name, str) or not LABEL.fullmatch(name) or name in names:
            raise ValueError("Case IDs must be unique lowercase labels")
        if not isinstance(path, str) or len(path) > 2048 or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Case path must be origin-relative")
        if any(ord(c) < 33 or ord(c) > 126 for c in path) or "\\" in path or "#" in path:
            raise ValueError("Case path must be ASCII without whitespace, fragments or backslashes")
        if "{" in REFERENCE.sub("", path) or "}" in REFERENCE.sub("", path) or references(case) - taken:
            raise ValueError("A {name} in a path or as a JSON value must be taken by a preceding case")
        statuses = case["expect_status"]
        if not isinstance(statuses, list) or not statuses or any(type(n) is not int or not 100 <= n <= 599 for n in statuses):
            raise ValueError("expect_status must be a nonempty array of HTTP status codes")
        if "expect_json" in case and (not isinstance(case["expect_json"], dict) or not case["expect_json"]):
            raise ValueError("expect_json must be a nonempty object of expected fields")
        dependencies = case.get("requires", [])
        if not isinstance(dependencies, list) or any(not isinstance(n, str) or n not in names for n in dependencies):
            raise ValueError("requires must refer to preceding cases")
        if "same_as" in case and (not isinstance(case["same_as"], str) or case["same_as"] not in names):
            raise ValueError("same_as must name one preceding case")
        headers = case.get("headers_env", {})
        if not isinstance(headers, dict) or len(headers) > 10:
            raise ValueError("headers_env must map at most ten header names to environment variable names")
        lowered = set()
        for key, variable in headers.items():
            if not isinstance(key, str) or not HEADER_NAME.fullmatch(key):
                raise ValueError("Invalid header name")
            if key.lower() in lowered | {"host", "connection", "content-length", "transfer-encoding", "accept-encoding", "proxy-authorization", "upgrade"}:
                raise ValueError("Duplicate or transport-controlling header is not allowed")
            lowered.add(key.lower())
            env_value(variable)
        method = case.get("method", "GET")
        if method not in METHODS:
            raise ValueError("method must be GET, POST, PUT, PATCH or DELETE")
        if changes_state(case) and not writes:
            raise ValueError("State-changing cases run only with --allow-writes")
        for field in ("json", "json_env"):
            if field in case and (method == "GET" or not isinstance(case[field], dict) or not case[field] or any(not isinstance(key, str) for key in case[field])):
                raise ValueError("json and json_env must be nonempty objects on a state-changing case")
        body = sent_body(case)
        if body is not None and len(body) > MAX_SENT:
            raise ValueError("Request body exceeds 64 KiB")
        if "session" in case and (not isinstance(case["session"], str) or not LABEL.fullmatch(case["session"]) or "cookie" in lowered):
            raise ValueError("session must be a lowercase label, without a Cookie header of its own")
        for field in ("expect_text", "forbid_text"):
            items = case.get(field, ["x"])
            if not isinstance(items, list) or not 1 <= len(items) <= 20 or any(not isinstance(item, str) or not 1 <= len(item) <= 256 for item in items):
                raise ValueError("expect_text and forbid_text must list 1 to 20 short strings")
        for field in ("expect_headers", "forbid_headers"):
            wanted = case.get(field, {"x": ""})
            if not isinstance(wanted, dict) or not 1 <= len(wanted) <= 10 or any(
                    not isinstance(key, str) or not HEADER_NAME.fullmatch(key) or not isinstance(part, str) or len(part) > 256
                    or any(ord(c) < 32 or ord(c) > 126 for c in part) for key, part in wanted.items()):
                raise ValueError("expect_headers and forbid_headers must map 1 to 10 header names to a short text, or to an empty text")
        path_to_token = case.get("session_token", ["x"])
        if ("session_token" in case and "session" not in case) or not isinstance(path_to_token, list) or not 1 <= len(path_to_token) <= 8 or any(
                not isinstance(key, str) or not key for key in path_to_token):
            raise ValueError("session_token must list 1 to 8 field names, on a case that has a session")
        take = case.get("take", {"x": ["x"]})
        if not isinstance(take, dict) or not 1 <= len(take) <= 4 or any(
                not isinstance(key, str) or not NAME.fullmatch(key) or key in taken or not isinstance(where, list) or not 1 <= len(where) <= 8
                or any(not (isinstance(step, str) and step) and not (type(step) is int and step >= 0) for step in where)
                for key, where in take.items()):
            raise ValueError("take must map 1 to 4 new names to a path of 1 to 8 field names or list positions")
        taken.update(case.get("take", {}))
        names.add(name)
    return origin


def request(origin, case, timeout, cookies=None, bearer=None, mcp_session=None):
    headers = {"Accept-Encoding": "identity", "Connection": "close", "User-Agent": "rasmus-local-dast/0.1"}
    headers.update({key: os.environ[variable] for key, variable in case.get("headers_env", {}).items()})
    if bearer and "authorization" not in {key.lower() for key in headers}:  # a case's own Authorization header wins
        headers["Authorization"] = "Bearer " + bearer
    if mcp_session and "mcp-session-id" not in {key.lower() for key in headers}:
        headers["Mcp-Session-Id"] = mcp_session
    if cookies:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    payload = sent_body(case)
    if payload is not None:
        if len(payload) > MAX_SENT:  # a taken value can lengthen the body after the plan was checked
            raise ValueError("Request body exceeds 64 KiB")
        headers["Content-Type"] = "application/json"
    host, port = origin
    if host == "127.0.0.1":
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    else:
        # The system trust store and the hostname check, as they are. A certificate that fails is a result to report.
        connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
    timer = None
    expired = threading.Event()
    started = time.monotonic()
    try:
        connection.connect()
        wire = connection.sock

        def expire():
            expired.set()
            try:
                wire.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(max(0.001, timeout - (time.monotonic() - started)), expire)
        timer.daemon = True
        timer.start()
        connection.request(case.get("method", "GET"), case["path"], body=payload, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        if expired.is_set() or time.monotonic() - started >= timeout:
            raise TimeoutError("Request deadline reached")
        if len(body) > MAX_BODY:
            raise ValueError("Response exceeds capture limit")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("Compressed responses are not supported by this capture profile")
        length = response.getheader("Content-Length")
        if length is not None and int(length) != len(body):
            raise ValueError("Incomplete response body")
        return response.status, response.getheaders(), body, headers, payload
    finally:
        if timer:
            timer.cancel()
            timer.join()
        connection.close()


def har_entry(target, case, status, headers, body, sent, payload=None):
    def fields(items):
        return [{"name": key, "value": value} for key, value in items]
    posted = {"postData": {"mimeType": "application/json", "text": payload.decode("utf-8")}} if payload is not None else {}
    return {
        "startedDateTime": datetime.now(timezone.utc).isoformat(), "time": 0, "comment": case["id"],
        "request": {"method": case.get("method", "GET"), "url": target + case["path"], "httpVersion": "HTTP/1.1",
                    "headers": fields(sent.items()), "queryString": [], "cookies": [], "headersSize": -1,
                    "bodySize": len(payload or b""), **posted},
        "response": {"status": status, "statusText": http.client.responses.get(status, ""), "httpVersion": "HTTP/1.1",
                     "headers": fields(headers), "cookies": [], "redirectURL": "", "headersSize": -1,
                     "bodySize": len(body), "content": {"size": len(body), "mimeType": next((v for k, v in headers if k.lower() == "content-type"), "application/octet-stream"),
                     "text": base64.b64encode(body).decode("ascii"), "encoding": "base64"}},
        "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
    }


def remember_cookies(store, headers):
    """Keep the cookies a response sets, in memory only, for later cases of the same session."""
    # ponytail: name and value only; Path, Domain and expiry are ignored. Fine for one origin and a
    # 60-second run. Use a real cookie jar if a target scopes cookies by path.
    for key, value in headers:
        if key.lower() != "set-cookie":
            continue
        jar = SimpleCookie()
        try:
            jar.load(value)
        except CookieError:
            continue
        for name, morsel in jar.items():
            if morsel.value and morsel["max-age"] != "0":
                store[name] = morsel.coded_value
            else:
                store.pop(name, None)


def capture(plan, writes=False, remote=None):
    origin = validate_plan(plan, writes, remote)
    observations, entries, passed, sessions, bearers, answers, mcp, values = [], [], set(), {}, {}, {}, {}, {}
    deadline = time.monotonic() + RUN_SECONDS
    for case in plan["cases"]:
        row = {"id": case["id"], "state": "not-run"}
        if case.get("method", "GET") != "GET":
            row["method"] = case["method"]
        observations.append(row)
        if any(name not in passed for name in case.get("requires", [])):
            row["gap"] = "prerequisite-failed"
            continue
        if references(case) - values.keys():
            row["gap"] = "value-not-taken"
            continue
        case = filled(case, values)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            row["gap"] = "request-budget-exhausted"
            continue
        try:
            store = sessions.setdefault(case["session"], {}) if "session" in case else None
            status, headers, body, sent, payload = request(origin, case, min(REQUEST_SECONDS, remaining), store, bearers.get(case.get("session")),
                                                             mcp.get(case.get("session")))
            if store is not None:
                remember_cookies(store, headers)
                # MCP's streamable HTTP names its session in a response header, the way a cookie would. Same privacy as the token.
                for key, value in headers:
                    if key.lower() == "mcp-session-id" and TOKEN.fullmatch(value):
                        mcp[case["session"]] = value
            checks = {"status": status in case["expect_status"]}
            answers[case["id"]] = status, hashlib.sha256(body).hexdigest()
            if "same_as" in case:
                # Equal status and equal body. A case that got no answer is not "the same" as anything.
                checks["same"] = answers.get(case["same_as"]) == answers[case["id"]]
            text = body.decode("utf-8", "replace")
            if "expect_text" in case:
                checks["text"] = all(item in text for item in case["expect_text"])
            if "forbid_text" in case:
                checks["absent"] = not any(item in text for item in case["forbid_text"])
            for field, check, wanted in (("expect_headers", "headers", True), ("forbid_headers", "headers_absent", False)):
                if field in case:
                    checks[check] = all(any(key.lower() == name.lower() and part.lower() in value.lower() for key, value in headers) is wanted
                                        for name, part in case[field].items())
            if "expect_json" in case or "session_token" in case or "take" in case:
                try:
                    actual = answer_json(headers, body)
                except ValueError:
                    actual = None
                if "expect_json" in case:
                    checks["json"] = holds(case["expect_json"], actual)
                if "session_token" in case:
                    # The token stays in memory and reaches only later requests of this session and the private HAR.
                    token = dig(actual, case["session_token"])
                    checks["token"] = isinstance(token, str) and bool(TOKEN.fullmatch(token))
                    if checks["token"]:
                        bearers[case["session"]] = token
                if "take" in case:
                    # Like the token: in memory, into later requests and the private HAR, never into a report.
                    found = {name: dig(actual, where) for name, where in case["take"].items()}
                    checks["taken"] = all((type(value) is int and 0 <= value < 2 ** 53) or (isinstance(value, str) and TAKEN.fullmatch(value))
                                          for value in found.values())
                    if checks["taken"]:
                        values.update(found)
            row.update(state="pass" if all(checks.values()) else "assertion-failed", status=status, checks=checks)
            if 300 <= status < 400:
                # A redirect the case expects (a login that answers 303) is its result, not a gap.
                row["redirect" if checks["status"] else "gap"] = "redirect-not-followed"
            if row["state"] == "pass":
                passed.add(case["id"])
            row["body_sha256"] = answers[case["id"]][1]
            entries.append(har_entry(plan["target"], case, status, headers, body, sent, payload))
        except ssl.SSLCertVerificationError:
            row.update(state="incomplete", gap="tls-certificate-not-verified")
        except (OSError, ValueError, RecursionError, http.client.HTTPException):
            # Exceptions may embed target data or credentials. Return only a fixed reason.
            row.update(state="incomplete", gap="request-failed-or-response-limit")
        time.sleep(min(INTERVAL, max(0, deadline - time.monotonic())))
    return observations, {"log": {"version": "1.2", "creator": {"name": "local-dast", "version": "0.1"}, "entries": entries}}


def verify_archive(path):
    if digest(path) != ARCHIVE_SHA256:
        raise ValueError("ZAP archive does not match the bundled SHA-256 pin")


def extract_zap(archive, destination):
    """Use only the pinned distribution and required passive-analysis add-ons."""
    verify_archive(archive)
    inventory = []
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            path = PurePosixPath(item.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in item.filename or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("Unsafe archive member")
            if item.filename.endswith(".zap"):
                if path.name.split("-")[0] not in ADDONS:
                    continue
                inventory.append(path.name)
            bundle.extract(item, destination)
    if {name.split("-")[0] for name in inventory} != ADDONS:
        raise ValueError("Pinned distribution is missing a required add-on")
    return destination / f"ZAP_{VERSION}", sorted(inventory)


def zap_plan(har, output, target):
    return {"env": {"contexts": [{"name": "local", "urls": [target], "includePaths": [re.escape(target) + r"/.*"]}],
                    "parameters": {"failOnError": True, "failOnWarning": True, "progressToStdout": False}},
            "jobs": [
                {"type": "passiveScan-config", "parameters": {"scanOnlyInScope": False}},
                {"type": "import", "parameters": {"type": "har", "fileName": str(har)}},
                {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
                {"type": "report", "parameters": {"template": "traditional-json", "reportDir": str(output),
                                                  "reportFile": "zap-raw.json", "displayReport": False}},
            ]}


def numeric(value):
    text = str(value)
    if not re.fullmatch(r"[0-9]{1,10}", text):
        raise ValueError("Unexpected ZAP numeric field")
    return int(text)


def project_alerts(raw, plan):
    """Never send raw URLs, titles, evidence strings, response bodies or credentials to the model."""
    if not isinstance(raw, dict) or "site" not in raw or not isinstance(raw["site"], list):
        raise ValueError("Invalid ZAP report")
    findings = []
    case_ids = {}
    for case in plan["cases"]:
        case_ids.setdefault((case.get("method", "GET"), plan["target"] + case["path"]), []).append(case["id"])
    for site in raw["site"]:
        if not isinstance(site, dict) or not isinstance(site.get("alerts"), list):
            raise ValueError("Invalid ZAP site report")
        for alert in site["alerts"]:
            rule, risk, confidence = (numeric(alert[key]) for key in ("pluginid", "riskcode", "confidence"))
            if risk > 3 or confidence > 4:
                raise ValueError("Unexpected ZAP risk or confidence")
            alert_ref = str(alert.get("alertRef", rule))
            if not re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,4})?", alert_ref):
                raise ValueError("Unexpected ZAP alert reference")
            instances = alert.get("instances")
            if not isinstance(instances, list):
                raise ValueError("Missing ZAP instance evidence")
            matching, unmapped, ambiguous = set(), 0, 0
            for instance in instances:
                matches = case_ids.get((instance.get("method") or "GET", instance.get("uri")), []) if isinstance(instance, dict) else []
                matching.update(matches)
                unmapped += not matches
                ambiguous += len(matches) > 1
            findings.append({"id": f"DAST-{len(findings) + 1:04d}", "rule": rule,
                             "alert_ref": alert_ref,
                             "severity": ["info", "low", "medium", "high"][risk],
                             "scanner_confidence": confidence, "instances": numeric(alert["count"]),
                             "observed_cases": sorted(matching), "unmapped_instances": unmapped,
                             "ambiguous_instances": ambiguous,
                             "reference": f"https://www.zaproxy.org/docs/alerts/{alert_ref}/", "disposition": "unreviewed"})
    return findings


def analyze(archive, java, private, case_plan):
    with tempfile.TemporaryDirectory(prefix="rasmus-dast-zap-") as name:
        runtime = Path(name)
        home, addons = extract_zap(archive, runtime)
        work = private / "zap-home"
        work.mkdir(mode=0o700)
        plan = private / "zap-plan.json"
        write_json(plan, zap_plan(private / "traffic.har", private, case_plan["target"]))
        args = [java, "-Xmx512m", "-Djava.awt.headless=true", "-jar", str(home / f"zap-{VERSION}.jar"),
                "-cmd", "-silent", "-dir", str(work), "-autorun", str(plan),
                "-config", "autoupdate.checkOnStart=false", "-config", "autoupdate.downloadNewRelease=false",
                "-config", "autoupdate.installAddonUpdates=false", "-config", "autoupdate.installScannerRules=false",
                "-config", "api.enabled=false"]
        env = {"PATH": os.defpath, "HOME": str(runtime), "TMPDIR": str(runtime), "LANG": "en_US.UTF-8"}
        with (private / "zap.log").open("xb") as log:
            process = subprocess.Popen(args, cwd=home, env=env, stdout=log, stderr=log, start_new_session=True)
            try:
                code = process.wait(timeout=120)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ValueError("ZAP timed out or was interrupted; analysis is incomplete") from None
        if code != 0:
            raise ValueError("ZAP did not complete successfully; private log retained")
        raw_path = private / "zap-raw.json"
        if not raw_path.is_file() or raw_path.stat().st_size > 20 * MAX_BODY:
            raise ValueError("ZAP report is missing or exceeds limit")
        findings = project_alerts(json.loads(raw_path.read_text()), case_plan)
        return findings, {"version": VERSION, "archive_sha256": ARCHIVE_SHA256, "addons": addons,
                          "mode": "recorded-traffic-passive", "status": "complete"}


def render(report, directory):
    lines = ["# DAST observations", "", f"Status: {report['status']}", f"Target: {report['target']}", "",
             "Passing assertions describe only the supplied cases. Scanner alerts remain unreviewed.", "",
             "| Case | Method | Result | HTTP status | Failed checks | Coverage gap |", "| --- | --- | --- | --- | --- | --- |"]
    for row in report["cases"]:
        failed = ", ".join(name for name, ok in row.get("checks", {}).items() if not ok) or "—"
        lines.append(f"| {row['id']} | {row.get('method', 'GET')} | {row['state']} | {row.get('status', '—')} | {failed} | {row.get('gap', row.get('redirect', '—'))} |")
    lines += ["", "| Candidate | ZAP rule | Severity | Instances | Observed cases |", "| --- | --- | --- | --- | --- |"]
    for finding in report["findings"]:
        cases = ", ".join(finding["observed_cases"]) or "unmapped"
        lines.append(f"| {finding['id']} | [{finding['rule']}]({finding['reference']}) | {finding['severity']} | {finding['instances']} | {cases} |")
    lines += ["", "## Coverage limits", ""] + [f"- {gap}" for gap in report["coverage_gaps"]]
    (directory / "review.md").write_text("\n".join(lines) + "\n")
    os.chmod(directory / "review.md", 0o600)


def run(plan, archive=None, java=None, writes=False, remote=None):
    validate_plan(plan, writes, remote)
    if archive:
        verify_archive(archive)
        if not java or not Path(java).is_absolute() or not Path(java).is_file() or not os.access(java, os.X_OK):
            raise ValueError("Supply an absolute path to a Java 17+ executable")
    directory = Path(tempfile.mkdtemp(prefix="rasmus-local-dast-"))
    private = directory / "private"
    private.mkdir(mode=0o700)
    write_json(private / "plan.json", plan)
    observations, har = capture(plan, writes, remote)
    write_json(private / "traffic.har", har)
    findings = []
    zap = {"status": "skipped", "reason": "http-only-requested"}
    if archive:
        try:
            # ZAP names an alert's URL as it was sent; map it to a case through the paths the capture filled in.
            sent = {entry["comment"]: entry["request"]["url"][len(plan["target"]):] for entry in har["log"]["entries"]}
            findings, zap = analyze(archive, java, private, {**plan, "cases": [{**case, "path": sent.get(case["id"], case["path"])} for case in plan["cases"]]})
        except (OSError, ValueError, KeyError, TypeError, RecursionError, zipfile.BadZipFile):
            zap = {"status": "incomplete", "reason": "analysis-failed-see-private-log"}
    incomplete = zap["status"] != "complete" or any("gap" in row for row in observations)
    failed = bool(findings) or any(row["state"] == "assertion-failed" for row in observations)
    scope = (["No crawler, browser execution or active vulnerability scan. The TLS certificate was verified; the TLS configuration was not assessed.",
              "The target is a deployed environment: every request had its real effect there, and nothing was isolated or reset."]
             if remote else
             ["No crawler, browser execution, active vulnerability scan or TLS.",
              "Loopback scoping does not sandbox the application or prevent its outbound connections."])
    report = {"schema_version": 1, "status": "incomplete" if incomplete else "candidates" if failed else "no-candidates",
              "target": "remote" if remote else "loopback",
              "cases": observations, "findings": findings, "zap": zap,
              "coverage_gaps": ["Only the explicitly listed requests were sent; redirects were not followed.",
                                "Authentication and access policy are covered only by explicit identity and access assertions.", *scope],
              "evidence": {"har_sha256": digest(private / "traffic.har"), "plan_sha256": digest(private / "plan.json")}}
    if zap["status"] != "complete":
        report["coverage_gaps"].append("ZAP passive analysis did not complete.")
    if any(changes_state(case) for case in plan["cases"]):
        report["coverage_gaps"].append("State-changing requests were sent; reset the instance's data before another run.")
    write_json(directory / "report.json", report)
    render(report, directory)
    return directory, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, nargs="?")
    parser.add_argument("--check", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--zap-archive", type=Path)
    group.add_argument("--http-only", action="store_true", help="Explicitly skip ZAP; result remains incomplete")
    parser.add_argument("--java", help="Absolute path to a Java 17+ executable")
    parser.add_argument("--allow-writes", action="store_true",
                        help="Send the plan's state-changing cases (POST, PUT, PATCH, DELETE; a JSON-RPC read needs no flag); only where data may be changed")
    parser.add_argument("--remote", metavar="ORIGIN",
                        help="Test this one https://hostname, a pre-production environment the user named, instead of a loopback port")
    args = parser.parse_args()
    if args.check:
        ready = False
        if args.zap_archive:
            verify_archive(args.zap_archive)
            ready = bool(args.java and Path(args.java).is_absolute() and Path(args.java).is_file() and os.access(args.java, os.X_OK))
        print(json.dumps({"status": "ready-for-run" if ready else "needs-setup", "zap_version": VERSION,
                          "java_runtime_verified": False, "network_used": False}))
        return 0 if ready else 2
    if not args.plan or not (args.zap_archive or args.http_only):
        parser.error("Supply a plan and either --zap-archive or --http-only")
    if args.plan.stat().st_size > 256 * 1024:
        parser.error("Plan exceeds 256 KiB")
    plan = json.loads(args.plan.read_text())
    cases = plan.get("cases") if isinstance(plan, dict) else None
    if not args.allow_writes and isinstance(cases, list) and any(isinstance(c, dict) and changes_state(c) for c in cases):
        parser.error("The plan holds state-changing cases; they run only with --allow-writes")
    directory, report = run(plan, args.zap_archive, args.java, args.allow_writes, args.remote)
    print(json.dumps({"status": report["status"], "report": str(directory / "report.json"), "review": str(directory / "review.md")}))
    return {"no-candidates": 0, "candidates": 1, "incomplete": 2}[report["status"]]


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, RecursionError, zipfile.BadZipFile):
        print(json.dumps({"status": "incomplete", "error": "Invalid plan, archive or runtime. See the skill's setup and plan reference."}))
        sys.exit(2)

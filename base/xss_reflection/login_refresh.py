import http.cookiejar
import json
import os
import re
import subprocess
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

from .integration.cgi_runner import CGIRunner


def refresh_xss_login(
    work_dir: str,
    config_path: Optional[str],
    log_path: Optional[str] = None,
) -> Dict[str, str]:
    log_path = log_path or os.path.join(work_dir, "xss_reflection.log")
    cfg = _load_config(config_path)
    loginconfig = cfg.get("direct") if isinstance(cfg, dict) else {}
    if not isinstance(loginconfig, dict):
        return {}
    login_url = str(loginconfig.get("url", "") or "").strip()
    if not login_url or login_url == "NO_LOGIN":
        return {}

    base_env, script_path = _load_fuzz_env(work_dir)
    if script_path:
        _log(log_path, "Witcher-XSS refresh_login using fuzz script %s" % script_path)
    else:
        _log(log_path, "Witcher-XSS refresh_login without fuzz script env")

    try:
        auth_env = _get_login_env(work_dir, loginconfig, base_env)
    except Exception as ex:
        _log(log_path, "Witcher-XSS refresh_login_failed: %s" % ex)
        return {}

    _write_auth_snapshot(work_dir, auth_env, source="xss_fresh_login")
    login_cookie = str(auth_env.get("LOGIN_COOKIE", "") or "").strip()
    session_name, session_value = _extract_session_cookie(login_cookie, loginconfig)
    if session_name and session_value:
        _log(log_path, "Witcher-XSS refresh_login_ok session_cookie=%s" % session_name)
    else:
        _log(log_path, "Witcher-XSS refresh_login_ok")
    return {
        "LOGIN_COOKIE": login_cookie,
        "session_cookie_name": session_name,
        "session_cookie_value": session_value,
    }


def _load_config(config_path: Optional[str]) -> Dict:
    path = str(config_path or "").strip()
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as rf:
            data = json.load(rf)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_fuzz_env(work_dir: str) -> Tuple[Dict[str, str], Optional[str]]:
    runner = CGIRunner(work_dir)
    script_path = runner.find_script()
    if not script_path:
        return os.environ.copy(), None
    try:
        env, _ = runner.parse_script(script_path)
        return env, script_path
    except Exception:
        return os.environ.copy(), script_path


def _get_login_env(work_dir: str, loginconfig: Dict, base_env: Dict[str, str]) -> Dict[str, str]:
    authdata = None
    last_error = ""
    for _ in range(0, 10):
        try:
            if _should_use_http_login(loginconfig):
                authdata = _do_http_req_login(loginconfig)
                if authdata:
                    _do_authorized_requests(loginconfig, authdata)
            else:
                authdata = _do_local_cgi_req_login(loginconfig, base_env)
            if authdata:
                break
        except Exception as ex:
            last_error = str(ex)
        time.sleep(0.5)
    if not authdata:
        raise ValueError(last_error or "login failed to return authenticated cookie/bearer value")
    auth_env = dict(base_env or {})
    for auth_name, auth_value in authdata:
        auth_env[str(auth_name)] = str(auth_value)
    auth_env.setdefault("MANDATORY_COOKIE", str(auth_env.get("MANDATORY_COOKIE", "") or ""))
    auth_env.setdefault("MANDATORY_GET", str(auth_env.get("MANDATORY_GET", "") or ""))
    auth_env.setdefault("MANDATORY_POST", str(auth_env.get("MANDATORY_POST", "") or ""))
    return auth_env


def _do_local_cgi_req_login(loginconfig: Dict, base_env: Dict[str, str]) -> List[Tuple[str, str]]:
    cgi_bin = str(loginconfig.get("cgiBinary", "") or "").strip()
    if not cgi_bin:
        raise ValueError("cgiBinary missing in login config")

    env = dict(base_env or {})
    env.pop("AFL_BASE", None)
    env["METHOD"] = str(loginconfig.get("method", "GET") or "GET")

    login_script_filename, login_get_in_url = _split_cgi_url(loginconfig.get("url", ""))
    if not login_script_filename:
        raise ValueError("login url missing for cgi login")
    env["SCRIPT_FILENAME"] = login_script_filename
    env["SCRIPT_NAME"] = login_script_filename
    if env["SCRIPT_NAME"].startswith("/app"):
        env["SCRIPT_NAME"] = env["SCRIPT_NAME"].replace("/app", "")

    extra_form_data = ""
    cookie_data = str(loginconfig.get("cookieData", "") or "")
    pre_login_url = str(loginconfig.get("pre_login", "") or loginconfig.get("preLoginPage", "") or "")
    if pre_login_url:
        pre_env = dict(env)
        pre_script_filename, pre_login_get = _split_cgi_url(pre_login_url)
        pre_env["SCRIPT_FILENAME"] = pre_script_filename
        pre_env["SCRIPT_NAME"] = pre_script_filename
        if pre_env["SCRIPT_NAME"].startswith("/app"):
            pre_env["SCRIPT_NAME"] = pre_env["SCRIPT_NAME"].replace("/app", "")
        pre_env["METHOD"] = "GET"
        pre_stdout, _ = _run_cgi(
            cgi_bin,
            pre_env,
            ("%s\x00%s\x00\x00" % (cookie_data, pre_login_get)).encode("utf-8", errors="replace"),
        )
        pre_text = pre_stdout.decode("latin-1", errors="replace")
        pre_headers, _ = _parse_cgi_login_response(pre_text)
        set_cookies = []
        for header_name, header_value in pre_headers:
            if str(header_name).lower() == "set-cookie":
                set_cookies.append(header_value)
        normalized = _normalize_set_cookie_values(set_cookies)
        if normalized:
            cookie_data = normalized
        match = re.search(r"(formid).*([a-f0-9]{32})", pre_text)
        if match:
            extra_form_data = "%s=%s" % (match.group(1), match.group(2))

    get_data = _merge_query_strings(login_get_in_url, loginconfig.get("getData", ""))
    post_data = str(loginconfig.get("postData", "") or "")
    if len(get_data) > len(post_data):
        if extra_form_data:
            get_data += "&" + extra_form_data
    elif extra_form_data:
        post_data += "&" + extra_form_data

    stdout, _ = _run_cgi(
        cgi_bin,
        env,
        ("%s\x00%s\x00%s\x00" % (cookie_data, get_data, post_data)).encode("utf-8", errors="replace"),
    )
    text = stdout.decode("latin-1", errors="replace")
    headers, body = _parse_cgi_login_response(text)
    login_set_cookies = []
    for header_name, header_value in headers:
        if str(header_name).lower() == "set-cookie":
            login_set_cookies.append(header_value)
    merged_cookie = _merge_cookie_headers(cookie_data, _normalize_set_cookie_values(login_set_cookies))
    if not _check_for_authorized_response(body, headers, loginconfig):
        raise ValueError("failed to get authorization")
    if merged_cookie:
        return [("LOGIN_COOKIE", merged_cookie)]
    return _extract_authdata(headers)


def _run_cgi(cgi_bin: str, env: Dict[str, str], payload: bytes) -> Tuple[bytes, bytes]:
    close_fds = os.name != "nt"
    proc = subprocess.Popen(
        [cgi_bin],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        close_fds=close_fds,
    )
    return proc.communicate(input=payload)


def _parse_cgi_login_response(text: str) -> Tuple[List[Tuple[str, str]], str]:
    headers = []
    body_lines = []
    in_body = False
    extra_wait = False
    for raw in str(text or "").splitlines():
        line = raw.rstrip("\r\n")
        if "@@@@@@@@@@@@@@" in line:
            extra_wait = True
        if line == "":
            if extra_wait:
                extra_wait = False
                continue
            in_body = True
            continue
        if in_body:
            body_lines.append(raw)
            continue
        if ":" in line:
            header_name, header_value = line.split(":", 1)
            headers.append((header_name.strip(), header_value.lstrip()))
    return headers, "\n".join(body_lines)


def _do_http_req_login(loginconfig: Dict) -> List[Tuple[str, str]]:
    url = str(loginconfig.get("url", "") or "").replace("@@PORT_INCREMENT@@", "18080")
    pre_login_url = str(loginconfig.get("pre_login", "") or loginconfig.get("preLoginPage", "") or "")
    pre_login_url = pre_login_url.replace("@@PORT_INCREMENT@@", "18080")

    if (not _is_http_url(url)) and _is_http_url(pre_login_url):
        try:
            from urllib.parse import urljoin, urlparse

            parsed = urlparse(pre_login_url)
            origin = "%s://%s" % (parsed.scheme, parsed.netloc)
            url = urljoin(origin + "/", url.lstrip("/"))
        except Exception:
            pass

    get_data = str(loginconfig.get("getData", "") or "")
    if get_data:
        url += ("&" if "?" in url else "?") + get_data

    post_data = str(loginconfig.get("postData", "") or "").encode("ascii")
    req_headers = dict(loginconfig.get("headers", {}) or {})
    method = str(loginconfig.get("method", "GET") or "GET")
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar), NoRedirection)
    urllib.request.install_opener(opener)

    if pre_login_url:
        pre_req = urllib.request.Request(pre_login_url, method="GET")
        urllib.request.urlopen(pre_req)

    req = urllib.request.Request(url, post_data, req_headers, method=method)
    response = urllib.request.urlopen(req)
    headers = response.getheaders()
    body = response.read()
    if not _check_for_authorized_response(body, headers, loginconfig):
        raise ValueError("failed to get authorization")
    return _extract_authdata(headers)


def _do_authorized_requests(loginconfig: Dict, authdata: List[Tuple[str, str]]) -> None:
    extra_requests = loginconfig.get("extra_authorized_requests", []) or []
    for auth_request in extra_requests:
        if not isinstance(auth_request, dict):
            continue
        url = str(auth_request.get("url", "") or "").strip()
        if not url:
            continue
        get_data = str(auth_request.get("getData", "") or "")
        if get_data:
            url += ("&" if "?" in url else "?") + get_data
        post_data = str(auth_request.get("postData", "") or "").encode("ascii")
        req_headers = dict(auth_request.get("headers", {}) or {})
        for auth_name, auth_value in authdata:
            req_headers[str(auth_name).replace("LOGIN_COOKIE", "Cookie")] = auth_value
        req = urllib.request.Request(url, post_data, req_headers)
        urllib.request.urlopen(req)


def _extract_authdata(headers: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    authdata = []
    login_auth_cookies = []
    for header_name, header_value in headers:
        upper_name = str(header_name or "").upper()
        if upper_name == "SET-COOKIE":
            login_auth_cookies.append(header_value)
        elif upper_name == "AUTHORIZATION":
            authdata.append((header_name, header_value))
    normalized_cookie = _normalize_set_cookie_values(login_auth_cookies)
    if normalized_cookie:
        authdata.insert(0, ("LOGIN_COOKIE", normalized_cookie))
    return authdata


def _extract_session_cookie(login_cookie: str, loginconfig: Dict) -> Tuple[str, str]:
    session_cookie_name = str((loginconfig or {}).get("loginSessionCookie", "") or "").strip()
    if not session_cookie_name:
        return "", ""
    cookie_map = _cookie_map_from_cookie_header(login_cookie)
    for cookie_name, cookie_value in cookie_map.items():
        if str(cookie_name or "").strip().lower() == session_cookie_name.lower():
            return cookie_name, str(cookie_value)
    return "", ""


def _write_auth_snapshot(work_dir: str, env_obj: Dict[str, str], source: str = "") -> None:
    path = os.path.join(work_dir, "symex_runtime", "meta", "auth_snapshot.json")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        return
    prev = {}
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as rf:
                data = json.load(rf)
            if isinstance(data, dict):
                prev = data
    except Exception:
        prev = {}
    payload = {
        "source": source or "",
        "updated_at": int(time.time()),
        "LOGIN_COOKIE": str(env_obj.get("LOGIN_COOKIE", "") or ""),
        "MANDATORY_COOKIE": str(env_obj.get("MANDATORY_COOKIE", "") or ""),
        "MANDATORY_GET": str(env_obj.get("MANDATORY_GET", "") or ""),
        "MANDATORY_POST": str(env_obj.get("MANDATORY_POST", "") or ""),
        "AUTHORIZATION": str(env_obj.get("AUTHORIZATION", "") or ""),
        "HTTP_AUTHORIZATION": str(env_obj.get("HTTP_AUTHORIZATION", "") or ""),
    }
    for key in (
        "LOGIN_COOKIE",
        "MANDATORY_COOKIE",
        "MANDATORY_GET",
        "MANDATORY_POST",
        "AUTHORIZATION",
        "HTTP_AUTHORIZATION",
    ):
        if payload.get(key):
            continue
        if prev.get(key):
            payload[key] = str(prev.get(key) or "")
    try:
        with open(path, "w", encoding="utf-8") as wf:
            json.dump(payload, wf, ensure_ascii=False, indent=2)
    except Exception:
        return


def _iter_positive_headers(loginconfig: Dict) -> List[Tuple[str, str]]:
    out = []
    positive_headers = (loginconfig or {}).get("positiveHeaders", [])
    if isinstance(positive_headers, dict):
        return list(positive_headers.items())
    if isinstance(positive_headers, list):
        for item in positive_headers:
            if isinstance(item, dict):
                out.extend(list(item.items()))
    return out


def _check_for_authorized_response(body, headers, loginconfig: Dict) -> bool:
    return _check_body(body, loginconfig) and _check_headers(headers, loginconfig)


def _check_body(body, loginconfig: Dict) -> bool:
    try:
        body = body.decode()
    except Exception:
        pass
    positive_body = str((loginconfig or {}).get("positiveBody", "") or "")
    if len(positive_body) > 1:
        return re.compile(positive_body).search(str(body)) is not None
    return True


def _check_headers(headers, loginconfig: Dict) -> bool:
    for pos_name, pos_value in _iter_positive_headers(loginconfig):
        found = False
        for header_name, header_value in headers:
            if pos_name == header_name and str(pos_value) in str(header_value):
                found = True
                break
        if not found:
            return False
    return True


def _normalize_set_cookie_values(cookie_values: List[str]) -> str:
    values = []
    for raw in cookie_values or []:
        cookie = _cookie_name_value_only(raw)
        if cookie:
            values.append(cookie)
    return "; ".join(values)


def _cookie_name_value_only(cookie_value: str) -> str:
    first = str(cookie_value or "").strip().split(";", 1)[0].strip()
    if "=" not in first:
        return ""
    return first


def _cookie_map_from_cookie_header(cookie_header: str) -> Dict[str, str]:
    raw_cookie = str(cookie_header or "").strip()
    if not raw_cookie:
        return {}
    ignore = {"path", "expires", "max-age", "domain", "secure", "httponly", "samesite", "priority"}
    out = {}
    for part in raw_cookie.split(";"):
        piece = str(part or "").strip()
        if not piece or "=" not in piece:
            continue
        key, value = piece.split("=", 1)
        key = str(key or "").strip()
        value = str(value or "").strip()
        if not key or key.lower() in ignore:
            continue
        out[key] = value
    return out


def _cookie_map_to_header(cookie_map: Dict[str, str]) -> str:
    parts = []
    for key, value in (cookie_map or {}).items():
        name = str(key or "").strip()
        if not name:
            continue
        parts.append("%s=%s" % (name, "" if value is None else str(value)))
    return "; ".join(parts)


def _merge_cookie_headers(pre_cookie: str, login_cookie: str) -> str:
    merged = _cookie_map_from_cookie_header(pre_cookie)
    merged.update(_cookie_map_from_cookie_header(login_cookie))
    return _cookie_map_to_header(merged)


def _split_cgi_url(url_or_path: str) -> Tuple[str, str]:
    raw = str(url_or_path or "").strip()
    if not raw:
        return "", ""
    if raw.startswith("http://") or raw.startswith("https://"):
        from urllib.parse import urlparse

        parsed = urlparse(raw)
        return parsed.path or "", parsed.query or ""
    if "?" in raw:
        path, query = raw.split("?", 1)
        return path.strip(), query.strip()
    return raw, ""


def _merge_query_strings(first: str, second: str) -> str:
    left = str(first or "").strip().lstrip("?")
    right = str(second or "").strip().lstrip("?")
    if left and right:
        return left + "&" + right
    return left or right


def _should_use_http_login(loginconfig: Dict) -> bool:
    url = str((loginconfig or {}).get("url", "") or "")
    pre = str((loginconfig or {}).get("pre_login", "") or (loginconfig or {}).get("preLoginPage", "") or "")
    return _is_http_url(url) or _is_http_url(pre)


def _is_http_url(raw: str) -> bool:
    value = str(raw or "").strip().lower()
    return value.startswith("http://") or value.startswith("https://")


def _log(log_path: str, message: str) -> None:
    try:
        with open(log_path, "a", encoding="utf-8") as wf:
            wf.write(message + "\n")
    except Exception:
        return


class NoRedirection(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response

    https_response = http_response

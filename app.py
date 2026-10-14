from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import socket
import ssl
from datetime import datetime, timedelta, timezone
from functools import wraps
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import ParseResult, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "brandshield.sqlite3"
REQUIRED_TABLES = ("cases", "report_history", "app_meta")
STATUSES = {"New", "Under Review", "Confirmed", "False Positive"}
PLATFORMS = {
    "Instagram", "Facebook", "TikTok", "X / Twitter", "LinkedIn",
    "YouTube", "Website", "Google Play", "Apple App Store", "Other",
}
MOBILE_APP_PLATFORMS = {"Google Play", "Apple App Store"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "linktr.ee"}
WEBSITE_CHECK_TIMEOUT = 5
WEBSITE_CHECK_MAX_REDIRECTS = 3
WEBSITE_CHECK_MAX_BYTES = 64 * 1024
SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_TIMEOUT = 8
SAFE_BROWSING_MAX_RESPONSE_BYTES = 64 * 1024
SAFE_BROWSING_THREAT_TYPES = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
)
SUSPICIOUS_LANGUAGE = re.compile(
    r"\b(scam|phish(?:ing)?|credential harvest|urgent|act now|limited time|"
    r"giveaway|free gift|claim your|verify your|password|payment|crypto|wallet)\b",
    re.IGNORECASE,
)
IMPERSONATION_LANGUAGE = re.compile(
    r"\b(fake|clone|counterfeit|unofficial|unverified|impersonat\w*|lookalike|"
    r"publisher mismatch|sideload)\b",
    re.IGNORECASE,
)

app = Flask(__name__, static_folder=None, template_folder=str(BASE_DIR))
app.config.update(
    SECRET_KEY=os.environ.get("BRANDSHIELD_SECRET_KEY") or secrets.token_hex(32),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
DEMO_USERNAME = os.environ.get("BRANDSHIELD_DEMO_USERNAME") or "analyst"
DEMO_PASSWORD = os.environ.get("BRANDSHIELD_DEMO_PASSWORD") or "shield-demo"


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        del _args, _kwargs
        return None


def _open_safe_browsing(request: Request):
    return build_opener(_NoRedirectHandler()).open(request, timeout=SAFE_BROWSING_TIMEOUT)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify(error="Sign in to access BrandShield AI."), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


def valid_csrf_token() -> bool:
    expected = session.get("csrf_token")
    provided = request.form.get("csrf_token", "")
    return isinstance(expected, str) and hmac.compare_digest(expected, provided)


def new_csrf_token() -> str:
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def check_google_safe_browsing(url: str, api_key: str) -> dict:
    request_body = {
        "client": {
            "clientId": "brandshield-ai-demo",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": list(SAFE_BROWSING_THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    api_url = f"{SAFE_BROWSING_ENDPOINT}?{urlencode({'key': api_key})}"
    google_request = Request(
        api_url,
        data=json.dumps(request_body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with _open_safe_browsing(google_request) as response:
            response_body = response.read(SAFE_BROWSING_MAX_RESPONSE_BYTES + 1)
            if len(response_body) > SAFE_BROWSING_MAX_RESPONSE_BYTES:
                raise RuntimeError("Google Safe Browsing returned an oversized response.")
    except HTTPError as error:
        error.close()
        raise RuntimeError("Google Safe Browsing rejected the request. Check the API key and quota.") from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("Google Safe Browsing could not be reached. Please retry.") from None

    try:
        payload = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("Google Safe Browsing returned an unreadable response.") from None
    if not isinstance(payload, dict):
        raise RuntimeError("Google Safe Browsing returned an unexpected response.")

    matches = payload.get("matches", [])
    if not isinstance(matches, list):
        raise RuntimeError("Google Safe Browsing returned an unexpected response.")
    threat_types = []
    for match in matches:
        if not isinstance(match, dict) or not isinstance(match.get("threatType"), str):
            raise RuntimeError("Google Safe Browsing returned an unexpected response.")
        threat_types.append(match["threatType"])
    return {
        "provider": "Google Safe Browsing",
        "verdict": "known_threat" if matches else "no_match",
        "threatTypes": sorted(set(threat_types)),
        "checkedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


class _PageTitleParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        super().handle_starttag(tag, _attrs)
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title and len("".join(self.parts)) < 200:
            self.parts.append(data)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int):
        super().__init__(host, port, timeout=WEBSITE_CHECK_TIMEOUT)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self.address, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int):
        super().__init__(
            host,
            port,
            timeout=WEBSITE_CHECK_TIMEOUT,
            context=ssl.create_default_context(),
        )
        self.address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self.address, self.port), self.timeout, self.source_address
        )
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _resolve_public_website(url: str) -> tuple[ParseResult, str, int, str]:
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as error:
        raise ValueError("The website URL or port is invalid.") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or any(character.isspace() for character in url)
    ):
        raise ValueError("Only public http:// and https:// website URLs can be checked.")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError as error:
        raise ValueError("The website hostname is invalid.") from error
    port = port or (443 if parsed.scheme == "https" else 80)
    expected_port = 443 if parsed.scheme == "https" else 80
    if port != expected_port:
        raise ValueError("Website checks only allow standard HTTP and HTTPS ports.")
    try:
        addresses = {
            ipaddress.ip_address(record[4][0])
            for record in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as error:
        raise ValueError("The website host could not be resolved.") from error
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("For safety, only publicly routable website hosts can be checked.")
    return parsed, hostname, port, str(next(iter(addresses)))


def check_public_website(url: str) -> dict:
    current_url = url
    visited = set()
    for redirect_count in range(WEBSITE_CHECK_MAX_REDIRECTS + 1):
        parsed, hostname, port, address = _resolve_public_website(current_url)
        if current_url in visited:
            raise ValueError("The website returned a redirect loop.")
        visited.add(current_url)

        connection_class = (
            _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
        )
        connection = connection_class(hostname, address, port)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host_header = f"[{hostname}]" if ":" in hostname else hostname
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": host_header,
                    "User-Agent": "BrandShield-Manual-Website-Check/1.0",
                    "Accept": "text/html",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            status_code = response.status
            location = response.getheader("Location")
            content_type = response.getheader("Content-Type", "")
            if status_code in {301, 302, 303, 307, 308} and location:
                if redirect_count == WEBSITE_CHECK_MAX_REDIRECTS:
                    raise ValueError("The website redirected too many times.")
                current_url = urljoin(current_url, location)
                continue

            title = ""
            if "text/html" in content_type.lower():
                raw_content = response.read(WEBSITE_CHECK_MAX_BYTES)
                parser = _PageTitleParser()
                parser.feed(raw_content.decode("utf-8", errors="replace"))
                title = re.sub(r"\s+", " ", "".join(parser.parts)).strip()[:200]
            return {
                "statusCode": status_code,
                "reachable": 200 <= status_code < 400,
                "contentType": content_type[:120],
                "title": title,
                "checkedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        finally:
            connection.close()
    raise ValueError("The website redirected too many times.")


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def insert_demo_cases(connection: sqlite3.Connection) -> None:
    connection.executemany(
        """
        INSERT OR IGNORE INTO cases
            (id, brand, url, platform, observations, indicators_json, status, created_at, demo)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        [
            (
                "BS-1042",
                "Northstar Outfitters",
                "https://northstar-outlet.example.com/claim",
                "Instagram",
                "Profile uses a similar brand name and promotes a limited-time giveaway. This is sample demo content, not a verified report.",
                json.dumps(["spring-campaign-42"]),
                "Under Review",
                "2026-10-12T10:20:00+00:00",
            ),
            (
                "BS-1041",
                "Verde Skincare",
                "https://social.example.net/verde.skin.official",
                "TikTok",
                "The profile requests payment through an external link. This is sample demo content, not a verified report.",
                json.dumps(["promo-link-17"]),
                "New",
                "2026-10-11T08:45:00+00:00",
            ),
            (
                "BS-1040",
                "Northstar Outfitters",
                "https://northstar-outlet.example.com/support",
                "Website",
                "A second sample URL on the same domain. Domain similarity alone does not create a case link.",
                json.dumps(["spring-campaign-42"]),
                "Confirmed",
                "2026-10-09T14:10:00+00:00",
            ),
            (
                "BS-1043",
                "Verde Skincare",
                "https://social.example.net/brand_help_247/",
                "Instagram",
                "Sample scam account impersonates the brand and asks users to pay a delivery fee to claim a giveaway. Simulated example, not a verified report.",
                json.dumps(["promo-link-17"]),
                "New",
                "2026-10-08T12:30:00+00:00",
            ),
            (
                "BS-1044",
                "Northstar Outfitters",
                "https://play.google.com/store/apps/details?id=com.example.northstar.rewards",
                "Google Play",
                "Sample suspicious mobile app uses an unofficial brand rewards name and requests payment details. Simulated listing, not a verified report.",
                json.dumps(["northstar-rewards-app"]),
                "Under Review",
                "2026-10-07T09:15:00+00:00",
            ),
            (
                "BS-1045",
                "Verde Skincare",
                "https://apps.apple.com/us/app/verde-official-rewards/id000000001",
                "Apple App Store",
                "Sample app listing claims to be the official rewards app, but its publisher is unverified. Simulated listing, not a verified report.",
                json.dumps(["verde-rewards-app"]),
                "New",
                "2026-10-06T11:05:00+00:00",
            ),
            (
                "BS-1046",
                "Finish Line",
                "https://finishline-outlet.example.com/store/boost-nmd",
                "Website",
                "Shoes, Clothing & Accessories / Boost, NMD, Stan Smith | Finish Line counterfeit clone shop with logo drift, lookalike brand assets, and unauthorized checkout.",
                json.dumps(["boost-campaign-2021", "finishline-lookalike", "msx.cexecalnk.net"]),
                "Under Review",
                "2026-10-14T07:38:00+00:00",
            ),
        ],
    )


def initialize_database() -> None:
    with connect_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                brand TEXT NOT NULL,
                url TEXT NOT NULL,
                platform TEXT NOT NULL,
                observations TEXT NOT NULL DEFAULT '',
                indicators_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'New',
                created_at TEXT NOT NULL,
                demo INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS report_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                content TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);
            CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON report_history(generated_at);
            """
        )
        seeded = connection.execute(
            "SELECT value FROM app_meta WHERE key = 'demo_seeded'"
        ).fetchone()
        if not seeded:
            existing = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            if existing == 0:
                insert_demo_cases(connection)
            connection.execute(
                "INSERT INTO app_meta (key, value) VALUES ('demo_seeded', '1')"
            )
        insert_demo_cases(connection)
        connection.execute(
            "INSERT OR IGNORE INTO app_meta (key, value) VALUES ('digital_risk_samples_v2', '1')"
        )
        sample_url_refresh = connection.execute(
            "SELECT value FROM app_meta WHERE key = 'digital_risk_sample_url_v4'"
        ).fetchone()
        if not sample_url_refresh:
            connection.execute(
                "UPDATE cases SET url = ? WHERE id = ? AND demo = 1",
                ("https://social.example.net/brand_help_247/", "BS-1043"),
            )
            connection.execute(
                "INSERT INTO app_meta (key, value) VALUES ('digital_risk_sample_url_v4', '1')"
            )
        finishline_seed = connection.execute(
            "SELECT value FROM app_meta WHERE key = 'finishline_seed_v1'"
        ).fetchone()
        if not finishline_seed:
            insert_demo_cases(connection)
            connection.execute(
                "INSERT INTO app_meta (key, value) VALUES ('finishline_seed_v1', '1')"
            )


def validate_case(data: object, partial: bool = False) -> tuple[dict | None, str | None]:
    if not isinstance(data, dict):
        return None, "Request body must be a JSON object."

    result: dict = {}
    required_text = {"brand": 80, "url": 500, "platform": 40, "observations": 1200}
    for field, maximum in required_text.items():
        if partial and field not in data:
            continue
        value = data.get(field, "" if field == "observations" else None)
        if not isinstance(value, str):
            return None, f"{field} must be text."
        value = value.strip()
        if field != "observations" and not value:
            return None, f"{field} is required."
        if len(value) > maximum:
            return None, f"{field} must be {maximum} characters or fewer."
        result[field] = value

    if "platform" in result and (
        not isinstance(result["platform"], str) or result["platform"] not in PLATFORMS
    ):
        return None, "Choose a supported platform."
    if "url" in result:
        parsed = urlparse(result["url"])
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or "." not in parsed.hostname
            or any(character.isspace() for character in result["url"])
        ):
            return None, "Enter a valid URL beginning with http:// or https://."
        result["url"] = result["url"][:500]

    if not partial or "indicators" in data:
        indicators = data.get("indicators", [])
        if not isinstance(indicators, list) or len(indicators) > 20:
            return None, "indicators must be a list of at most 20 values."
        clean_indicators = []
        for indicator in indicators:
            if not isinstance(indicator, str) or len(indicator.strip()) > 100:
                return None, "Each indicator must be text of at most 100 characters."
            clean = indicator.strip()
            if clean and clean not in clean_indicators:
                clean_indicators.append(clean)
        result["indicators"] = clean_indicators

    if "status" in data:
        if not isinstance(data["status"], str) or data["status"] not in STATUSES:
            return None, "Choose a valid review status."
        result["status"] = data["status"]
    return result, None


def shared_indicators(left: dict, right: dict) -> list[str]:
    right_values = {value.strip().casefold() for value in right["indicators"] if value.strip()}
    return list(dict.fromkeys(
        value.strip()
        for value in left["indicators"]
        if value.strip() and value.strip().casefold() in right_values
    ))


def risk_for(case: dict, all_cases: list[dict]) -> dict:
    parsed_url = urlparse(case["url"])
    host = (parsed_url.hostname or "").removeprefix("www.").casefold()
    asset_reference = host
    if case["platform"] != "Website":
        asset_reference = f"{host} {parsed_url.path} {parsed_url.query}"
    asset_words = set(re.findall(r"[a-z0-9]+", asset_reference.casefold()))
    brand_words = {
        word for word in re.findall(r"[a-z0-9]+", case["brand"].casefold())
        if len(word) > 2
    }
    reasons = []
    score = 0

    if host in SHORTENERS:
        score += 25
        reasons.append({"points": 25, "text": "URL uses a commonly shortened or redirect-style link (+25)."})
    if host and brand_words and not brand_words.intersection(asset_words):
        score += 20
        reasons.append({
            "points": 20,
            "text": "Brand name is not present in the asset domain, profile handle, or app listing identifier (+20). This is a heuristic, not proof of impersonation.",
        })
    if SUSPICIOUS_LANGUAGE.search(case["observations"]):
        score += 20
        reasons.append({"points": 20, "text": "Notes mention scam, phishing, urgency, prize, credential, or payment language (+20)."})
    if IMPERSONATION_LANGUAGE.search(case["observations"]):
        points = 25 if case["platform"] in MOBILE_APP_PLATFORMS else 20
        score += points
        reasons.append({
            "points": points,
            "text": (
                "App notes mention an unofficial, cloned, or impersonating listing (+25)."
                if case["platform"] in MOBILE_APP_PLATFORMS
                else "Notes mention a fake, cloned, or impersonating profile (+20)."
            ),
        })
    if any(shared_indicators(case, other) for other in all_cases if other["id"] != case["id"]):
        score += 10
        reasons.append({"points": 10, "text": "An explicitly entered indicator exactly matches another case (+10)."})
    if case["url"].casefold().startswith("http://"):
        score += 10
        reasons.append({"points": 10, "text": "URL uses unencrypted HTTP rather than HTTPS (+10)."})
    if not reasons:
        score = 5
        reasons.append({
            "points": 5,
            "text": "No listed demo-rule signals were detected; this does not establish that the profile is safe (+5 baseline).",
        })

    value = min(score, 100)
    level = "high" if value >= 70 else "medium" if value >= 40 else "low"
    recommendation = (
        "Prioritize manual review. The rule signals are stronger, but do not establish wrongdoing."
        if value >= 70
        else "Review the URL and observations in context before deciding whether further action is needed."
        if value >= 40
        else "No strong demo-rule signals were found. Review normally; a low score is not a safety guarantee."
    )
    return {"value": value, "level": level, "reasons": reasons, "recommendation": recommendation}


def get_cases(connection: sqlite3.Connection) -> list[dict]:
    rows = connection.execute("SELECT * FROM cases ORDER BY created_at DESC, id DESC").fetchall()
    return [
        {
            "id": row["id"],
            "brand": row["brand"],
            "url": row["url"],
            "platform": row["platform"],
            "observations": row["observations"],
            "indicators": json.loads(row["indicators_json"]),
            "status": row["status"],
            "createdAt": row["created_at"],
            "demo": bool(row["demo"]),
        }
        for row in rows
    ]


def serialize_cases(connection: sqlite3.Connection) -> list[dict]:
    cases = get_cases(connection)
    for case in cases:
        case["risk"] = risk_for(case, cases)
    return cases


def dashboard_analytics(connection: sqlite3.Connection) -> dict:
    cases = serialize_cases(connection)
    risk_distribution = {"Low": 0, "Medium": 0, "High": 0}
    status_distribution = {status: 0 for status in STATUSES}
    platform_distribution: dict[str, int] = {}
    for case in cases:
        risk_distribution[case["risk"]["level"].title()] += 1
        status_distribution[case["status"]] += 1
        platform = case["platform"]
        platform_distribution[platform] = platform_distribution.get(platform, 0) + 1

    relationships = []
    adjacency = {case["id"]: set() for case in cases}
    for index, case in enumerate(cases):
        for other in cases[index + 1:]:
            indicators = shared_indicators(case, other)
            if indicators:
                relationships.append({
                    "source": case["id"],
                    "target": other["id"],
                    "indicators": indicators,
                })
                adjacency[case["id"]].add(other["id"])
                adjacency[other["id"]].add(case["id"])

    remaining = set(adjacency)
    related_clusters = 0
    while remaining:
        stack = [remaining.pop()]
        cluster_size = 0
        while stack:
            current = stack.pop()
            cluster_size += 1
            connected = adjacency[current] & remaining
            remaining.difference_update(connected)
            stack.extend(connected)
        if cluster_size > 1:
            related_clusters += 1

    report_count = connection.execute(
        "SELECT COUNT(*) FROM report_history"
    ).fetchone()[0]
    return {
        "summary": {
            "totalCases": len(cases),
            "openCases": sum(
                1 for case in cases if case["status"] in {"New", "Under Review"}
            ),
            "highRiskCases": sum(
                1 for case in cases if case["risk"]["value"] >= 70
            ),
            "relatedClusters": related_clusters,
            "reportsReady": report_count,
        },
        "riskDistribution": risk_distribution,
        "statusDistribution": status_distribution,
        "platformDistribution": [
            {"platform": platform, "count": count}
            for platform, count in sorted(
                platform_distribution.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "relationships": relationships,
    }


def report_text(case: dict, risk: dict, related: list[tuple[dict, list[str]]]) -> str:
    lines = [
        "BRANDSHIELD AI — DEMO INVESTIGATION SUMMARY",
        "============================================",
        f"Case: {case['id']}",
        f"Brand: {case['brand']}",
        f"Platform: {case['platform']}",
        f"Profile / app listing URL: {case['url']}",
        f"Status: {case['status']}",
        f"Date added: {case['createdAt']}",
        f"Case type: {'Sample demo data' if case['demo'] else 'User-entered local case'}",
        "",
        f"EXPLAINABLE RISK INDICATOR: {risk['value']}/100 ({risk['level'].title()})",
        "This score is produced by simple backend demo rules. It is an indicator, not proof of fraud.",
        "",
        "CONTRIBUTING RULES",
        *[f"- {reason['text']}" for reason in risk["reasons"]],
        "",
        "REVIEW RECOMMENDATION",
        risk["recommendation"],
        "",
        "EVIDENCE / OBSERVATIONS",
        case["observations"] or "No observations were provided.",
        "",
        "EXPLICITLY ENTERED SHARED INDICATORS",
        *([f"- {value}" for value in case["indicators"]] or ["None provided."]),
        "",
        "RELATED CASES",
        *(
            [f"- {other['id']} · {other['brand']} — linked by explicitly shared indicator: {', '.join(shared)}."
             for other, shared in related]
            or ["No other case has an exact matching shared indicator."]
        ),
        "",
        "LIMITATIONS",
        "The Google Safe Browsing check is an on-demand lookup against its queried threat lists, not a guarantee of safety or a determination of fraud. The submitted URL is sent to Google and Safe Browsing results are not included in this locally generated report.",
        "This simulated local demo does not connect to social networks or app stores, continuously monitor assets, or use a trained AI model. Its explainable scores are heuristic triage indicators, not verified detections.",
        "A website is fetched only after an analyst explicitly requests a manual check. App-store listings are not queried.",
        "Related-case matching uses only explicitly entered indicators that exactly match another case (case-insensitive).",
        "This report is not proof of fraud, a verified finding, or a legal determination.",
        "",
        f"Generated locally: {datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')}",
    ]
    return "\n".join(lines)


@app.errorhandler(sqlite3.Error)
def handle_database_error(error: sqlite3.Error):
    app.logger.exception("SQLite operation failed")
    return jsonify(error="The local database operation failed. Please retry."), 500


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    if request.method == "GET":
        csrf_token = session.get("csrf_token")
        if not isinstance(csrf_token, str):
            csrf_token = new_csrf_token()
        return render_template(
            "login.html",
            csrf_token=csrf_token,
            demo_username=DEMO_USERNAME,
            demo_password=DEMO_PASSWORD,
        )
    if not valid_csrf_token():
        return render_template(
            "login.html",
            csrf_token=new_csrf_token(),
            demo_username=DEMO_USERNAME,
            demo_password=DEMO_PASSWORD,
            error="Your sign-in form expired. Please try again.",
        ), 400

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    username_matches = hmac.compare_digest(username.encode("utf-8"), DEMO_USERNAME.encode("utf-8"))
    password_matches = hmac.compare_digest(password.encode("utf-8"), DEMO_PASSWORD.encode("utf-8"))
    if not (username_matches and password_matches):
        return render_template(
            "login.html",
            csrf_token=new_csrf_token(),
            demo_username=DEMO_USERNAME,
            demo_password=DEMO_PASSWORD,
            error="That demo username or password is not correct.",
        ), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True
    new_csrf_token()
    return redirect(url_for("index"))


@app.post("/logout")
@login_required
def logout():
    if not valid_csrf_token():
        abort(400, description="Your sign-out form expired. Reload the app and try again.")
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    csrf_token = session.get("csrf_token")
    if not isinstance(csrf_token, str):
        csrf_token = new_csrf_token()
    return render_template(
        "index.html",
        csrf_token=csrf_token,
        safe_browsing_configured=bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()),
    )


@app.get("/style.css")
def stylesheet():
    return send_from_directory(BASE_DIR, "style.css")


@app.get("/script.js")
def javascript():
    return send_from_directory(BASE_DIR, "script.js")


@app.get("/api/health")
@login_required
def health():
    with connect_db() as connection:
        connection.execute("SELECT 1").fetchone()
        existing_tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    missing_tables = [table for table in REQUIRED_TABLES if table not in existing_tables]
    if missing_tables:
        return jsonify(
            status="error",
            storage="sqlite",
            database="connected",
            tables="missing",
            missingTables=missing_tables,
            demo=True,
        ), 503
    return jsonify(
        status="ok",
        storage="sqlite",
        database="connected",
        tables="ready",
        demo=True,
    )


@app.get("/api/cases")
@login_required
def list_cases():
    with connect_db() as connection:
        return jsonify(cases=serialize_cases(connection))


@app.get("/api/dashboard")
@login_required
def dashboard():
    with connect_db() as connection:
        return jsonify(dashboard_analytics(connection))


@app.post("/api/cases")
@login_required
def create_case():
    data, error = validate_case(request.get_json(silent=True))
    if error:
        return jsonify(error=error), 400
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with connect_db() as connection:
        rows = connection.execute("SELECT id FROM cases").fetchall()
        highest = max(
            (int(match.group(1)) for row in rows if (match := re.fullmatch(r"BS-(\d+)", row["id"]))),
            default=1000,
        )
        case_id = f"BS-{highest + 1}"
        connection.execute(
            """
            INSERT INTO cases
                (id, brand, url, platform, observations, indicators_json, status, created_at, demo)
            VALUES (?, ?, ?, ?, ?, ?, 'New', ?, 0)
            """,
            (
                case_id, data["brand"], data["url"], data["platform"],
                data["observations"], json.dumps(data["indicators"]), now,
            ),
        )
        case = next(item for item in serialize_cases(connection) if item["id"] == case_id)
        return jsonify(case=case), 201


@app.get("/api/cases/<case_id>")
@login_required
def view_case(case_id: str):
    with connect_db() as connection:
        all_cases = serialize_cases(connection)
        case = next((item for item in all_cases if item["id"] == case_id), None)
        if case is None:
            return jsonify(error="Investigation not found."), 404
        case["relatedCases"] = [
            {"case": other, "indicators": shared_indicators(case, other)}
            for other in all_cases
            if other["id"] != case_id and shared_indicators(case, other)
        ]
        return jsonify(case=case)


@app.post("/api/cases/<case_id>/website-check")
@login_required
def manual_website_check(case_id: str):
    with connect_db() as connection:
        case = connection.execute(
            "SELECT url, platform FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
    if case is None:
        return jsonify(error="Investigation not found."), 404
    if case["platform"] != "Website":
        return jsonify(error="Manual website checks are available for Website cases only."), 400
    try:
        result = check_public_website(case["url"])
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except (OSError, http.client.HTTPException) as error:
        app.logger.info("Manual website check failed for %s: %s", case_id, error)
        return jsonify(
            error="The website could not be reached within the manual check limits."
        ), 502
    return jsonify(check=result)


@app.post("/api/cases/<case_id>/safe-browsing-check")
@login_required
def manual_safe_browsing_check(case_id: str):
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return jsonify(
            error="Google Safe Browsing is not configured. Set GOOGLE_SAFE_BROWSING_API_KEY on the server and restart it."
        ), 503
    with connect_db() as connection:
        case = connection.execute(
            "SELECT url FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
    if case is None:
        return jsonify(error="Investigation not found."), 404
    try:
        result = check_google_safe_browsing(case["url"], api_key)
    except RuntimeError as error:
        app.logger.warning("Safe Browsing check failed for %s: %s", case_id, error)
        return jsonify(error=str(error)), 502
    return jsonify(check=result)


@app.put("/api/cases/<case_id>")
@login_required
def update_case(case_id: str):
    payload = request.get_json(silent=True)
    data, error = validate_case(payload, partial=True)
    if error:
        return jsonify(error=error), 400
    if not data:
        return jsonify(error="Provide at least one case field to update."), 400
    with connect_db() as connection:
        existing = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if existing is None:
            return jsonify(error="Investigation not found."), 404
        updates = []
        values = []
        for field, value in data.items():
            column = "indicators_json" if field == "indicators" else field
            updates.append(f"{column} = ?")
            values.append(json.dumps(value) if field == "indicators" else value)
        connection.execute(f"UPDATE cases SET {', '.join(updates)} WHERE id = ?", (*values, case_id))
        case = next(item for item in serialize_cases(connection) if item["id"] == case_id)
        return jsonify(case=case)


@app.delete("/api/cases/<case_id>")
@login_required
def delete_case(case_id: str):
    with connect_db() as connection:
        cursor = connection.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        if cursor.rowcount == 0:
            return jsonify(error="Investigation not found."), 404
        return jsonify(message=f"{case_id} deleted.")


@app.post("/api/cases/<case_id>/reports")
@login_required
def create_report(case_id: str):
    with connect_db() as connection:
        cases = get_cases(connection)
        case = next((item for item in cases if item["id"] == case_id), None)
        if case is None:
            return jsonify(error="Investigation not found."), 404
        risk = risk_for(case, cases)
        related = [
            (other, shared_indicators(case, other))
            for other in cases
            if other["id"] != case_id and shared_indicators(case, other)
        ]
        content = report_text(case, risk, related)
        generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cursor = connection.execute(
            "INSERT INTO report_history (case_id, generated_at, content) VALUES (?, ?, ?)",
            (case_id, generated_at, content),
        )
        report_id = cursor.lastrowid
        return jsonify(report={
            "id": report_id, "caseId": case_id, "brand": case["brand"],
            "generatedAt": generated_at, "content": content,
        }), 201


@app.get("/api/reports")
@login_required
def list_reports():
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT r.id, r.case_id, r.generated_at, c.brand
            FROM report_history r JOIN cases c ON c.id = r.case_id
            ORDER BY r.generated_at DESC, r.id DESC
            """
        ).fetchall()
        return jsonify(reports=[
            {"id": row["id"], "caseId": row["case_id"], "brand": row["brand"], "generatedAt": row["generated_at"]}
            for row in rows
        ])


@app.get("/api/reports/<int:report_id>")
@login_required
def view_report(report_id: int):
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT r.id, r.case_id, r.generated_at, r.content, c.brand
            FROM report_history r JOIN cases c ON c.id = r.case_id
            WHERE r.id = ?
            """,
            (report_id,),
        ).fetchone()
        if row is None:
            return jsonify(error="Saved report not found."), 404
        return jsonify(report={
            "id": row["id"], "caseId": row["case_id"], "brand": row["brand"],
            "generatedAt": row["generated_at"], "content": row["content"],
        })


@app.post("/api/reset-demo")
@login_required
def reset_demo():
    with connect_db() as connection:
        connection.execute("DELETE FROM cases")
        insert_demo_cases(connection)
        return jsonify(message="Demo data restored.", cases=serialize_cases(connection))


@app.post("/api/migrate")
@login_required
def migrate_legacy_cases():
    payload = request.get_json(silent=True)
    legacy_cases = payload.get("cases") if isinstance(payload, dict) else None
    if not isinstance(legacy_cases, list) or len(legacy_cases) > 1000:
        return jsonify(error="cases must be a list of at most 1000 items."), 400
    prepared_cases = []
    for old_case in legacy_cases:
        data, error = validate_case(old_case)
        if error:
            return jsonify(error=f"Could not import a saved case: {error}"), 400
        case_id = old_case.get("id") if isinstance(old_case.get("id"), str) else ""
        if not re.fullmatch(r"BS-[A-Za-z0-9-]{1,40}", case_id):
            continue
        status = old_case.get("status", "New")
        if status not in STATUSES:
            status = "New"
        created_at = old_case.get("createdAt")
        if not isinstance(created_at, str) or len(created_at) > 40:
            created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        prepared_cases.append(
            (
                case_id, data["brand"], data["url"], data["platform"], data["observations"],
                json.dumps(data["indicators"]), status, created_at, int(bool(old_case.get("demo"))),
            )
        )

    with connect_db() as connection:
        connection.executemany(
            """
            INSERT INTO cases
                (id, brand, url, platform, observations, indicators_json, status, created_at, demo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                brand=excluded.brand, url=excluded.url, platform=excluded.platform,
                observations=excluded.observations, indicators_json=excluded.indicators_json,
                status=excluded.status, created_at=excluded.created_at, demo=excluded.demo
            """,
            prepared_cases,
        )
    return jsonify(migrated=len(prepared_cases))


initialize_database()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

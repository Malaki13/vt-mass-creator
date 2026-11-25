#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusTotal mass account creator - 100% requests (no browser).

Flow for each account:
  1. random credible identity + logo
  2. temporary inbox (mail.tm) or catch-all IMAP inbox
  3. reCAPTCHA Enterprise solved by 2captcha
  4. POST /ui/signup
  5. activation link read from the inbox -> POST /ui/signup/confirm
  6. sign-in (2captcha v3) -> personal API key
  7. profile picture uploaded to the VT avatar endpoint

Output: accounts.jsonl (one JSON per line) + accounts.csv
Vote mode: cast one vote per saved account on a file hash.

Usage:
  python vt_mass_creator.py --count 5
  python vt_mass_creator.py --count 20 --workers 4 --logo-dir logos
  python vt_mass_creator.py --mode vote --hash <sha256> --verdict harmless
"""

from __future__ import annotations

import argparse
import base64
import csv
import email as email_lib
import imaplib
import json
import mimetypes
import os
import random
import re
import shutil
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Constants (extracted from the live VirusTotal GUI)
# ---------------------------------------------------------------------------

VT_BASE = "https://www.virustotal.com"
TWO_CAPTCHA_API = "https://api.2captcha.com"

# Not versioned: pass --captcha-key or export CAPTCHA_API_KEY.
DEFAULT_CAPTCHA_KEY = os.getenv("CAPTCHA_API_KEY", "")

# reCAPTCHA keys used by the VirusTotal signup form.
SIGNUP_SITEKEY = "6Le-FTYqAAAAAKhTKMsdty7T9sOWkICH4UvIGUzp"
LOGIN_SITEKEY = "6LdawOwtAAAAAEJuyEXijrVsxVKwqhUS8E1rUkT3"

# The anti-abuse header is base64("<big number>-ZG9udCBiZSBldmls-<unix time>")
ANTI_ABUSE_TAG = "ZG9udCBiZSBldmls"  # "dont be evil"

# Activation tokens are base64url: A-Z a-z 0-9 - _ =. Do not include the
# sentence-ending dot from the email, otherwise VT answers "Invalid token".
ACTIVATION_RE = re.compile(r"/gui/account-activation/([A-Za-z0-9_\-=]+)")
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
]

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}

DICEBEAR_STYLES = ["shapes", "identicon", "rings", "initials"]

# Realistic, ASCII-only names. Mix of US / European / international.
FIRST_NAMES = [
    "James", "Liam", "Noah", "Ethan", "Lucas", "Mason", "Logan", "Oliver",
    "Elijah", "Benjamin", "William", "Henry", "Alexander", "Daniel", "Michael",
    "Matthew", "Samuel", "David", "Joseph", "Owen", "Jack", "Leo", "Nathan",
    "Gabriel", "Adam", "Thomas", "Charles", "Max", "Hugo", "Louis", "Arthur",
    "Jules", "Paul", "Antoine", "Mathis", "Baptiste", "Raphael", "Julien",
    "Romain", "Theo", "Enzo", "Mateo", "Diego", "Javier", "Carlos", "Miguel",
    "Alejandro", "Pablo", "Andres", "Sergio", "Marco", "Luca", "Matteo",
    "Lorenzo", "Alessandro", "Davide", "Andrea", "Felix", "Jonas", "Leon",
    "Erik", "Lars", "Nils", "Emil", "Oscar", "Axel", "Viktor", "Ivan",
    "Nikola", "Dmitri", "Andrei", "Mikhail", "Tomas", "Jan", "Petr", "Jakub",
    "Kacper", "Piotr", "Sven", "Bjorn", "Rasmus", "Kenji", "Haruto", "Yuki",
    "Hiroshi", "Arjun", "Rohan", "Vikram", "Aditya", "Rahul", "Omar", "Karim",
    "Youssef", "Mehdi", "Amir", "Sami", "Bilal", "Elias", "Nathaniel",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis",
    "Wilson", "Anderson", "Taylor", "Thomas", "Moore", "Martin", "Jackson",
    "Thompson", "White", "Harris", "Clark", "Lewis", "Walker", "Hall",
    "Allen", "Young", "King", "Wright", "Scott", "Green", "Baker", "Adams",
    "Nelson", "Carter", "Mitchell", "Roberts", "Turner", "Phillips",
    "Campbell", "Parker", "Evans", "Edwards", "Collins", "Stewart", "Morris",
    "Murphy", "Cook", "Rogers", "Morgan", "Peterson", "Cooper", "Reed",
    "Bailey", "Bell", "Kelly", "Howard", "Ward", "Cox", "Diaz", "Richardson",
    "Wood", "Watson", "Brooks", "Bennett", "Gray", "James", "Reyes", "Cruz",
    "Hughes", "Price", "Myers", "Long", "Foster", "Sanders", "Ross", "Powell",
    "Sullivan", "Russell", "Ortiz", "Jenkins", "Perry", "Butler", "Barnes",
    "Fisher", "Henderson", "Coleman", "Simmons", "Patterson", "Jordan",
    "Reynolds", "Hamilton", "Graham", "Kim", "Lee", "Park", "Nguyen", "Tran",
    "Patel", "Shah", "Singh", "Kumar", "Rossi", "Russo", "Ferrari",
    "Esposito", "Bianchi", "Romano", "Moreau", "Laurent", "Simon", "Michel",
    "Leroy", "Roux", "Bertrand", "Vincent", "Fournier", "Mercier", "Dupont",
    "Garcia", "Martinez", "Lopez", "Gonzalez", "Perez", "Sanchez", "Ramirez",
    "Torres", "Flores", "Rivera", "Gomez", "Novak", "Kowalski", "Nowak",
    "Wisniewski", "Andersson", "Johansson", "Karlsson", "Nilsson", "Hansen",
    "Jensen", "Nielsen", "Larsen", "Olsen", "Virtanen", "Korhonen",
    "Makinen", "Petrov", "Ivanov", "Smirnov", "Volkov", "Sokolov", "Popov",
]

PRINT_LOCK = threading.Lock()


def log(message: str) -> None:
    with PRINT_LOCK:
        print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class Config:
    count: int = 5
    workers: int = 3
    captcha_key: str = DEFAULT_CAPTCHA_KEY
    # mailtm-pool: one inbox + unlimited plus-addresses (recommended)
    # mailtm: one inbox per account | imap: catch-all on your own domain
    mail_provider: str = "mailtm-pool"
    mailtm_batch: int = 40
    mail_api: str = "https://api.mail.tm"
    email_domain: str | None = None
    imap_host: str | None = None
    imap_port: int = 993
    imap_user: str | None = None
    imap_pass: str | None = None
    imap_folder: str = "INBOX"
    logo_dir: Path | None = None
    avatars_dir: Path = Path("avatars")
    output: Path = Path("accounts.jsonl")
    csv_output: Path = Path("accounts.csv")
    proxies: list[str] = field(default_factory=list)
    activation_timeout: int = 240
    request_timeout: int = 60
    upload_avatar: bool = True
    delay: float = 0.0
    signup_retries: int = 7
    signin_retries: int = 5
    logo_files: list[Path] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class VTError(RuntimeError):
    pass


class CaptchaError(RuntimeError):
    pass


class MailError(RuntimeError):
    pass


class ActivationTimeout(MailError):
    pass


class DuplicateAccount(VTError):
    pass


# ---------------------------------------------------------------------------
# Identity generation
# ---------------------------------------------------------------------------


def make_password(rng: random.Random) -> str:
    specials = "!@#$%&*?"
    while True:
        chars = [
            rng.choice(string.ascii_uppercase),
            rng.choice(string.ascii_lowercase),
            rng.choice(string.digits),
            rng.choice(specials),
        ]
        chars += [rng.choice(string.ascii_letters + string.digits + specials)
                  for _ in range(10)]
        rng.shuffle(chars)
        password = "".join(chars)
        if (len(password) >= 8
                and re.search(r"[A-Za-z]", password)
                and re.search(r"\d", password)
                and re.search(r"[^A-Za-z0-9]", password)):
            return password


def make_local_part(first: str, last: str, rng: random.Random) -> str:
    # mail.tm rejects overly long local parts (~20 chars max).
    base = re.sub(r"[^a-z]", "", (first + last).lower())[:14]
    return f"{base}{rng.randint(10 ** 4, 10 ** 6 - 1)}"


def make_profile(rng: random.Random, used: set[str], used_lock: threading.Lock) -> dict:
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    with used_lock:
        for _ in range(50):
            username = make_local_part(first, last, rng)
            if username not in used:
                used.add(username)
                break
        else:
            username = f"{first.lower()}{rng.randint(10 ** 7, 10 ** 8 - 1)}"
            used.add(username)
    return {
        "first_name": first,
        "last_name": last,
        "username": username,
        "email_local": make_local_part(first, last, rng),
        "password": make_password(rng),
        "mail_password": "M" + "".join(
            rng.choice(string.ascii_letters + string.digits) for _ in range(15)
        ),
        "ua": rng.choice(UA_POOL),
    }


# ---------------------------------------------------------------------------
# 2captcha
# ---------------------------------------------------------------------------


class TwoCaptcha:
    """Minimal 2captcha JSON API client (createTask / getTaskResult)."""

    def __init__(self, api_key: str, timeout: int = 300, request_timeout: int = 60):
        self.api_key = api_key
        self.timeout = timeout
        self.request_timeout = request_timeout

    def _post(self, path: str, payload: dict) -> dict:
        last_error = None
        for attempt in range(4):
            try:
                response = requests.post(
                    f"{TWO_CAPTCHA_API}/{path}",
                    json=payload,
                    timeout=self.request_timeout,
                )
                if response.status_code >= 500:
                    raise requests.RequestException(f"HTTP {response.status_code}")
                return response.json()
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                time.sleep(3 + attempt * 3)
        raise CaptchaError(f"2captcha {path} failed: {last_error}")

    def solve(self, task: dict) -> str:
        created = self._post("createTask", {"clientKey": self.api_key, "task": task})
        if created.get("errorId"):
            raise CaptchaError(
                f"2captcha createTask: {created.get('errorCode')} "
                f"{created.get('errorDescription', '')}"
            )
        task_id = created["taskId"]
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            time.sleep(5)
            result = self._post(
                "getTaskResult", {"clientKey": self.api_key, "taskId": task_id}
            )
            if result.get("status") == "ready":
                return result["solution"]["gRecaptchaResponse"]
            if result.get("errorId"):
                raise CaptchaError(
                    f"2captcha getTaskResult: {result.get('errorCode')} "
                    f"{result.get('errorDescription', '')}"
                )
        raise CaptchaError("2captcha timeout")

    def _legacy(self, params: dict) -> str:
        """2captcha legacy in.php/res.php API.

        The legacy endpoint forwards `action` to the Enterprise solver much
        more reliably than the JSON createTask endpoint. This is required for
        VirusTotal's signup checkbox (tokens without action are refused).
        """
        payload = {"key": self.api_key, "json": 1, **params}
        last_error = None
        task_id = None
        for attempt in range(4):
            try:
                response = requests.post(
                    "https://2captcha.com/in.php", data=payload,
                    timeout=self.request_timeout,
                )
                data = response.json()
                if data.get("status") == 1:
                    task_id = data["request"]
                    break
                last_error = f"{data.get('request')} (HTTP {response.status_code})"
            except (requests.RequestException, ValueError) as exc:
                last_error = str(exc)
            time.sleep(3 + attempt * 3)
        if not task_id:
            raise CaptchaError(f"2captcha in.php failed: {last_error}")

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            time.sleep(5)
            try:
                response = requests.get(
                    "https://2captcha.com/res.php",
                    params={"key": self.api_key, "action": "get",
                            "id": task_id, "json": 1},
                    timeout=self.request_timeout,
                )
                data = response.json()
            except (requests.RequestException, ValueError) as exc:
                last_error = str(exc)
                continue
            if data.get("status") == 1:
                return data["request"]
            if data.get("request") != "CAPCHA_NOT_READY":
                raise CaptchaError(f"2captcha res.php: {data.get('request')}")
        raise CaptchaError("2captcha timeout")

    def _enterprise_s(self, user_agent: str) -> str | None:
        """Fetch the dynamic `s` payload from the reCAPTCHA Enterprise anchor.

        VirusTotal's checkbox key requires this value for the token to be
        accepted. Without it, 2captcha returns tokens that VT rejects with
        RecaptchaRequiredError even though the solve succeeded.
        """
        origin = base64.b64encode(
            f"{VT_BASE}:443".encode()
        ).decode().rstrip("=")
        url = (
            "https://www.google.com/recaptcha/enterprise/anchor"
            f"?ar=1&k={SIGNUP_SITEKEY}&co={origin}&hl=en&size=normal"
            f"&v={int(time.time() * 1000)}"
        )
        try:
            response = requests.get(
                url, headers={"User-Agent": user_agent},
                timeout=self.request_timeout,
            )
            if response.status_code == 200:
                match = re.search(
                    r'id="recaptcha-token" value="([^"]+)"', response.text
                )
                if match:
                    return match.group(1)
        except requests.RequestException:
            pass
        return None

    def solve_signup(self, user_agent: str) -> str:
        # Legacy API + action=checkbox + data-s is the combination VirusTotal
        # actually accepts. The JSON createTask endpoint does not reliably
        # forward `action`, and without `data-s` the Enterprise score is low.
        params = {
            "method": "userrecaptcha",
            "googlekey": SIGNUP_SITEKEY,
            "pageurl": f"{VT_BASE}/gui/join-us",
            "enterprise": 1,
            "action": "checkbox",
            "useragent": user_agent,
            "domain": "recaptcha.net",
        }
        s_value = self._enterprise_s(user_agent)
        if s_value:
            params["data-s"] = s_value
        return self._legacy(params)

    def solve_login(self, user_agent: str) -> str:
        return self.solve({
            "type": "RecaptchaV3TaskProxyless",
            "websiteURL": f"{VT_BASE}/gui/sign-in",
            "websiteKey": LOGIN_SITEKEY,
            "minScore": 0.3,
            "pageAction": "login",
            "isEnterprise": True,
            "apiDomain": "recaptcha.net",
            "userAgent": user_agent,
        })


# ---------------------------------------------------------------------------
# Temporary inboxes
# ---------------------------------------------------------------------------


class MailTM:
    """mail.tm compatible API (also works with any clone exposing the same API)."""

    def __init__(self, api_base: str, request_timeout: int = 60,
                 min_interval: float = 2.0):
        self.api_base = api_base.rstrip("/")
        self.request_timeout = request_timeout
        self.min_interval = min_interval
        self._rate_lock = threading.Lock()
        self._last_request = 0.0
        self._domains: list[str] | None = None
        self._domains_lock = threading.Lock()

    # -- low level ---------------------------------------------------------
    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.api_base}{path}"
        last_error = None
        for attempt in range(7):
            # mail.tm throttles aggressively per IP; keep all calls under
            # ~1 request/second across threads.
            with self._rate_lock:
                wait = self.min_interval - (time.time() - self._last_request)
                if wait > 0:
                    time.sleep(wait)
                self._last_request = time.time()
            try:
                response = requests.request(
                    method, url, timeout=self.request_timeout, **kwargs
                )
                if response.status_code == 429:
                    wait = min(8 * (attempt + 1), 45) + random.random() * 3
                    log(f"  mail.tm rate limit, retry in {wait:.0f}s")
                    time.sleep(wait)
                    continue
                return response
            except requests.RequestException as exc:
                last_error = exc
                time.sleep(3 + attempt * 3)
        raise MailError(f"mail.tm unreachable: {last_error}")

    # -- domains -----------------------------------------------------------
    def domains(self) -> list[str]:
        with self._domains_lock:
            if self._domains is not None:
                return self._domains
            response = self._request("GET", "/domains")
            if response.status_code != 200:
                raise MailError(f"mail.tm domains HTTP {response.status_code}")
            members = response.json().get("hydra:member", [])
            domains = [
                item["domain"] for item in members
                if item.get("isActive") and not item.get("isPrivate")
            ]
            if not domains:
                raise MailError("mail.tm has no active public domain")
            self._domains = domains
            return domains

    # -- inbox -------------------------------------------------------------
    def create_inbox(self, local_part: str, password: str,
                     domain: str | None = None) -> tuple[str, str]:
        domains = self.domains()
        chosen = domain or random.choice(domains)
        if domain and domain not in domains:
            log(f"  warning: {domain} is not in the mail.tm domain list")
        address = f"{local_part}@{chosen}"
        for attempt in range(4):
            response = self._request(
                "POST", "/accounts",
                json={"address": address, "password": password},
            )
            if response.status_code == 201:
                address = response.json().get("address", address)
                token_response = self._request(
                    "POST", "/token",
                    json={"address": address, "password": password},
                )
                if token_response.status_code != 200:
                    raise MailError(
                        f"mail.tm token HTTP {token_response.status_code}: "
                        f"{token_response.text[:160]}"
                    )
                return address, token_response.json()["token"]
            if response.status_code == 422:
                address = f"{local_part}{random.randint(10, 999)}@{chosen}"
                continue
            raise MailError(
                f"mail.tm account HTTP {response.status_code}: "
                f"{response.text[:160]}"
            )
        raise MailError("mail.tm could not allocate an address")

    # -- messages ----------------------------------------------------------
    def list_messages(self, token: str) -> list[dict]:
        headers = {"Authorization": f"Bearer {token}"}
        messages: list[dict] = []
        for page in range(1, 6):
            response = self._request(
                "GET", f"/messages?page={page}", headers=headers
            )
            if response.status_code != 200:
                break
            data = response.json()
            batch = data.get("hydra:member", []) or []
            messages.extend(batch)
            if not batch or not data.get("hydra:view", {}).get("hydra:next"):
                break
        return messages

    def message_text(self, token: str, message_id: str) -> str:
        response = self._request(
            "GET", f"/messages/{message_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if response.status_code != 200:
            return ""
        data = response.json()
        html = data.get("html") or []
        if isinstance(html, str):
            html = [html]
        return " ".join([data.get("text") or "", *html])

    # -- activation --------------------------------------------------------
    def wait_activation(self, token: str, timeout: int) -> str:
        seen: set[str] = set()
        deadline = time.time() + timeout
        while time.time() < deadline:
            for message in self.list_messages(token):
                message_id = message.get("id")
                if not message_id or message_id in seen:
                    continue
                seen.add(message_id)
                match = ACTIVATION_RE.search(self.message_text(token, message_id))
                if match:
                    return match.group(1)
            time.sleep(5)
        raise ActivationTimeout(
            f"no activation email after {timeout}s "
            "(mail.tm is rate limited or VT did not send it yet)"
        )


@dataclass
class MailBatch:
    address: str
    token: str
    password: str
    count: int = 0
    last_poll: float = 0.0
    seen: set[str] = field(default_factory=set)
    activations: dict[str, str] = field(default_factory=dict)
    poll_lock: threading.Lock = field(default_factory=threading.Lock)


class MailTMPool:
    """One mail.tm inbox, unlimited plus-addresses.

    mail.tm limits inbox *creation*, not delivery. Creating one inbox per
    account is what made the service slow. We create one base inbox, hand out
    `base+username@domain` aliases (all delivered to the base inbox), and map
    each activation token back to its username.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.mail = MailTM(cfg.mail_api, cfg.request_timeout)
        self._alloc_lock = threading.Lock()
        self._batch: MailBatch | None = None

    @staticmethod
    def _username_from_token(token: str) -> str | None:
        raw_token = token.rstrip(".")
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            for pad in range(4):
                try:
                    raw = decoder(raw_token + "=" * pad).decode("utf-8", "ignore")
                except Exception:
                    continue
                if "||" in raw:
                    username = raw.split("||", 1)[0].strip()
                    if username:
                        return username
        return None

    def allocate(self, username: str) -> tuple[str, MailBatch]:
        with self._alloc_lock:
            if self._batch is None or self._batch.count >= self.cfg.mailtm_batch:
                first = random.choice(FIRST_NAMES)
                last = random.choice(LAST_NAMES)
                local = (first + last).lower()[:14] + str(random.randint(10 ** 5, 10 ** 6))
                password = "M" + "".join(
                    random.choice(string.ascii_letters + string.digits)
                    for _ in range(15)
                )
                address, token = self.mail.create_inbox(
                    local, password, self.cfg.email_domain
                )
                self._batch = MailBatch(
                    address=address, token=token, password=password
                )
                log(f"  new mail.tm pool inbox {address} "
                    f"(batch size {self.cfg.mailtm_batch})")
            self._batch.count += 1
            base_local, domain = self._batch.address.split("@", 1)
            return f"{base_local}+{username}@{domain}", self._batch

    def wait_activation(self, batch: MailBatch, username: str,
                        timeout: int) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if username in batch.activations:
                return batch.activations[username]
            self._poll(batch)
            if username in batch.activations:
                return batch.activations[username]
            time.sleep(1)
        raise ActivationTimeout(
            f"no activation email for {username} after {timeout}s"
        )

    def _poll(self, batch: MailBatch) -> None:
        with batch.poll_lock:
            now = time.time()
            if now - batch.last_poll < 6:
                return
            batch.last_poll = now
            for message in self.mail.list_messages(batch.token):
                message_id = message.get("id")
                if not message_id or message_id in batch.seen:
                    continue
                text = self.mail.message_text(batch.token, message_id)
                if not text:
                    continue
                batch.seen.add(message_id)
                for match in ACTIVATION_RE.finditer(text):
                    token = match.group(1)
                    account = self._username_from_token(token)
                    if account:
                        batch.activations[account] = token


class ImapInbox:
    """Catch-all / mailbox IMAP reader for a domain you own."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._conn: imaplib.IMAP4_SSL | None = None
        self._seen: set[str] = set()

    def _connect(self) -> imaplib.IMAP4_SSL:
        if self._conn is None:
            self._conn = imaplib.IMAP4_SSL(self.cfg.imap_host, self.cfg.imap_port)
            self._conn.login(self.cfg.imap_user, self.cfg.imap_pass)
        return self._conn

    def _reset(self) -> None:
        try:
            if self._conn is not None:
                self._conn.logout()
        except Exception:
            pass
        self._conn = None

    @staticmethod
    def _message_text(message) -> str:
        parts: list[str] = []
        for part in message.walk():
            if part.get_content_type() not in ("text/plain", "text/html"):
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            parts.append(payload.decode(charset, errors="ignore"))
        return "\n".join(parts)

    def wait_activation(self, address: str, timeout: int) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                conn = self._connect()
                conn.select(self.cfg.imap_folder)
                status, data = conn.uid(
                    "SEARCH", None, f'(TO "{address}")'
                )
                if status == "OK" and data and data[0]:
                    for uid in reversed(data[0].split()[-20:]):
                        uid_text = uid.decode() if isinstance(uid, bytes) else str(uid)
                        if uid_text in self._seen:
                            continue
                        self._seen.add(uid_text)
                        status, raw = conn.uid("FETCH", uid, "(RFC822)")
                        if status != "OK" or not raw:
                            continue
                        for item in raw:
                            if isinstance(item, tuple):
                                message = email_lib.message_from_bytes(item[1])
                                match = ACTIVATION_RE.search(
                                    self._message_text(message)
                                )
                                if match:
                                    try:
                                        conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
                                    except Exception:
                                        pass
                                    return match.group(1)
                time.sleep(5)
            except Exception as exc:
                log(f"  IMAP error: {exc}; reconnecting")
                self._reset()
                time.sleep(5)
        raise ActivationTimeout(
            f"no activation email for {address} after {timeout}s"
        )


# ---------------------------------------------------------------------------
# Logos / profile pictures
# ---------------------------------------------------------------------------


def choose_logo(cfg: Config, username: str, rng: random.Random) -> str | None:
    """Pick a local logo or generate one with DiceBear. Returns a local path."""
    cfg.avatars_dir.mkdir(parents=True, exist_ok=True)

    if cfg.logo_files:
        source = rng.choice(cfg.logo_files)
        target = cfg.avatars_dir / f"{username}{source.suffix.lower()}"
        try:
            shutil.copyfile(source, target)
            return str(target)
        except OSError as exc:
            log(f"  logo copy failed: {exc}")

    style = rng.choice(DICEBEAR_STYLES)
    seed = f"{username}-{rng.randint(1000, 999999)}"
    for attempt in range(2):
        try:
            response = requests.get(
                f"https://api.dicebear.com/9.x/{style}/png",
                params={"seed": seed, "size": 256},
                timeout=30,
                headers={"User-Agent": UA_POOL[0]},
            )
            if response.status_code == 200 and len(response.content) > 200:
                target = cfg.avatars_dir / f"{username}.png"
                target.write_bytes(response.content)
                return str(target)
        except requests.RequestException:
            pass
        style = "shapes"
        time.sleep(1)
    return None


# ---------------------------------------------------------------------------
# VirusTotal client
# ---------------------------------------------------------------------------


def request_proxies(proxy: str | None) -> dict | None:
    if not proxy:
        return None
    value = proxy if "://" in proxy else f"http://{proxy}"
    return {"http": value, "https": value}


class VTClient:
    def __init__(self, profile: dict, cfg: Config, captcha: TwoCaptcha,
                 proxy: str | None):
        self.profile = profile
        self.cfg = cfg
        self.captcha = captcha
        self.proxy = proxy
        self.proxies = request_proxies(proxy)
        self.session = requests.Session()

    # -- headers -----------------------------------------------------------
    @staticmethod
    def _anti_abuse() -> str:
        raw = (
            f"{((1 + random.random() % 5e4) * 1e10):.0f}"
            f"-{ANTI_ABUSE_TAG}-{time.time()}"
        )
        return base64.b64encode(raw.encode()).decode()

    def headers(self, extra: dict | None = None) -> dict:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "accept-language": "en-US,en;q=0.9",
            "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
            "X-VT-Anti-Abuse-Header": self._anti_abuse(),
            "Referer": "https://www.virustotal.com/",
            "User-Agent": self.profile["ua"],
            "x-tool": "vt-ui-main",
            "x-app-version": "v1x689x3",
        }
        if extra:
            headers.update(extra)
        return headers

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{VT_BASE}{path}"
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                return self.session.request(
                    method, url, timeout=self.cfg.request_timeout,
                    proxies=self.proxies, **kwargs,
                )
            except requests.RequestException as exc:
                last_error = exc
                time.sleep(2 + attempt * 2)
        raise VTError(f"{method} {path} failed: {last_error}")

    # -- steps -------------------------------------------------------------
    def signup(self) -> dict:
        payload = {"data": {
            "user_id": self.profile["username"],
            "email": self.profile["email"],
            "password": self.profile["password"],
            "first_name": self.profile["first_name"],
            "last_name": self.profile["last_name"],
            "service": "gui",
        }}
        last_error = "unknown"
        # VT's Enterprise score is picky: 2captcha tokens are regularly
        # refused even when the solve itself succeeded. Retry with fresh
        # tokens until one passes.
        for attempt in range(self.cfg.signup_retries):
            token = self.captcha.solve_signup(self.profile["ua"])
            response = self._request(
                "POST", "/ui/signup",
                headers=self.headers({
                    "x-recaptcha-v3-token": token,
                    "x-recaptcha-v3-action": "checkbox",
                }),
                json=payload,
            )
            if response.status_code < 400:
                return response.json()
            try:
                code = response.json().get("error", {}).get("code")
                message = response.json().get("error", {}).get("message", "")
            except ValueError:
                code, message = None, response.text[:200]
            last_error = f"HTTP {response.status_code} {code}: {message}"
            if code == "AlreadyExistsError":
                raise DuplicateAccount(last_error)
            if code == "RecaptchaRequiredError":
                log(f"  captcha rejected, solving again "
                    f"({attempt + 1}/{self.cfg.signup_retries})")
                time.sleep(2)
                continue
            if response.status_code in (429, 502, 503, 504):
                time.sleep(8 + attempt * 5)
                continue
            raise VTError(f"signup failed: {last_error}")
        raise VTError(f"signup failed: {last_error}")

    def confirm(self, token: str) -> None:
        response = self._request(
            "POST", "/ui/signup/confirm",
            headers=self.headers(),
            json={"data": {"token": token}},
        )
        if response.status_code >= 400:
            raise VTError(
                f"activation failed HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )

    def signin(self) -> tuple[str, dict]:
        body = {"data": {
            "user_id": self.profile["email"],
            "password": self.profile["password"],
            "forever": False,
        }}
        # v3 tokens are proxyless; if a proxy is configured, try the proxied
        # request first and fall back to a direct one.
        attempts = [self.proxies]
        if self.proxies:
            attempts.append(None)
        last_error = "unknown"
        for proxies in attempts:
            for token_attempt in range(self.cfg.signin_retries):
                try:
                    token = self.captcha.solve_login(self.profile["ua"])
                except CaptchaError as exc:
                    last_error = str(exc)
                    log(f"  login captcha failed ({exc}), retrying "
                        f"({token_attempt + 1}/{self.cfg.signin_retries})")
                    time.sleep(3)
                    continue
                try:
                    response = self.session.post(
                        f"{VT_BASE}/ui/signin?relationships=active_group,parent_group",
                        headers=self.headers({"X-Recaptcha-Token": token}),
                        json=body,
                        timeout=self.cfg.request_timeout,
                        proxies=proxies,
                    )
                except requests.RequestException as exc:
                    last_error = str(exc)
                    log(f"  signin failed ({last_error}), retrying")
                    time.sleep(3)
                    continue
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    apikey = attributes.get("apikey")
                    if not apikey:
                        apikey = self._fetch_apikey() or ""
                    return apikey, self.session.cookies.get_dict()
                last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                log(f"  signin failed ({last_error}), retrying "
                    f"({token_attempt + 1}/{self.cfg.signin_retries})")
                if response.status_code == 401:
                    break
                time.sleep(3)
        raise VTError(f"signin failed: {last_error}")

    def _fetch_apikey(self) -> str | None:
        try:
            response = self._request("GET", "/ui/user_data", headers=self.headers())
            if response.status_code == 200:
                return response.json().get("data", {}).get("attributes", {}).get("apikey")
        except Exception:
            pass
        return None

    def upload_avatar(self, path: str | None) -> bool:
        if not path:
            return False
        target = Path(path)
        if not target.is_file():
            return False
        mime = mimetypes.guess_type(target.name)[0] or "image/png"
        headers = self.headers()
        headers.pop("content-type", None)
        try:
            with target.open("rb") as handle:
                response = self._request(
                    "POST", f"/ui/users/{self.profile['username']}/avatar",
                    headers=headers,
                    files={"file": (target.name, handle, mime)},
                )
            return response.status_code < 400
        except VTError as exc:
            log(f"  avatar upload failed: {exc}")
            return False


# ---------------------------------------------------------------------------
# Account creation worker
# ---------------------------------------------------------------------------


@dataclass
class Runner:
    cfg: Config
    captcha: TwoCaptcha
    used_names: set[str] = field(default_factory=set)
    used_lock: threading.Lock = field(default_factory=threading.Lock)
    store: "AccountStore | None" = None
    mail_pool: MailTMPool | None = None

    def __post_init__(self) -> None:
        if self.cfg.mail_provider == "mailtm-pool":
            self.mail_pool = MailTMPool(self.cfg)

    def create_one(self, index: int) -> dict:
        rng = random.Random()
        profile = make_profile(rng, self.used_names, self.used_lock)
        proxy = self.cfg.proxies[index % len(self.cfg.proxies)] if self.cfg.proxies else None
        record: dict = {
            "created_at": now_iso(),
            "status": "started",
            "index": index + 1,
            "first_name": profile["first_name"],
            "last_name": profile["last_name"],
            "user_id": profile["username"],
            "email": "",
            "password": profile["password"],
            "mail_password": profile["mail_password"],
            "mail_api": self.cfg.mail_api,
            "mail_token": "",
            "mail_base": "",
            "user_agent": profile["ua"],
            "apikey": "",
            "cookies": {},
            "avatar": "",
            "avatar_uploaded": False,
            "proxy": proxy or "",
            "activation_token": "",
            "error": "",
        }
        log(f"[{index + 1}/{self.cfg.count}] {profile['username']} starting"
            + (f" via {proxy}" if proxy else ""))
        try:
            # 1. inbox
            mailbox = None
            batch = None
            if self.cfg.mail_provider == "imap":
                if not all([self.cfg.email_domain, self.cfg.imap_host,
                            self.cfg.imap_user, self.cfg.imap_pass]):
                    raise MailError(
                        "IMAP mode requires --email-domain, --imap-host, "
                        "--imap-user and --imap-pass"
                    )
                address = f"{profile['email_local']}@{self.cfg.email_domain}"
                profile["email"] = address
                mailbox = ImapInbox(self.cfg)
                record.update(email=address, status="inbox_ready")
            elif self.cfg.mail_provider == "mailtm-pool":
                address, batch = self.mail_pool.allocate(profile["username"])
                profile["email"] = address
                record.update(
                    email=address, mail_token=batch.token,
                    mail_password=batch.password, mail_base=batch.address,
                    status="inbox_ready",
                )
            else:  # one mail.tm inbox per account
                mailbox = MailTM(self.cfg.mail_api, self.cfg.request_timeout)
                address, mail_token = mailbox.create_inbox(
                    profile["email_local"], profile["mail_password"],
                    self.cfg.email_domain,
                )
                profile["email"] = address
                record.update(email=address, mail_token=mail_token,
                              mail_base=address, status="inbox_ready")
            log(f"[{index + 1}/{self.cfg.count}] inbox {address}")

            # 2. logo (local or generated)
            logo = choose_logo(self.cfg, profile["username"], rng) \
                if self.cfg.upload_avatar else None
            record["avatar"] = logo or ""

            # 3. signup
            client = VTClient(profile, self.cfg, self.captcha, proxy)
            client.signup()
            record["status"] = "signed_up"
            log(f"[{index + 1}/{self.cfg.count}] signup OK, waiting for email")

            # 4. activation
            if self.cfg.mail_provider == "mailtm-pool":
                activation = self.mail_pool.wait_activation(
                    batch, profile["username"], self.cfg.activation_timeout
                )
            elif self.cfg.mail_provider == "mailtm":
                activation = mailbox.wait_activation(
                    record["mail_token"], self.cfg.activation_timeout
                )
            else:
                activation = mailbox.wait_activation(
                    address, self.cfg.activation_timeout
                )
            record.update(activation_token=activation, status="activation_received")
            client.confirm(activation)
            record["status"] = "activated"
            log(f"[{index + 1}/{self.cfg.count}] activated")

            # 5. sign-in -> API key
            apikey, cookies = client.signin()
            record.update(apikey=apikey, cookies=cookies, status="active")
            log(f"[{index + 1}/{self.cfg.count}] active, apikey {apikey[:12]}...")

            # 6. avatar
            if self.cfg.upload_avatar and logo:
                record["avatar_uploaded"] = client.upload_avatar(logo)
                if record["avatar_uploaded"]:
                    log(f"[{index + 1}/{self.cfg.count}] avatar uploaded")

        except ActivationTimeout as exc:
            record["status"] = "pending_activation"
            record["error"] = str(exc)
            log(f"[{index + 1}/{self.cfg.count}] {exc}")
        except DuplicateAccount as exc:
            record["status"] = "duplicate"
            record["error"] = str(exc)
            log(f"[{index + 1}/{self.cfg.count}] duplicate: {exc}")
        except (CaptchaError, MailError, VTError, requests.RequestException) as exc:
            record["status"] = "error"
            record["error"] = str(exc)
            log(f"[{index + 1}/{self.cfg.count}] ERROR: {exc}")
        except Exception as exc:  # keep the batch alive
            record["status"] = "error"
            record["error"] = f"{type(exc).__name__}: {exc}"
            log(f"[{index + 1}/{self.cfg.count}] ERROR: {type(exc).__name__}: {exc}")
        return record


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


class AccountStore:
    def __init__(self, jsonl_path: Path, csv_path: Path):
        self.jsonl_path = jsonl_path
        self.csv_path = csv_path
        self.lock = threading.Lock()
        self.records: list[dict] = []
        # Keep history so a second run does not overwrite the CSV with only
        # the new accounts.
        if jsonl_path.is_file():
            with jsonl_path.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    def append(self, record: dict) -> None:
        with self.lock:
            self.records.append(record)
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            with self.jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                handle.flush()

    def write_csv(self) -> None:
        if not self.records:
            return
        columns = [
            "created_at", "status", "user_id", "first_name", "last_name",
            "email", "password", "mail_password", "mail_api", "mail_token",
            "mail_base", "user_agent", "apikey", "avatar", "avatar_uploaded", "proxy",
            "activation_token", "error", "cookies",
        ]
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        with self.csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for record in self.records:
                row = dict(record)
                row["cookies"] = json.dumps(row.get("cookies", {}), ensure_ascii=False)
                writer.writerow(row)


# ---------------------------------------------------------------------------
# Vote mode
# ---------------------------------------------------------------------------


def run_vote(args: argparse.Namespace) -> int:
    accounts_path = Path(args.accounts or args.output)
    if not accounts_path.is_file():
        print(f"accounts file not found: {accounts_path}", file=sys.stderr)
        return 2
    if not args.file_hash or not HASH_RE.match(args.file_hash):
        print("--hash must be a MD5, SHA-1 or SHA-256 hex digest", file=sys.stderr)
        return 2

    accounts: list[dict] = []
    with accounts_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("apikey"):
                accounts.append(record)
    if not accounts:
        print("no account with an API key found", file=sys.stderr)
        return 2

    comments: list[str] = []
    if args.comment:
        comments = [args.comment]
    elif args.comments_file:
        path = Path(args.comments_file)
        if not path.is_file():
            print(f"comments file not found: {path}", file=sys.stderr)
            return 2
        comments = [
            line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not comments:
            print(f"comments file is empty: {path}", file=sys.stderr)
            return 2

    log(f"voting {args.verdict} on {args.file_hash} with {len(accounts)} accounts"
        + (f", {len(comments)} comment(s) available" if comments else ""))
    counts = {"ok": 0, "already": 0, "error": 0}
    counts_lock = threading.Lock()

    def vote(record: dict) -> None:
        cookies = record.get("cookies") or {}
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        session_hash = cookies.get("VT_SESSION_HASH", "")
        use_ui = bool(cookies.get("VT_SESSION_ID"))
        user_agent = record.get("user_agent") or UA_POOL[0]
        vote_ui_url = f"{VT_BASE}/ui/files/{args.file_hash}/votes"
        vote_api_url = f"{VT_BASE}/api/v3/files/{args.file_hash}/votes"
        comment_ui_url = f"{VT_BASE}/ui/files/{args.file_hash}/comments"
        comment_api_url = f"{VT_BASE}/api/v3/files/{args.file_hash}/comments"

        def anti_abuse() -> str:
            raw = (
                f"{((1 + random.random() % 5e4) * 1e10):.0f}"
                f"-{ANTI_ABUSE_TAG}-{time.time()}"
            )
            return base64.b64encode(raw.encode()).decode()

        def ui_headers() -> dict:
            return {
                "accept": "application/json",
                "content-type": "application/json",
                "accept-language": "en-US,en;q=0.9",
                "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
                "X-VT-Anti-Abuse-Header": anti_abuse(),
                "Referer": "https://www.virustotal.com/",
                "User-Agent": user_agent,
                "x-tool": "vt-ui-main",
                "x-app-version": "v1x689x3",
                "Cookie": cookie_header,
                "x-session-hash": session_hash,
            }

        def api_headers() -> dict:
            return {
                "accept": "application/json",
                "content-type": "application/json",
                "User-Agent": user_agent,
                "x-apikey": record["apikey"],
            }

        result = "error"
        for attempt in range(6):
            url = vote_ui_url if use_ui else vote_api_url
            headers = ui_headers() if use_ui else api_headers()
            try:
                response = requests.post(
                    url, headers=headers,
                    json={"data": {"type": "vote",
                                   "attributes": {"verdict": args.verdict}}},
                    timeout=args.request_timeout,
                )
                if response.status_code in (200, 201):
                    result = "ok"
                    break
                if use_ui and response.status_code in (401, 403):
                    use_ui = False
                    continue
                if response.status_code == 409:
                    result = "already"
                    break
                if response.status_code == 429:
                    time.sleep(8 + attempt * 5)
                    continue
                if response.status_code in (502, 503, 504):
                    time.sleep(6 + attempt * 4)
                    continue
                if response.status_code == 404:
                    log(f"  hash not found on VirusTotal yet - upload the file "
                        f"first, then vote again")
                result = "error"
                log(f"  {record['user_id']}: HTTP {response.status_code} "
                    f"{response.text[:120]}")
                break
            except requests.RequestException as exc:
                log(f"  {record['user_id']}: {exc}")
                time.sleep(3)
        if comments and result != "error":
            text = random.choice(comments)
            for attempt in range(4):
                url = comment_ui_url if use_ui else comment_api_url
                headers = ui_headers() if use_ui else api_headers()
                try:
                    response = requests.post(
                        url, headers=headers,
                        json={"data": {"type": "comment",
                                       "attributes": {"text": text}}},
                        timeout=args.request_timeout,
                    )
                    if response.status_code in (200, 201):
                        break
                    if use_ui and response.status_code in (401, 403):
                        use_ui = False
                        continue
                    if response.status_code in (429, 502, 503, 504):
                        time.sleep(10 + attempt * 5)
                        continue
                    break
                except requests.RequestException:
                    time.sleep(3)
        with counts_lock:
            counts[result] += 1

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(vote, record) for record in accounts]
        for future in as_completed(futures):
            future.result()

    log(f"votes: {counts['ok']} new, {counts['already']} already, "
        f"{counts['error']} errors")
    return 0 if counts["ok"] or counts["already"] else 1


def run_comment(args: argparse.Namespace) -> int:
    """Post N different pre-written comments, spread over all API keys."""
    accounts_path = Path(args.accounts or args.output)
    if not accounts_path.is_file():
        print(f"accounts file not found: {accounts_path}", file=sys.stderr)
        return 2
    if not args.file_hash or not HASH_RE.match(args.file_hash):
        print("--hash must be a MD5, SHA-1 or SHA-256 hex digest", file=sys.stderr)
        return 2
    if not args.comments_file:
        print("comment mode requires --comments-file", file=sys.stderr)
        return 2
    path = Path(args.comments_file)
    if not path.is_file():
        print(f"comments file not found: {path}", file=sys.stderr)
        return 2
    comments = list(dict.fromkeys(
        line.strip() for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ))
    if not comments:
        print("comments file is empty", file=sys.stderr)
        return 2

    accounts: list[dict] = []
    with accounts_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("apikey"):
                accounts.append(record)
    if not accounts:
        print("no account with an API key found", file=sys.stderr)
        return 2

    target = args.total_comments or len(comments)
    target = min(target, len(comments))
    random.shuffle(comments)
    comments = comments[:target]
    buckets: list[list[str]] = [[] for _ in accounts]
    for index, text in enumerate(comments):
        buckets[index % len(accounts)].append(text)

    log(f"posting {target} comment(s) on {args.file_hash} with "
        f"{len(accounts)} accounts")
    counts = {"ok": 0, "already": 0, "error": 0}
    counts_lock = threading.Lock()
    done = 0

    def post(record: dict, bucket: list[str]) -> None:
        nonlocal done
        cookies = record.get("cookies") or {}
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        session_hash = cookies.get("VT_SESSION_HASH", "")
        use_ui = bool(cookies.get("VT_SESSION_ID"))
        user_agent = record.get("user_agent") or UA_POOL[0]
        ui_url = f"{VT_BASE}/ui/files/{args.file_hash}/comments"
        api_url = f"{VT_BASE}/api/v3/files/{args.file_hash}/comments"

        def anti_abuse() -> str:
            raw = (
                f"{((1 + random.random() % 5e4) * 1e10):.0f}"
                f"-{ANTI_ABUSE_TAG}-{time.time()}"
            )
            return base64.b64encode(raw.encode()).decode()

        def ui_headers() -> dict:
            return {
                "accept": "application/json",
                "content-type": "application/json",
                "accept-language": "en-US,en;q=0.9",
                "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
                "X-VT-Anti-Abuse-Header": anti_abuse(),
                "Referer": "https://www.virustotal.com/",
                "User-Agent": user_agent,
                "x-tool": "vt-ui-main",
                "x-app-version": "v1x689x3",
                "Cookie": cookie_header,
                "x-session-hash": session_hash,
            }

        def api_headers() -> dict:
            return {
                "accept": "application/json",
                "content-type": "application/json",
                "User-Agent": user_agent,
                "x-apikey": record["apikey"],
            }

        for text in bucket:
            result = "error"
            for attempt in range(8):
                url = ui_url if use_ui else api_url
                headers = ui_headers() if use_ui else api_headers()
                try:
                    response = requests.post(
                        url, headers=headers,
                        json={"data": {"type": "comment",
                                       "attributes": {"text": text}}},
                        timeout=args.request_timeout,
                    )
                    if response.status_code in (200, 201):
                        result = "ok"
                        break
                    if use_ui and response.status_code in (401, 403):
                        use_ui = False
                        continue
                    if response.status_code == 429:
                        time.sleep(15 + attempt * 8)
                        continue
                    if response.status_code in (502, 503, 504):
                        time.sleep(6 + attempt * 4)
                        continue
                    if response.status_code == 409:
                        result = "already"
                        break
                    result = "error"
                    log(f"  {record['user_id']}: HTTP {response.status_code} "
                        f"{response.text[:100]}")
                    break
                except requests.RequestException as exc:
                    log(f"  {record['user_id']}: {exc}")
                    time.sleep(3)
            with counts_lock:
                counts[result] += 1
                done += 1
                if done % 50 == 0:
                    log(f"  progress {done}/{target}")
            time.sleep(0.2)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(post, record, bucket)
                   for record, bucket in zip(accounts, buckets)]
        for future in as_completed(futures):
            future.result()

    log(f"comments: {counts['ok']} posted, {counts['already']} already, "
        f"{counts['error']} errors")
    return 0 if counts["ok"] or counts["already"] else 1


def run_signin(args: argparse.Namespace) -> int:
    """Retry the sign-in step for accounts that were activated but have no key."""
    accounts_path = Path(args.accounts or args.output)
    if not accounts_path.is_file():
        print(f"accounts file not found: {accounts_path}", file=sys.stderr)
        return 2
    rows: list[dict] = []
    with accounts_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    todo = [
        row for row in rows
        if row.get("email") and row.get("password") and not row.get("apikey")
    ]
    if not todo:
        log("no account without an API key")
        return 0

    cfg = Config(
        captcha_key=args.captcha_key,
        request_timeout=max(10, args.request_timeout),
        proxies=load_proxies(args.proxy_file),
        output=accounts_path,
        csv_output=Path(args.csv),
    )
    captcha = TwoCaptcha(args.captcha_key, request_timeout=cfg.request_timeout)
    lock = threading.Lock()
    counts = {"ok": 0, "error": 0}
    log(f"retrying sign-in for {len(todo)} account(s)")

    def recover(row: dict) -> None:
        profile = {
            "username": row["user_id"],
            "email": row["email"],
            "password": row["password"],
            "first_name": row.get("first_name", ""),
            "last_name": row.get("last_name", ""),
            "ua": row.get("user_agent") or UA_POOL[0],
        }
        client = VTClient(profile, cfg, captcha, row.get("proxy") or None)
        try:
            apikey, cookies = client.signin()
        except (CaptchaError, VTError, requests.RequestException) as exc:
            log(f"  {row['user_id']}: {exc}")
            with lock:
                counts["error"] += 1
            return
        with lock:
            row.update(apikey=apikey, cookies=cookies, status="active", error="")
            counts["ok"] += 1
        log(f"  {row['user_id']}: apikey recovered ({apikey[:12]}...)")

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(recover, row) for row in todo]
        for future in as_completed(futures):
            future.result()

    with accounts_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    store = AccountStore(accounts_path, Path(args.csv))
    store.records = rows
    store.write_csv()
    log(f"signin retry: {counts['ok']} recovered, {counts['error']} still failing")
    return 0 if counts["ok"] or not counts["error"] else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VirusTotal mass account creator (requests only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", choices=["create", "vote", "comment", "signin"],
                        default="create")
    parser.add_argument("--count", type=int, default=5,
                        help="number of accounts to create")
    parser.add_argument("--workers", type=int, default=3,
                        help="parallel accounts / parallel votes")
    parser.add_argument("--captcha-key", default=os.getenv("CAPTCHA_API_KEY",
                                                           DEFAULT_CAPTCHA_KEY),
                        help="2captcha API key")
    parser.add_argument("--mail-provider",
                        choices=["mailtm-pool", "mailtm", "imap"],
                        default="mailtm-pool",
                        help="mailtm-pool = 1 inbox + plus aliases (recommended)")
    parser.add_argument("--mailtm-batch", type=int, default=40,
                        help="accounts per pooled mail.tm inbox")
    parser.add_argument("--mail-api", default="https://api.mail.tm")
    parser.add_argument("--email-domain", default=None,
                        help="mail.tm domain or your catch-all domain")
    parser.add_argument("--imap-host", default=None)
    parser.add_argument("--imap-port", type=int, default=993)
    parser.add_argument("--imap-user", default=None)
    parser.add_argument("--imap-pass", default=None)
    parser.add_argument("--imap-folder", default="INBOX")
    parser.add_argument("--logo-dir", default=None,
                        help="folder of logo images (png/jpg/webp/gif)")
    parser.add_argument("--avatars-dir", default="avatars")
    parser.add_argument("--no-avatar", action="store_true",
                        help="do not set a profile picture")
    parser.add_argument("--output", default="accounts.jsonl")
    parser.add_argument("--csv", default="accounts.csv")
    parser.add_argument("--proxy-file", default=None,
                        help="one HTTP proxy per line; rounded-robin per account")
    parser.add_argument("--activation-timeout", type=int, default=240)
    parser.add_argument("--request-timeout", type=int, default=60)
    parser.add_argument("--signup-retries", type=int, default=7)
    parser.add_argument("--signin-retries", type=int, default=5)
    parser.add_argument("--delay", type=float, default=0.0,
                        help="seconds to wait before each account")
    # vote mode
    parser.add_argument("--hash", dest="file_hash", default=None,
                        help="file hash to vote on (vote mode)")
    parser.add_argument("--verdict", choices=["harmless", "malicious"],
                        default="harmless")
    parser.add_argument("--accounts", default=None,
                        help="accounts.jsonl used by vote mode")
    parser.add_argument("--comment", default=None,
                        help="optional comment posted with each vote")
    parser.add_argument("--comments-file", default=None,
                        help="one pre-written comment per line; one is picked "
                             "at random for each account")
    parser.add_argument("--total-comments", type=int, default=0,
                        help="comment mode: how many comments to post "
                             "(default: all)")
    return parser


def load_proxies(path: str | None) -> list[str]:
    if not path:
        return []
    proxies = [
        line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return proxies


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.mode == "vote":
        return run_vote(args)
    if args.mode == "comment":
        return run_comment(args)
    if args.mode == "signin":
        return run_signin(args)

    logo_dir = Path(args.logo_dir) if args.logo_dir else None
    if logo_dir is None:
        for candidate in (Path("logos"),
                          Path(__file__).resolve().parent / "logos"):
            if candidate.is_dir():
                logo_dir = candidate
                break
    logo_files: list[Path] = []
    if logo_dir:
        if not logo_dir.is_dir():
            print(f"logo folder not found: {logo_dir}", file=sys.stderr)
            return 2
        logo_files = sorted(
            path for path in logo_dir.iterdir()
            if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS
        )
        if not logo_files:
            log(f"no image in {logo_dir}, using generated DiceBear logos")

    cfg = Config(
        count=max(1, args.count),
        workers=max(1, args.workers),
        captcha_key=args.captcha_key,
        mail_provider=args.mail_provider,
        mailtm_batch=max(1, args.mailtm_batch),
        mail_api=args.mail_api,
        email_domain=args.email_domain,
        imap_host=args.imap_host,
        imap_port=args.imap_port,
        imap_user=args.imap_user,
        imap_pass=args.imap_pass,
        imap_folder=args.imap_folder,
        logo_dir=logo_dir,
        avatars_dir=Path(args.avatars_dir),
        output=Path(args.output),
        csv_output=Path(args.csv),
        proxies=load_proxies(args.proxy_file),
        activation_timeout=max(30, args.activation_timeout),
        request_timeout=max(10, args.request_timeout),
        signup_retries=max(1, args.signup_retries),
        signin_retries=max(1, args.signin_retries),
        upload_avatar=not args.no_avatar,
        delay=max(0.0, args.delay),
        logo_files=logo_files,
    )

    if not cfg.captcha_key:
        print("missing 2captcha key (--captcha-key or CAPTCHA_API_KEY)",
              file=sys.stderr)
        return 2
    if cfg.mail_provider == "imap" and not all(
        [cfg.email_domain, cfg.imap_host, cfg.imap_user, cfg.imap_pass]
    ):
        print("IMAP mode requires --email-domain --imap-host --imap-user "
              "--imap-pass", file=sys.stderr)
        return 2

    masked = cfg.captcha_key[:6] + "..." + cfg.captcha_key[-4:]
    log(f"creating {cfg.count} account(s), {cfg.workers} worker(s), "
        f"captcha key {masked}")
    log(f"mail provider: {cfg.mail_provider}; output: {cfg.output}")

    captcha = TwoCaptcha(cfg.captcha_key, request_timeout=cfg.request_timeout)
    store = AccountStore(cfg.output, cfg.csv_output)
    runner = Runner(cfg=cfg, captcha=captcha, store=store)

    def job(index: int) -> dict:
        if cfg.delay:
            time.sleep(cfg.delay)
        return runner.create_one(index)

    try:
        with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
            futures = [pool.submit(job, index) for index in range(cfg.count)]
            for future in as_completed(futures):
                store.append(future.result())
    except KeyboardInterrupt:
        log("interrupted, writing partial results")
    finally:
        store.write_csv()

    active = sum(1 for record in store.records if record["status"] == "active")
    with_key = sum(1 for record in store.records if record.get("apikey"))
    log(f"done: {active} active account(s), {with_key} API key(s)")
    log(f"results: {cfg.output} and {cfg.csv_output}")
    return 0 if with_key else 1


if __name__ == "__main__":
    raise SystemExit(main())

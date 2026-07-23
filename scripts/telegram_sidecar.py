#!/usr/bin/env python3
"""Embedded Telegram sidecar for single-container deployments.

Fronts a personal Telegram account via MTProto (Telethon). Authenticates
per-request from the JSON credential payload in X-OAuth-Credential-Data —
that lets the enclave run without a second Docker container for Telethon.

Accepts Bot-API-style names (/getMe, /sendMessage, chat_id, text,
reply_to_message_id) as aliases so agents' Bot API priors produce
correct calls. Capabilities exceed the Bot API: you can read any chat
you're in, list dialogs, and list contacts.

Routes:
  GET  /                                   — service index
  GET  /health                             — status
  GET  /openapi.json                       — OpenAPI 3.1 spec

  GET  /me               (alias: /getMe)   — own profile
  GET  /dialogs?limit=N                    — list your chats
  GET  /messages?chat=X&limit=N            — read a chat's history

  POST /send             (alias: /sendMessage)
       body: { chat|chat_id, message|text, reply_to|reply_to_message_id? }
  POST /reply            — /send with reply_to (convenience)

Each request must include:
  X-OAuth-Credential-Data: {"api_id": N, "api_hash": "...", "session_string": "..."}
"""

import asyncio
import difflib
import hashlib
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.types import Channel, Chat, User


BIND_HOST = os.environ.get("TELEGRAM_SIDECAR_HOST", "127.0.0.1")
PORT = int(os.environ.get("TELEGRAM_SIDECAR_PORT", "8082"))

loop = None
clients = {}


def entity_to_dict(entity):
    if isinstance(entity, User):
        return {
            "type": "user",
            "id": entity.id,
            "username": entity.username,
            "first_name": entity.first_name,
            "last_name": entity.last_name,
            "phone": entity.phone,
        }
    if isinstance(entity, (Chat, Channel)):
        return {
            "type": "channel" if isinstance(entity, Channel) else "chat",
            "id": entity.id,
            "title": entity.title,
            "username": getattr(entity, "username", None),
        }
    return {"type": "unknown", "id": getattr(entity, "id", None)}


def message_to_dict(msg):
    return {
        "id": msg.id,
        "date": msg.date.isoformat() if msg.date else None,
        "text": msg.text,
        "sender_id": msg.sender_id,
        "reply_to_msg_id": msg.reply_to.reply_to_msg_id if msg.reply_to else None,
        "out": msg.out,
    }


def run_async(coro):
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=30)


def parse_credential_data(headers):
    raw = headers.get("X-OAuth-Credential-Data")
    if not raw:
        raise ValueError("Missing X-OAuth-Credential-Data header")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid Telegram credential JSON: {exc}") from exc

    try:
        api_id = int(payload["api_id"])
        api_hash = str(payload["api_hash"])
        session_string = str(payload["session_string"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "Telegram credential must include api_id, api_hash, and session_string"
        ) from exc

    cred_name = headers.get("X-OAuth-Credential", "telegram")
    digest = hashlib.sha256(raw.encode()).hexdigest()
    cache_key = f"{cred_name}:{digest}"
    return cache_key, api_id, api_hash, session_string


def parse_relay_proxy(headers):
    """Egress relay wiring. When the proxy routes this session through a per-user
    reverse-SOCKS relay (so Telegram sees the user's own IP, not the enclave's),
    it passes the enclave-local SOCKS endpoint in `X-Relay-Socks`. `X-Relay-Required`
    enforces fail-closed: if a relay is required but none was supplied we refuse to
    connect rather than silently egress from the datacenter IP. Returns
    `(proxy_tuple_or_None, tag)` where `tag` distinguishes egress paths for caching."""
    socks = headers.get("X-Relay-Socks", "").strip()
    required = headers.get("X-Relay-Required", "").strip().lower() in ("1", "true", "yes")
    if not socks:
        if required:
            raise RuntimeError(
                "Relay required for this credential but no live relay endpoint was supplied"
            )
        return None, "direct"
    host, _, port = socks.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"Invalid X-Relay-Socks endpoint: {socks!r}")
    return ("socks5", host, int(port)), socks


async def get_client(headers):
    cache_key, api_id, api_hash, session_string = parse_credential_data(headers)
    proxy, proxy_tag = parse_relay_proxy(headers)
    # A change of egress path (relay up/down, or a new relay endpoint) must force a
    # reconnect from the new origin, so it is part of the cache identity.
    cache_key = f"{cache_key}|relay={proxy_tag}"

    client = clients.get(cache_key)
    if client is None:
        client = TelegramClient(
            StringSession(session_string), api_id, api_hash, proxy=proxy
        )
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            raise RuntimeError("Telegram session string is not authorized")
        clients[cache_key] = client
        return client

    if not client.is_connected():
        await client.connect()

    return client


async def async_get_me(headers):
    client = await get_client(headers)
    me = await client.get_me()
    return entity_to_dict(me)


async def async_get_messages(headers, chat, limit=20):
    client = await get_client(headers)
    entity = await client.get_entity(chat)
    messages = await client.get_messages(entity, limit=limit)
    return {
        "chat": entity_to_dict(entity),
        "messages": [message_to_dict(m) for m in messages],
    }


async def async_get_dialogs(headers, limit=20):
    client = await get_client(headers)
    dialogs = await client.get_dialogs(limit=limit)
    return [
        {
            "name": d.name,
            "entity": entity_to_dict(d.entity),
            "unread_count": d.unread_count,
            "last_message": message_to_dict(d.message) if d.message else None,
        }
        for d in dialogs
    ]


async def async_send_message(headers, chat, message, reply_to=None):
    client = await get_client(headers)
    entity = await client.get_entity(chat)
    msg = await client.send_message(entity, message, reply_to=reply_to)
    return message_to_dict(msg)


# ---------------------------------------------------------------------------
# Route map — aliases resolve to the same handler key
# ---------------------------------------------------------------------------

GET_ROUTES = {
    "/":                "index",
    "/health":          "health",
    "/openapi.json":    "openapi",

    "/me":              "me",
    "/getMe":           "me",   # Bot API alias

    "/dialogs":         "dialogs",
    "/messages":        "messages",
}

POST_ROUTES = {
    "/send":            "send",
    "/sendMessage":     "send",  # Bot API alias
    "/reply":           "send",
}


BOT_API_HINTS = {
    "/getUpdates":
        "No long-poll endpoint here — this sidecar fronts a personal account that "
        "receives messages over MTProto automatically. To read a chat's history, "
        "GET /messages?chat=USERNAME&limit=N.",
    "/getChat":
        "No direct equivalent. To list your chats, GET /dialogs. "
        "To read a specific chat, GET /messages?chat=USERNAME.",
    "/getChatHistory":
        "Use GET /messages?chat=USERNAME&limit=N.",
    "/setWebhook":
        "Webhooks are Bot-API only; this sidecar is pull-based.",
    "/deleteWebhook":
        "Not applicable.",
    "/forwardMessage":
        "Not implemented.",
    "/copyMessage":
        "Not implemented.",
    "/deleteMessage":
        "Not implemented.",
    "/editMessageText":
        "Not implemented.",
    "/sendPhoto":
        "Media sending not implemented.",
    "/sendDocument":
        "Media sending not implemented.",
    "/answerCallbackQuery":
        "Callback queries are Bot-API only.",
}


# ---------------------------------------------------------------------------
# OpenAPI 3.1 spec
# ---------------------------------------------------------------------------

def build_openapi():
    send_body = {
        "type": "object",
        "required": ["chat", "message"],
        "properties": {
            "chat":     {"type": ["string", "integer"], "description": "Username, phone, 'me', or numeric ID. Alias: chat_id."},
            "chat_id":  {"type": ["string", "integer"], "description": "Bot-API-style alias for 'chat'."},
            "message":  {"type": "string", "description": "Message text. Alias: text."},
            "text":     {"type": "string", "description": "Bot-API-style alias for 'message'."},
            "reply_to": {"type": "integer", "description": "Optional message ID to reply to. Alias: reply_to_message_id."},
            "reply_to_message_id": {"type": "integer", "description": "Bot-API-style alias for 'reply_to'."},
        },
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Telegram Personal-Account Sidecar",
            "version": "0.2.0",
            "description": (
                "Fronts a personal Telegram account via Telethon (MTProto). "
                "Not the Telegram Bot API. Bot-API-style names are accepted as aliases."
            ),
        },
        "paths": {
            "/me":       {"get":  {"summary": "Get own profile (alias: /getMe)"}},
            "/dialogs":  {"get":  {"summary": "List your chats", "description": "Query: limit."}},
            "/messages": {"get":  {"summary": "Read a chat's history", "description": "Query: chat, limit."}},
            "/send":     {"post": {"summary": "Send a message (alias: /sendMessage)",
                                   "requestBody": {"required": True, "content": {"application/json": {"schema": send_body}}}}},
            "/reply":    {"post": {"summary": "Convenience alias for /send with reply_to"}},
            "/health":   {"get":  {"summary": "Service health"}},
        },
        "x-aliases": {
            "paths":  {"/getMe": "/me", "/sendMessage": "/send"},
            "params": {"chat_id": "chat", "text": "message", "reply_to_message_id": "reply_to"},
        },
    }


OPENAPI = build_openapi()


# ---------------------------------------------------------------------------
# 404 with helpful hints
# ---------------------------------------------------------------------------

BOT_TOKEN_PATH = re.compile(r"^/bot[^/]+/(.+)$")
UPSTREAM_URL_PATH = re.compile(r"^/https?://[^/]+(/.+)$")


def list_paths(method):
    table = GET_ROUTES if method == "GET" else POST_ROUTES
    return sorted(table.keys())


def not_found_body(method, path):
    m = UPSTREAM_URL_PATH.match(path)
    if m:
        inner = m.group(1)
        body = {
            "error": "Target must be a path, not a full URL.",
            "routes": list_paths(method),
            "docs": "/openapi.json",
        }
        table = GET_ROUTES if method == "GET" else POST_ROUTES
        tm = BOT_TOKEN_PATH.match(inner)
        if tm:
            inner = "/" + tm.group(1)
        if inner in table:
            body["did_you_mean"] = inner
        elif inner in BOT_API_HINTS:
            body["hint"] = BOT_API_HINTS[inner]
        return body

    m = BOT_TOKEN_PATH.match(path)
    if m:
        inner = "/" + m.group(1)
        body = {
            "error": "No /bot{TOKEN}/ prefix — this is a personal-account sidecar, auth is session-based.",
            "routes": list_paths(method),
            "docs": "/openapi.json",
        }
        table = GET_ROUTES if method == "GET" else POST_ROUTES
        if inner in table:
            body["did_you_mean"] = inner
        elif inner in BOT_API_HINTS:
            body["hint"] = BOT_API_HINTS[inner]
        return body

    if path in BOT_API_HINTS:
        return {
            "error": f"Unknown endpoint: {method} {path}",
            "hint": BOT_API_HINTS[path],
            "routes": list_paths(method),
            "docs": "/openapi.json",
        }

    all_paths = sorted(set(list_paths("GET") + list_paths("POST")))
    close = difflib.get_close_matches(path, all_paths, n=1, cutoff=0.4)
    body = {
        "error": f"Unknown endpoint: {method} {path}",
        "routes": list_paths(method),
        "docs": "/openapi.json",
    }
    if close:
        body["did_you_mean"] = close[0]
    return body


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class TelegramHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        key = GET_ROUTES.get(path)
        if not key:
            self.json_response(404, not_found_body("GET", path))
            return

        if key == "index":
            self.json_response(200, {
                "service": "telegram-sidecar",
                "mode": "embedded",
                "description": "Personal Telegram account via Telethon (MTProto). Not the Bot API; Bot-API-style names accepted as aliases.",
                "routes": {
                    "GET /me":                      "own profile (alias: /getMe)",
                    "GET /dialogs?limit=N":         "list your chats",
                    "GET /messages?chat=X&limit=N": "read a chat's history",
                    "POST /send":                   "send (alias: /sendMessage); body: {chat|chat_id, message|text, reply_to|reply_to_message_id?}",
                    "POST /reply":                  "/send with reply_to",
                },
                "docs": "/openapi.json",
            })
            return

        if key == "health":
            self.json_response(200, {
                "status": "ok",
                "service": "telegram-sidecar",
                "mode": "embedded",
                "cached_clients": len(clients),
            })
            return

        if key == "openapi":
            self.json_response(200, OPENAPI)
            return

        try:
            if key == "me":
                self.json_response(200, run_async(async_get_me(self.headers)))

            elif key == "dialogs":
                limit = int(params.get("limit", ["20"])[0])
                self.json_response(200, run_async(async_get_dialogs(self.headers, limit)))

            elif key == "messages":
                chat = params.get("chat", [None])[0] or params.get("chat_id", [None])[0]
                limit = int(params.get("limit", ["20"])[0])
                if not chat:
                    self.json_response(400, {"error": "Missing ?chat= (or ?chat_id=) parameter"})
                    return
                self.json_response(200, run_async(async_get_messages(self.headers, chat, limit)))

        except ValueError as exc:
            self.json_response(400, {"error": str(exc)})
        except Exception as exc:
            self.json_response(500, {"error": str(exc)})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        try:
            body = (
                json.loads(self.rfile.read(content_length).decode("utf-8"))
                if content_length > 0
                else {}
            )
        except json.JSONDecodeError as exc:
            self.json_response(400, {"error": f"Invalid JSON body: {exc}"})
            return

        path = urlparse(self.path).path

        key = POST_ROUTES.get(path)
        if not key:
            self.json_response(404, not_found_body("POST", path))
            return

        try:
            if key == "send":
                chat = body.get("chat") or body.get("chat_id")
                message = body.get("message") or body.get("text")
                reply_to = body.get("reply_to") or body.get("reply_to_message_id")
                if not chat or not message:
                    self.json_response(400, {
                        "error": "Missing 'chat' (or 'chat_id') and/or 'message' (or 'text') in body",
                        "expected_body": {"chat": "username|id|'me'", "message": "text", "reply_to": "optional message id"},
                    })
                    return
                result = run_async(
                    async_send_message(
                        self.headers, chat, message,
                        reply_to=int(reply_to) if reply_to else None,
                    )
                )
                self.json_response(200, result)

        except ValueError as exc:
            self.json_response(400, {"error": str(exc)})
        except Exception as exc:
            self.json_response(500, {"error": str(exc)})

    def json_response(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[telegram-sidecar] {args[0]} {args[1]} {args[2]}\n")


def run_loop():
    global loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_forever()


def main():
    thread = Thread(target=run_loop, daemon=True)
    thread.start()

    server = HTTPServer((BIND_HOST, PORT), TelegramHandler)
    print(
        f"[telegram-sidecar] Listening on {BIND_HOST}:{PORT} (embedded mode)",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
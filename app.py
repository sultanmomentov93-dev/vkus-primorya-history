
import os
import json
import hmac
import hashlib
import sqlite3
import time
from urllib.parse import parse_qsl

from aiohttp import web

BOT_TOKEN = os.environ["BOT_TOKEN"]
DB_PATH = os.environ.get("DB_PATH", "shop.db")
ALLOWED_ORIGIN = "https://resonant-meerkat-fce37c.netlify.app"


def verify_user(init_data):
    if not init_data or len(init_data) > 10000:
        return None

    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True))
        received_hash = pairs.pop("hash", "")
        pairs.pop("signature", None)

        if not received_hash:
            return None

        check_string = "\n".join(
            f"{key}={value}" for key, value in sorted(pairs.items())
        )
        secret = hmac.new(
            b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256
        ).digest()
        expected = hmac.new(
            secret, check_string.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, received_hash):
            return None

        auth_date = int(pairs.get("auth_date", "0"))
        if auth_date <= 0 or time.time() - auth_date > 86400:
            return None

        user = json.loads(pairs.get("user", "{}"))
        user_id = user.get("id")
        return user_id if isinstance(user_id, int) and not isinstance(user_id, bool) else None

    except (ValueError, TypeError, json.JSONDecodeError):
        return None


async def health(request):
    return web.json_response({"ok": True})


async def my_orders(request):
    if request.content_length and request.content_length > 12000:
        return web.json_response({"error": "too_large"}, status=413)

    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError):
        return web.json_response({"error": "invalid_json"}, status=400)

    user_id = verify_user(body.get("initData", ""))
    if user_id is None:
        return web.json_response({"error": "unauthorized"}, status=401)

    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT id, created_at, items, total, status
                   FROM orders WHERE user_id = ?
                   ORDER BY id DESC LIMIT 100""",
                (user_id,),
            ).fetchall()

        orders = [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "items": row["items"],
                "total": row["total"],
                "status": row["status"] or "new",
            }
            for row in rows
        ]
        return web.json_response({"orders": orders})

    except sqlite3.Error:
        return web.json_response({"error": "database_error"}, status=500)


@web.middleware
async def cors(request, handler):
    origin = request.headers.get("Origin", "")
    if request.method == "OPTIONS":
        response = web.Response(status=204)
    else:
        response = await handler(request)

    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"

    return response


app = web.Application(
    client_max_size=12000,
    middlewares=[cors],
)
app.router.add_get("/health", health)
app.router.add_post("/api/my-orders", my_orders)
app.router.add_options("/api/my-orders", lambda request: web.Response(status=204))

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))

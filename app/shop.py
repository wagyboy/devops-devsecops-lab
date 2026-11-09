"""shop: a small Flask storefront (product list, search, purchase API)."""
import os
import random
import secrets
import sqlite3

from flask import Flask, jsonify, request, render_template

app = Flask(__name__)
# Read from the environment (injected by the platform's secret store); a random key per process otherwise.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DB_PATH = os.getenv("SHOP_DB", os.path.join(app.instance_path, "shop.db"))

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cache-Control": "no-store",
}


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS products "
                     "(sku TEXT PRIMARY KEY, name TEXT, price INTEGER, stock INTEGER)")
        conn.executemany("INSERT OR IGNORE INTO products VALUES (?, ?, ?, ?)", [
            ("SKU-100", "Mechanical keyboard", 120, 30),
            ("SKU-200", "4K monitor", 450, 15),
            ("SKU-300", "Standing desk", 990, 5),
        ])


@app.after_request
def add_security_headers(resp):
    resp.headers.update(SECURITY_HEADERS)
    return resp


@app.get("/")
def index():
    with db() as conn:
        products = conn.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    with db() as conn:
        # bound parameter: the input is data, never SQL
        rows = conn.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    # Jinja2 autoescaping turns <script> into &lt;script&gt;
    return render_template("search.html", q=q, products=rows)


@app.post("/api/buy/<sku>")
def buy(sku):
    qty = int(request.args.get("qty", 1))
    with db() as conn:
        row = conn.execute("SELECT * FROM products WHERE sku = ?", (sku,)).fetchone()
        if row is None:
            return jsonify(error=f"unknown sku {sku}"), 404
        if row["stock"] < qty:
            return jsonify(error="out of stock"), 409
        # simulated payment gateway: about 1 in 20 cards is declined (not a security decision)
        if random.random() < 0.05:  # noqa: S311
            return jsonify(error="payment declined"), 402
        conn.execute("UPDATE products SET stock = stock - ? WHERE sku = ?", (qty, sku))
    return jsonify(status="ok", sku=sku, qty=qty, total=row["price"] * qty)


@app.get("/health")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return jsonify(status="ok")
    except sqlite3.Error:
        return jsonify(status="db error"), 500


init_db()

if __name__ == "__main__":
    # local development only; the container runs gunicorn
    app.run(host="127.0.0.1", port=8000, debug=os.getenv("FLASK_DEBUG") == "1")

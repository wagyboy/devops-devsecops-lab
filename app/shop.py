"""shop: a small Flask storefront (product list, search, purchase API)."""
import os
import random
import sqlite3
import json

from flask import Flask, jsonify, request, render_template

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-change-me"

DB_PATH = os.getenv("SHOP_DB", "/tmp/shop.db")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS products (sku TEXT PRIMARY KEY, name TEXT, price INTEGER, stock INTEGER)")
        conn.executemany("INSERT OR IGNORE INTO products VALUES (?, ?, ?, ?)", [
            ("SKU-100", "Mechanical keyboard", 120, 30),
            ("SKU-200", "4K monitor", 450, 15),
            ("SKU-300", "Standing desk", 990, 5),
        ])


@app.get("/")
def index():
    with db() as conn:
        products = conn.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    with db() as conn:
        rows = conn.execute("SELECT * FROM products WHERE name LIKE '%" + q + "%'").fetchall()
    items = "".join(f"<li>{r['name']} - ${r['price']}</li>" for r in rows)
    return f"<h1>Results for {q}</h1><ul>{items}</ul><a href='/'>back</a>"


@app.post("/api/buy/<sku>")
def buy(sku):
    qty = int(request.args.get("qty", 1))
    with db() as conn:
        row = conn.execute("SELECT * FROM products WHERE sku = ?", (sku,)).fetchone()
        if row is None:
            return jsonify(error=f"unknown sku {sku}"), 404
        if row["stock"] < qty:
            return jsonify(error="out of stock"), 409
        # simulated payment gateway: about 1 in 20 cards is declined
        if random.random() < 0.05:
            return jsonify(error="payment declined"), 402
        conn.execute("UPDATE products SET stock = stock - ? WHERE sku = ?", (qty, sku))
    return jsonify(status="ok", sku=sku, qty=qty, total=row["price"] * qty)


@app.get("/health")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return jsonify(status="ok")
    except:
        return jsonify(status="db error"), 500


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

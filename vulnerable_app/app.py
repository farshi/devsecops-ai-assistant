"""Vulnerable demo app — intentionally uses outdated packages for PatchPilot demos.

DO NOT deploy this application. It exists solely to demonstrate
PatchPilot's vulnerability triage capabilities.
"""

from flask import Flask, request, jsonify, render_template_string
import requests
import yaml
from PIL import Image
from sqlalchemy import create_engine, text
from cryptography.fernet import Fernet
import numpy as np

app = Flask(__name__)

# Simple in-memory data store
items = {}


@app.route("/health")
def health():
    return jsonify({"status": "vulnerable-demo", "warning": "DO NOT deploy"})


@app.route("/items", methods=["GET"])
def list_items():
    return jsonify(list(items.values()))


@app.route("/items", methods=["POST"])
def create_item():
    data = request.get_json()
    item_id = str(len(items) + 1)
    items[item_id] = {"id": item_id, **data}
    return jsonify(items[item_id]), 201


@app.route("/render")
def render_page():
    """Intentionally uses render_template_string for demo purposes."""
    template = request.args.get("template", "<h1>Hello</h1>")
    return render_template_string(template)


@app.route("/fetch")
def fetch_url():
    """Fetches a URL using the vulnerable requests/urllib3 versions."""
    url = request.args.get("url", "https://httpbin.org/get")
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code})


@app.route("/encrypt")
def encrypt_data():
    """Uses cryptography for demo — the old version has known CVEs."""
    key = Fernet.generate_key()
    f = Fernet(key)
    data = request.args.get("data", "secret").encode()
    encrypted = f.encrypt(data)
    return jsonify({"encrypted": encrypted.decode()})


@app.route("/parse-yaml", methods=["POST"])
def parse_yaml():
    """Parses YAML input — old pyyaml has code execution CVEs."""
    raw = request.get_data(as_text=True)
    parsed = yaml.safe_load(raw)
    return jsonify({"parsed": str(parsed)})


@app.route("/compute")
def compute():
    """Uses numpy for a simple computation."""
    size = int(request.args.get("size", "10"))
    matrix = np.random.rand(size, size)
    result = float(np.mean(matrix))
    return jsonify({"mean": result})


if __name__ == "__main__":
    app.run(debug=True, port=5001)

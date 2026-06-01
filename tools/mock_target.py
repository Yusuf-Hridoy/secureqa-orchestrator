"""Simple Flask mock server for end-to-end UI testing of SecureQA Orchestrator.

Run this in a separate terminal:
    python tools/mock_target.py

Then point the Streamlit UI at http://localhost:8888.
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/pets", methods=["GET"])
def list_pets():
    # No security headers — should trigger API8 findings
    return jsonify([{"id": "1", "name": "Rex"}])


@app.route("/pets/<pet_id>", methods=["GET"])
def get_pet(pet_id):
    # No auth check — should trigger API1 (BOLA) and API2 findings
    return jsonify({"id": pet_id, "name": "Rex", "owner_id": "user-1"})


@app.route("/pets", methods=["POST"])
def create_pet():
    body = request.get_json(silent=True) or {}
    # Echo body back (with is_admin, role, etc.) — should trigger API3 findings
    return jsonify({"created": True, **body}), 201


@app.route("/admin/users", methods=["GET"])
def admin_users():
    # Accessible without auth — should trigger API5 (FLA) findings
    return jsonify([{"id": "1", "name": "alice"}])


@app.route("/.env", methods=["GET"])
def env_file():
    # Exposed debug path — should trigger API9 finding
    return "API_KEY=fake-key\nDB_URL=postgres://localhost", 200


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8888, debug=False)

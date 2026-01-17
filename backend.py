from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets
import string
import json
import os
import bcrypt
from datetime import datetime, timedelta
from pathlib import Path
import jwt

app = Flask(__name__)

# Enhanced CORS configuration for production
CORS(
    app,
    resources={
        r"/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "expose_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True,
            "max_age": 3600,
        }
    },
)

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
JWT_EXPIRY_HOURS = 720
DATA_DIR = Path("data")
CONTENT_DIR = Path("content")

DATA_DIR.mkdir(exist_ok=True)
CONTENT_DIR.mkdir(exist_ok=True)

USERS_FILE = DATA_DIR / "users.json"
PLAYERS_FILE = DATA_DIR / "players.json"
CONTENT_FILE = DATA_DIR / "content.json"
SCHEDULES_FILE = DATA_DIR / "schedules.json"
PAIRING_FILE = DATA_DIR / "pairing.json"
ANALYTICS_FILE = DATA_DIR / "analytics.json"

for file in [
    USERS_FILE,
    PLAYERS_FILE,
    CONTENT_FILE,
    SCHEDULES_FILE,
    PAIRING_FILE,
    ANALYTICS_FILE,
]:
    if not file.exists():
        with open(file, "w") as f:
            json.dump({}, f)


def load_data(filename):
    with open(filename, "r") as f:
        return json.load(f)


def save_data(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)


def generate_token(user_id, org_id=None):
    payload = {
        "user_id": user_id,
        "org_id": org_id,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None


def generate_pairing_code():
    return "".join(secrets.choice(string.digits) for _ in range(6))


# Add CORS headers to all responses
@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response


@app.route("/api/auth/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    company = data.get("company", "My Company")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    users = load_data(USERS_FILE)

    if email in users:
        return jsonify({"error": "Email already registered"}), 409

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id = f"user-{secrets.token_urlsafe(16)}"
    org_id = f"org-{secrets.token_urlsafe(16)}"

    users[email] = {
        "user_id": user_id,
        "email": email,
        "password_hash": password_hash,
        "org_id": org_id,
        "company": company,
        "created_at": datetime.utcnow().isoformat(),
        "plan": "free",
    }

    save_data(USERS_FILE, users)
    token = generate_token(user_id, org_id)

    return (
        jsonify(
            {
                "success": True,
                "token": token,
                "user": {
                    "user_id": user_id,
                    "email": email,
                    "company": company,
                    "org_id": org_id,
                },
            }
        ),
        201,
    )


@app.route("/api/auth/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    users = load_data(USERS_FILE)
    user = users.get(email)

    if not user or not bcrypt.checkpw(
        password.encode(), user["password_hash"].encode()
    ):
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user["user_id"], user["org_id"])

    return (
        jsonify(
            {
                "success": True,
                "token": token,
                "user": {
                    "user_id": user["user_id"],
                    "email": email,
                    "company": user["company"],
                    "org_id": user["org_id"],
                    "plan": user["plan"],
                },
            }
        ),
        200,
    )


@app.route("/api/player/check-pairing", methods=["POST", "OPTIONS"])
def player_check_pairing():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json()
    device_id = data.get("device_id")
    pairing_code = data.get("pairing_code")

    pairing_requests = load_data(PAIRING_FILE)
    pairing_info = pairing_requests.get(pairing_code)

    if not pairing_info or pairing_info.get("device_id") != device_id:
        return jsonify({"paired": False}), 200

    if not pairing_info.get("paired"):
        return jsonify({"paired": False}), 200

    player_id = pairing_info["player_id"]
    token = generate_token(device_id, pairing_info.get("org_id"))

    return (
        jsonify(
            {
                "paired": True,
                "token": token,
                "player_id": player_id,
                "player_name": pairing_info.get("player_name", "Player"),
            }
        ),
        200,
    )


@app.route("/api/player/get-content", methods=["POST", "OPTIONS"])
def player_get_content():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json()
    device_id = data.get("device_id")
    token = data.get("token")

    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    players = load_data(PLAYERS_FILE)
    player = None
    for p in players.values():
        if p.get("device_id") == device_id:
            player = p
            break

    if not player:
        return jsonify({"error": "Player not found"}), 404

    player["last_seen"] = datetime.utcnow().isoformat()
    player["status"] = "online"
    players[player["player_id"]] = player
    save_data(PLAYERS_FILE, players)

    content_url = (
        player.get("content_url")
        or "data:text/html,<html><body style='margin:0;background:linear-gradient(135deg,%23667eea,%23764ba2);display:flex;align-items:center;justify-content:center;height:100vh;color:white;font-family:sans-serif'><div style='text-align:center'><h1 style='font-size:4em'>🎬 SMP</h1><p style='font-size:2em'>Digital Signage</p></div></body></html>"
    )

    return (
        jsonify(
            {
                "content_url": content_url,
                "refresh_interval": 300,
                "updated_at": datetime.utcnow().isoformat(),
            }
        ),
        200,
    )


@app.route("/api/admin/pair-device", methods=["POST", "OPTIONS"])
def admin_pair_device():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json()
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)

    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    pairing_code = data.get("pairing_code")
    player_name = data.get("player_name", "New Player")

    player_id = f"player-{secrets.token_urlsafe(16)}"
    device_id = f"device-{secrets.token_urlsafe(16)}"

    players = load_data(PLAYERS_FILE)
    players[player_id] = {
        "player_id": player_id,
        "name": player_name,
        "device_id": device_id,
        "org_id": payload["org_id"],
        "status": "online",
        "paired_at": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "content_url": None,
        "location": data.get("location", ""),
        "uptime": "0h",
        "content": "None",
    }
    save_data(PLAYERS_FILE, players)

    pairing_requests = load_data(PAIRING_FILE)
    pairing_requests[pairing_code] = {
        "paired": True,
        "player_id": player_id,
        "device_id": device_id,
        "player_name": player_name,
        "org_id": payload["org_id"],
    }
    save_data(PAIRING_FILE, pairing_requests)

    return (
        jsonify({"success": True, "player_id": player_id, "player_name": player_name}),
        200,
    )


@app.route("/api/admin/players", methods=["GET", "OPTIONS"])
def admin_list_players():
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)

    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    org_id = payload["org_id"]
    players = load_data(PLAYERS_FILE)

    org_players = []
    for player in players.values():
        if player.get("org_id") == org_id:
            last_seen = datetime.fromisoformat(player["last_seen"])
            if datetime.utcnow() - last_seen > timedelta(minutes=10):
                player["status"] = "offline"
            org_players.append(player)

    return jsonify({"players": org_players}), 200


@app.route("/api/admin/assign-content", methods=["POST", "OPTIONS"])
def admin_assign_content():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json()
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)

    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    player_id = data.get("player_id")
    content_url = data.get("content_url")

    players = load_data(PLAYERS_FILE)
    player = players.get(player_id)

    if not player or player.get("org_id") != payload["org_id"]:
        return jsonify({"error": "Player not found"}), 404

    player["content_url"] = content_url
    player["content_updated_at"] = datetime.utcnow().isoformat()
    players[player_id] = player
    save_data(PLAYERS_FILE, players)

    return jsonify({"success": True}), 200


@app.route("/health", methods=["GET"])
def health():
    players = load_data(PLAYERS_FILE)
    active = sum(
        1
        for p in players.values()
        if (
            datetime.utcnow()
            - datetime.fromisoformat(p.get("last_seen", datetime.utcnow().isoformat()))
        )
        < timedelta(minutes=10)
    )

    return (
        jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "players": {"total": len(players), "online": active},
            }
        ),
        200,
    )


@app.route("/", methods=["GET"])
def index():
    return (
        jsonify(
            {"name": "SMP Digital Signage API", "version": "2.0", "status": "running"}
        ),
        200,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

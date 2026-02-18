from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import secrets
import string
import os
import bcrypt
from datetime import datetime, timedelta
import jwt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///smp.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    org_id = db.Column(db.String(50), nullable=False)
    company = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    plan = db.Column(db.String(20), default="free")

class Player(db.Model):
    __tablename__ = 'players'
    player_id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    device_id = db.Column(db.String(50), unique=True)
    org_id = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="offline")
    paired_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    content_url = db.Column(db.Text)
    location = db.Column(db.String(120))
    uptime = db.Column(db.String(20), default="0h")
    content = db.Column(db.String(120), default="None")
    pairing_code = db.Column(db.String(10))

class Pairing(db.Model):
    __tablename__ = "pairings"
    pairing_code = db.Column(db.String(10), primary_key=True)
    paired = db.Column(db.Boolean, default=False)
    player_id = db.Column(db.String(50))
    device_id = db.Column(db.String(50))
    player_name = db.Column(db.String(120))
    org_id = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PairingRequest(db.Model):
    __tablename__ = "pairing_requests"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), nullable=False)
    pairing_code = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default="waiting")  # "waiting", "paired"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id = f"user-{secrets.token_urlsafe(16)}"
    org_id = f"org-{secrets.token_urlsafe(16)}"

    new_user = User(
        id=user_id,
        email=email,
        password_hash=password_hash,
        org_id=org_id,
        company=company,
        plan="free"
    )

    db.session.add(new_user)
    db.session.commit()
    
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

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.checkpw(
        password.encode(), user.password_hash.encode()
    ):
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user.id, user.org_id)

    return (
        jsonify(
            {
                "success": True,
                "token": token,
                "user": {
                    "user_id": user.id,
                    "email": email,
                    "company": user.company,
                    "org_id": user.org_id,
                    "plan": user.plan,
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

    pairing_info = Pairing.query.filter_by(pairing_code=pairing_code).first()

    if not pairing_info or pairing_info.device_id != device_id:
        return jsonify({"paired": False}), 200

    if not pairing_info.paired:
        return jsonify({"paired": False}), 200

    player_id = pairing_info.player_id
    token = generate_token(device_id, pairing_info.org_id)

    return (
        jsonify(
            {
                "paired": True,
                "token": token,
                "player_id": player_id,
                "player_name": pairing_info.player_name or "Player",
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

    player = Player.query.filter_by(device_id=device_id).first()

    if not player:
        return jsonify({"error": "Player not found"}), 404

    player.last_seen = datetime.utcnow()
    player.status = "online"
    db.session.commit()

    content_url = (
        player.content_url
        or "data:text/html,<html><body style='margin:0;background:linear-gradient(135deg,%23667eea,%23764ba2);display:flex;align-items:center;justify-content:center;height:100vh;color:white;font-family:sans-serif'><div style='text-align:center'><h1 style='font-size:4em'>🎬 SMP</h1><p style='font-size:2em'>Digital Signage</p></div></body></html>"
    )

    return (
        jsonify(
            {
                "content_url": content_url,
                "refresh_interval": 300,
                "updated_at": player.last_seen.isoformat(),
            }
        ),
        200,
    )


@app.route("/api/admin/pair-device", methods=["POST", "OPTIONS"], strict_slashes=False)
def admin_pair_device():
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)

    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    pairing_code = data.get("pairing_code")
    if pairing_code:
        pairing_code = str(pairing_code).strip()
    
    player_name = data.get("player_name", "New Player")

    if not pairing_code:
        return jsonify({"error": "pairing_code is required"}), 400

    # Look up the pairing request from the device
    req = PairingRequest.query.filter_by(pairing_code=pairing_code, status="waiting").first()
    if not req:
        # Check if it was already paired or doesn't exist
        already_paired = PairingRequest.query.filter_by(pairing_code=pairing_code, status="paired").first()
        if already_paired:
             return jsonify({"error": "This device is already paired"}), 400
        
        # Log or return a more specific error for this case
        # We use 400 instead of 404 here to distinguish from "Route Not Found"
        return jsonify({
            "error": "Invalid or expired pairing code", 
            "detail": f"No waiting pairing request found for code: {pairing_code}. Ensure the device is showing this code."
        }), 400

    device_id = req.device_id
    player_id = f"player-{secrets.token_urlsafe(16)}"

    new_player = Player(
        player_id=player_id,
        name=player_name,
        device_id=device_id,
        org_id=payload["org_id"],
        status="online",
        paired_at=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        location=data.get("location", ""),
        uptime="0h",
        content="None",
        pairing_code=pairing_code
    )
    db.session.add(new_player)

    # Update pairing request status
    req.status = "paired"

    # Maintain legacy Pairing record to ensure compatibility
    pairing_info = Pairing.query.filter_by(pairing_code=pairing_code).first()
    if not pairing_info:
        pairing_info = Pairing(pairing_code=pairing_code)
        db.session.add(pairing_info)
    
    pairing_info.paired = True
    pairing_info.player_id = player_id
    pairing_info.device_id = device_id
    pairing_info.player_name = player_name
    pairing_info.org_id = payload["org_id"]

    db.session.commit()

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
    players = Player.query.filter_by(org_id=org_id).all()

    org_players = []
    for player in players:
        if datetime.utcnow() - player.last_seen > timedelta(minutes=10):
            player.status = "offline"
            db.session.commit()
        
        org_players.append({
            "player_id": player.player_id,
            "name": player.name,
            "device_id": player.device_id,
            "org_id": player.org_id,
            "status": player.status,
            "paired_at": player.paired_at.isoformat(),
            "last_seen": player.last_seen.isoformat(),
            "content_url": player.content_url,
            "location": player.location,
            "uptime": player.uptime,
            "content": player.content,
            "pairing_code": player.pairing_code
        })

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

    player = Player.query.filter_by(player_id=player_id).first()

    if not player or player.org_id != payload["org_id"]:
        return jsonify({"error": "Player not found"}), 404

    player.content_url = content_url
    db.session.commit()

    return jsonify({"success": True}), 200


@app.route("/api/public/register-pairing", methods=["POST", "OPTIONS"], strict_slashes=False)
def register_pairing():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json()
    device_id = data.get("device_id")
    pairing_code = data.get("pairing_code")

    if not device_id or not pairing_code:
        return jsonify({"error": "device_id and pairing_code are required"}), 400

    # Clean up any old requests for this device/code to avoid duplicates
    try:
        PairingRequest.query.filter_by(device_id=device_id).delete()
        PairingRequest.query.filter_by(pairing_code=pairing_code).delete()
        
        new_request = PairingRequest(
            device_id=device_id,
            pairing_code=pairing_code,
            status="waiting"
        )
        db.session.add(new_request)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    return jsonify({"success": True, "message": "Pairing request registered"}), 201


@app.route("/api/public/players", methods=["GET", "OPTIONS"])
def public_list_players():
    if request.method == "OPTIONS":
        return "", 204

    players = Player.query.all()
    player_list = []

    for player in players:
        if datetime.utcnow() - player.last_seen > timedelta(minutes=10):
            player.status = "offline"
            db.session.commit()
        
        player_list.append({
            "player_id": player.player_id,
            "name": player.name,
            "device_id": player.device_id,
            "org_id": player.org_id,
            "status": player.status,
            "paired_at": player.paired_at.isoformat(),
            "last_seen": player.last_seen.isoformat(),
            "content_url": player.content_url,
            "location": player.location,
            "uptime": player.uptime,
            "content": player.content,
            "pairing_code": player.pairing_code
        })

    return jsonify({"players": player_list}), 200


@app.route("/health", methods=["GET"])
def health():
    total_players = Player.query.count()
    active_players = Player.query.filter(
        Player.last_seen > datetime.utcnow() - timedelta(minutes=10)
    ).count()

    return (
        jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "players": {"total": total_players, "online": active_players},
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


# Create tables and start the app
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

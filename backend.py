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
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

# Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///smp.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

R2_ENDPOINT_URL = os.environ.get("R2_ENDPOINT_URL")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME")
R2_PUBLIC_URL = os.environ.get("R2_PUBLIC_URL")

s3_client = boto3.client(
    's3',
    endpoint_url=R2_ENDPOINT_URL,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    region_name='auto',
    config=Config(signature_version='s3v4')
) if R2_ACCESS_KEY_ID else None

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

class Media(db.Model):
    __tablename__ = 'media'
    id = db.Column(db.String(50), primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    mime_type = db.Column(db.String(100))
    url = db.Column(db.Text, nullable=False)
    size_bytes = db.Column(db.Integer, default=0)
    org_id = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

    # Extended power scheduling & default content attributes
    default_content_type = db.Column(db.String(50), default="none")
    default_content_id = db.Column(db.String(50))
    weekday_on = db.Column(db.String(20), default="08:00")
    weekday_off = db.Column(db.String(20), default="22:00")
    weekend_on = db.Column(db.String(20), default="09:00")
    weekend_off = db.Column(db.String(20), default="20:00")
    power_cec = db.Column(db.Boolean, default=True)
    power_override = db.Column(db.String(20), default="none")

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

class Playlist(db.Model):
    __tablename__ = 'playlists'
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    org_id = db.Column(db.String(50), nullable=False)
    items = db.Column(db.JSON, default=[]) # List of {media_id, duration, name, url, type}
    assigned_players = db.Column(db.JSON, default=[]) # List of player_ids
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Layout(db.Model):
    __tablename__ = 'layouts'
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    org_id = db.Column(db.String(50), nullable=False)
    zones = db.Column(db.JSON, default=[]) # List of { id, name, top, left, width, height, layer, bg_color, content_type, content_id }
    aspect_ratio = db.Column(db.String(20), default="16:9")
    is_template = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Schedule(db.Model):
    __tablename__ = 'schedules'
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    content_type = db.Column(db.String(50), nullable=False) # playlist, layout, media
    content_id = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.String(10), nullable=False) # e.g. "08:00"
    end_time = db.Column(db.String(10), nullable=False) # e.g. "17:00"
    start_date = db.Column(db.String(20), nullable=False) # e.g. "2026-06-11"
    end_date = db.Column(db.String(20), nullable=False) # e.g. "2026-06-11"
    repeat_type = db.Column(db.String(20), default="once") # once, daily, weekly, monthly
    days_of_week = db.Column(db.JSON, default=[]) # list of integers (0=Sun, 1=Mon, ..., 6=Sat)
    end_repeat_date = db.Column(db.String(20)) # e.g. "2026-12-31" or null
    priority = db.Column(db.Integer, default=1) # 1=low, 5=critical
    assigned_players = db.Column(db.JSON, default=[]) # List of player_ids
    org_id = db.Column(db.String(50), nullable=False)
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


def is_schedule_active(schedule, current_date_str, current_time_str, day_of_week):
    if current_date_str < schedule.start_date:
        return False
    if schedule.end_repeat_date and current_date_str > schedule.end_repeat_date:
        return False
    if schedule.repeat_type == "once":
        if current_date_str > schedule.end_date:
            return False
    elif schedule.repeat_type == "weekly":
        if day_of_week not in (schedule.days_of_week or []):
            return False
    elif schedule.repeat_type == "monthly":
        try:
            start_day = schedule.start_date.split("-")[2]
            curr_day = current_date_str.split("-")[2]
            if start_day != curr_day:
                return False
        except:
            return False
    
    start_t = schedule.start_time
    end_t = schedule.end_time
    curr_t = current_time_str
    if start_t <= end_t:
        if not (start_t <= curr_t <= end_t):
            return False
    else:
        if not (curr_t >= start_t or curr_t <= end_t):
            return False
    return True

@app.route("/api/player/get-content", methods=["POST", "OPTIONS"])
def player_get_content():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json() or {}
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

    import datetime as dt
    current_time_str = data.get("current_time")
    current_date_str = data.get("current_date")
    day_of_week = data.get("day_of_week")

    now = dt.datetime.now()
    if not current_time_str:
        current_time_str = now.strftime("%H:%M")
    if not current_date_str:
        current_date_str = now.strftime("%Y-%m-%d")
    if day_of_week is None:
        day_of_week = (now.weekday() + 1) % 7

    # 1. Screen Power Schedule Evaluation
    screen_on = True
    override = player.power_override or "none"
    
    if override == "always_off":
        screen_on = False
    elif override == "always_on":
        screen_on = True
    else:
        is_weekend = day_of_week in [0, 6]
        on_time = player.weekend_on if is_weekend else player.weekday_on
        off_time = player.weekend_off if is_weekend else player.weekday_off
        
        if not on_time: on_time = "08:00"
        if not off_time: off_time = "22:00"
        
        if on_time <= off_time:
            screen_on = (on_time <= current_time_str <= off_time)
        else:
            screen_on = (current_time_str >= on_time or current_time_str <= off_time)

    if not screen_on:
        return jsonify({
            "content_url": f"{request.host_url}public/screen-off" if request.host_url else "/public/screen-off",
            "refresh_interval": 60,
            "updated_at": player.last_seen.isoformat(),
            "power_state": "off"
        }), 200

    # 2. Evaluate Active Schedules
    schedules = Schedule.query.all()
    active_matches = []
    
    for s in schedules:
        if player.player_id in (s.assigned_players or []):
            if is_schedule_active(s, current_date_str, current_time_str, day_of_week):
                url = ""
                name = s.name
                if s.content_type == "layout":
                    url = f"/public/layouts/{s.content_id}"
                elif s.content_type == "playlist":
                    url = f"/public/playlists/{s.content_id}"
                elif s.content_type == "media":
                    media = Media.query.filter_by(id=s.content_id).first()
                    url = media.url if media else ""
                
                if url:
                    active_matches.append({
                        "priority": s.priority or 1,
                        "created_at": s.created_at,
                        "url": url,
                        "name": name
                    })

    resolved_url = None
    resolved_name = "None"
    
    if active_matches:
        active_matches.sort(key=lambda x: (x["priority"], x["created_at"]), reverse=True)
        resolved_url = active_matches[0]["url"]
        resolved_name = active_matches[0]["name"]
    else:
        def_type = player.default_content_type or "none"
        def_id = player.default_content_id
        
        if def_type == "layout" and def_id:
            resolved_url = f"/public/layouts/{def_id}"
            layout = Layout.query.filter_by(id=def_id).first()
            resolved_name = f"Default Layout: {layout.name}" if layout else "Default Layout"
        elif def_type == "playlist" and def_id:
            resolved_url = f"/public/playlists/{def_id}"
            playlist = Playlist.query.filter_by(id=def_id).first()
            resolved_name = f"Default Playlist: {playlist.name}" if playlist else "Default Playlist"
        elif def_type == "media" and def_id:
            media = Media.query.filter_by(id=def_id).first()
            if media:
                resolved_url = media.url
                resolved_name = f"Default Media: {media.original_filename}"

    if not resolved_url:
        resolved_url = player.content_url or "data:text/html,<html><body style='margin:0;background:linear-gradient(135deg,%23667eea,%23764ba2);display:flex;align-items:center;justify-content:center;height:100vh;color:white;font-family:sans-serif'><div style='text-align:center'><h1 style='font-size:4em'>🎬 SMP</h1><p style='font-size:2em'>Digital Signage</p></div></body></html>"
        resolved_name = player.content or "None"

    if resolved_url.startswith("/public/"):
        resolved_url = request.host_url + resolved_url.lstrip("/")

    player.content = resolved_name
    db.session.commit()

    return (
        jsonify(
            {
                "content_url": resolved_url,
                "refresh_interval": 300,
                "updated_at": player.last_seen.isoformat(),
                "power_state": "on"
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
            "pairing_code": player.pairing_code,
            "default_content_type": player.default_content_type or "none",
            "default_content_id": player.default_content_id,
            "weekday_on": player.weekday_on or "08:00",
            "weekday_off": player.weekday_off or "22:00",
            "weekend_on": player.weekend_on or "09:00",
            "weekend_off": player.weekend_off or "20:00",
            "power_cec": player.power_cec if player.power_cec is not None else True,
            "power_override": player.power_override or "none",
        })

    return jsonify({"players": org_players}), 200


@app.route("/api/admin/pairing-requests", methods=["GET", "OPTIONS"], strict_slashes=False)
def admin_list_pairing_requests():
    if request.method == "OPTIONS":
        return "", 204
    
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    requests = PairingRequest.query.filter_by(status="waiting").all()
    return jsonify({
        "pairing_requests": [
            {
                "id": req.id,
                "device_id": req.device_id,
                "pairing_code": req.pairing_code,
                "created_at": req.created_at.isoformat()
            } for req in requests
        ]
    }), 200


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

@app.route("/api/admin/media/upload", methods=["POST", "OPTIONS"])
def admin_upload_media():
    if request.method == "OPTIONS":
        return "", 204
    
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401
    
    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401
    
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
        
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
        
    original_filename = secure_filename(file.filename)
    extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    media_id = f"media-{secrets.token_urlsafe(16)}"
    filename = f"{media_id}.{extension}"
    
    file_type = "image"
    if extension in ['mp4', 'webm', 'mov']:
        file_type = "video"
    elif extension not in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg']:
        return jsonify({"error": "Unsupported file type"}), 400
        
    file_content = file.read()
    size_bytes = len(file_content)
    
    url = ""
    if s3_client:
        try:
            s3_client.put_object(
                Bucket=R2_BUCKET_NAME,
                Key=filename,
                Body=file_content,
                ContentType=file.mimetype
            )
            url = f"{R2_PUBLIC_URL}/{filename}"
        except ClientError as e:
            return jsonify({"error": f"Failed to upload to cloud storage: {str(e)}"}), 500
    else:
        uploads_dir = os.path.join(app.root_path, "static", "uploads")
        if not os.path.exists(uploads_dir):
            os.makedirs(uploads_dir)
            
        file_path = os.path.join(uploads_dir, filename)
        with open(file_path, "wb") as f:
            f.write(file_content)
        
        url = request.host_url + f"static/uploads/{filename}"
    
    new_media = Media(
        id=media_id,
        filename=filename,
        original_filename=original_filename,
        file_type=file_type,
        mime_type=file.mimetype,
        url=url,
        size_bytes=size_bytes,
        org_id=payload["org_id"]
    )
    
    db.session.add(new_media)
    db.session.commit()
    
    return jsonify({
        "success": True,
        "media": {
            "id": media_id,
            "filename": filename,
            "original_filename": original_filename,
            "file_type": file_type,
            "url": url,
            "size_bytes": size_bytes,
            "created_at": new_media.created_at.isoformat()
        }
    }), 201

@app.route("/api/admin/media", methods=["GET", "OPTIONS"])
def admin_list_media():
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    media_items = Media.query.filter_by(org_id=payload["org_id"]).order_by(Media.created_at.desc()).all()
    
    return jsonify({
        "media": [{
            "id": m.id,
            "filename": m.filename,
            "original_filename": m.original_filename,
            "file_type": m.file_type,
            "mime_type": m.mime_type,
            "url": m.url,
            "size_bytes": m.size_bytes,
            "created_at": m.created_at.isoformat()
        } for m in media_items]
    }), 200

@app.route("/api/admin/media/<media_id>", methods=["DELETE", "OPTIONS"])
def admin_delete_media(media_id):
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    media = Media.query.filter_by(id=media_id).first()
    if not media or media.org_id != payload["org_id"]:
        return jsonify({"error": "Media not found"}), 404

    try:
        if s3_client:
            s3_client.delete_object(Bucket=R2_BUCKET_NAME, Key=media.filename)
    except ClientError:
        pass 

    db.session.delete(media)
    db.session.commit()

    return jsonify({"success": True}), 200

@app.route("/api/admin/media/<media_id>", methods=["PUT", "OPTIONS"])
def admin_rename_media(media_id):
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
    new_name = data.get("name")
    if not new_name:
         return jsonify({"error": "New name required"}), 400

    media = Media.query.filter_by(id=media_id).first()
    if not media or media.org_id != payload["org_id"]:
        return jsonify({"error": "Media not found"}), 404

    media.original_filename = new_name
    db.session.commit()

    return jsonify({"success": True, "original_filename": new_name}), 200

# --- Playlist Endpoints ---

@app.route("/api/admin/playlists", methods=["GET", "OPTIONS"])
def admin_list_playlists():
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    playlists = Playlist.query.filter_by(org_id=payload["org_id"]).order_by(Playlist.created_at.desc()).all()
    
    return jsonify({
        "playlists": [{
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "items": p.items,
            "assigned_players": p.assigned_players,
            "created_at": p.created_at.isoformat()
        } for p in playlists]
    }), 200

@app.route("/api/admin/playlists", methods=["POST", "OPTIONS"])
def admin_create_playlist():
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
    name = data.get("name")
    if not name:
        return jsonify({"error": "Playlist name required"}), 400

    playlist_id = f"playlist-{secrets.token_urlsafe(16)}"
    new_playlist = Playlist(
        id=playlist_id,
        name=name,
        description=data.get("description", ""),
        items=data.get("items", []),
        assigned_players=data.get("assigned_players", []),
        org_id=payload["org_id"]
    )

    db.session.add(new_playlist)
    db.session.commit()

    return jsonify({"success": True, "id": playlist_id}), 201

@app.route("/api/admin/playlists/<playlist_id>", methods=["PUT", "OPTIONS"])
def admin_update_playlist(playlist_id):
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    playlist = Playlist.query.filter_by(id=playlist_id).first()
    if not playlist or playlist.org_id != payload["org_id"]:
        return jsonify({"error": "Playlist not found"}), 404

    data = request.get_json()
    playlist.name = data.get("name", playlist.name)
    playlist.description = data.get("description", playlist.description)
    playlist.items = data.get("items", playlist.items)
    playlist.assigned_players = data.get("assigned_players", playlist.assigned_players)

    db.session.commit()
    return jsonify({"success": True}), 200

@app.route("/api/admin/playlists/<playlist_id>", methods=["DELETE", "OPTIONS"])
def admin_delete_playlist(playlist_id):
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    playlist = Playlist.query.filter_by(id=playlist_id).first()
    if not playlist or playlist.org_id != payload["org_id"]:
        return jsonify({"error": "Playlist not found"}), 404

    db.session.delete(playlist)
    db.session.commit()
    return jsonify({"success": True}), 200

@app.route("/api/admin/players/<player_id>/assign-playlist", methods=["POST", "OPTIONS"])
def admin_assign_playlist(player_id):
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
    playlist_id = data.get("playlist_id")

    player = Player.query.filter_by(player_id=player_id).first()
    if not player or player.org_id != payload["org_id"]:
        return jsonify({"error": "Player not found"}), 404

    playlist = Playlist.query.filter_by(id=playlist_id).first()
    if not playlist or playlist.org_id != payload["org_id"]:
        return jsonify({"error": "Playlist not found"}), 404

    # Update player record
    player.content = playlist.name
    # For simplicity, we store the playlist ID or a reference here
    # In a real system, the device would poll for this playlist
    player.content_url = f"/api/public/playlists/{playlist_id}/preview" # Example placeholder
    
    # Update playlist's assigned_players list if not already there
    assigned = list(playlist.assigned_players or [])
    if player_id not in assigned:
        assigned.append(player_id)
        playlist.assigned_players = assigned

    db.session.commit()
    return jsonify({"success": True}), 200

# --- Layout Endpoints ---

@app.route("/api/admin/layouts", methods=["GET", "OPTIONS"])
def admin_list_layouts():
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    layouts = Layout.query.filter_by(org_id=payload["org_id"]).order_by(Layout.created_at.desc()).all()
    
    return jsonify({
        "layouts": [{
            "id": l.id,
            "name": l.name,
            "description": l.description,
            "zones": l.zones,
            "aspect_ratio": l.aspect_ratio,
            "is_template": l.is_template,
            "created_at": l.created_at.isoformat()
        } for l in layouts]
    }), 200

@app.route("/api/admin/layouts", methods=["POST", "OPTIONS"])
def admin_create_layout():
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
    name = data.get("name")
    if not name:
        return jsonify({"error": "Layout name required"}), 400

    layout_id = f"layout-{secrets.token_urlsafe(16)}"
    new_layout = Layout(
        id=layout_id,
        name=name,
        description=data.get("description", ""),
        zones=data.get("zones", []),
        aspect_ratio=data.get("aspect_ratio", "16:9"),
        is_template=data.get("is_template", False),
        org_id=payload["org_id"]
    )

    db.session.add(new_layout)
    db.session.commit()

    return jsonify({"success": True, "id": layout_id}), 201

@app.route("/api/admin/layouts/<layout_id>", methods=["PUT", "OPTIONS"])
def admin_update_layout(layout_id):
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    layout = Layout.query.filter_by(id=layout_id).first()
    if not layout or layout.org_id != payload["org_id"]:
        return jsonify({"error": "Layout not found"}), 404

    data = request.get_json()
    layout.name = data.get("name", layout.name)
    layout.description = data.get("description", layout.description)
    layout.zones = data.get("zones", layout.zones)
    layout.aspect_ratio = data.get("aspect_ratio", layout.aspect_ratio)
    layout.is_template = data.get("is_template", layout.is_template)

    db.session.commit()
    return jsonify({"success": True}), 200

@app.route("/api/admin/layouts/<layout_id>", methods=["DELETE", "OPTIONS"])
def admin_delete_layout(layout_id):
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    layout = Layout.query.filter_by(id=layout_id).first()
    if not layout or layout.org_id != payload["org_id"]:
        return jsonify({"error": "Layout not found"}), 404

    db.session.delete(layout)
    db.session.commit()
    return jsonify({"success": True}), 200

@app.route("/api/admin/players/<player_id>/assign-layout", methods=["POST", "OPTIONS"])
def admin_assign_layout(player_id):
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
    layout_id = data.get("layout_id")

    player = Player.query.filter_by(player_id=player_id).first()
    if not player or player.org_id != payload["org_id"]:
        return jsonify({"error": "Player not found"}), 404

    layout = Layout.query.filter_by(id=layout_id).first()
    if not layout or layout.org_id != payload["org_id"]:
        return jsonify({"error": "Layout not found"}), 404

    player.content = f"Layout: {layout.name}"
    player.content_url = f"/public/layouts/{layout_id}"

    db.session.commit()
    return jsonify({"success": True}), 200

@app.route("/api/public/layouts/<layout_id>", methods=["GET", "OPTIONS"])
def public_get_layout(layout_id):
    if request.method == "OPTIONS":
        return "", 204

    layout = Layout.query.filter_by(id=layout_id).first()
    if not layout:
        return jsonify({"error": "Layout not found"}), 404

    enriched_zones = []
    for zone in (layout.zones or []):
        z = dict(zone)
        content_type = z.get("content_type")
        content_id = z.get("content_id")
        
        if content_type == "playlist" and content_id:
            playlist = Playlist.query.filter_by(id=content_id).first()
            if playlist:
                z["playlist"] = {
                    "id": playlist.id,
                    "name": playlist.name,
                    "items": playlist.items
                }
        elif content_type == "media" and content_id:
            media = Media.query.filter_by(id=content_id).first()
            if media:
                z["media"] = {
                    "id": media.id,
                    "filename": media.filename,
                    "original_filename": media.original_filename,
                    "file_type": media.file_type,
                    "url": media.url
                }
        enriched_zones.append(z)

    return jsonify({
        "id": layout.id,
        "name": layout.name,
        "description": layout.description,
        "zones": enriched_zones,
        "aspect_ratio": layout.aspect_ratio,
        "is_template": layout.is_template,
        "created_at": layout.created_at.isoformat()
    }), 200

@app.route("/api/public/register-pairing", methods=["POST", "OPTIONS"], strict_slashes=False)
def register_pairing():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    device_id = data.get("device_id")
    pairing_code = data.get("pairing_code")

    if device_id:
        device_id = str(device_id).strip()
    if pairing_code:
        pairing_code = str(pairing_code).strip()

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

@app.route("/api/public/playlists/<playlist_id>", methods=["GET", "OPTIONS"])
def public_get_playlist(playlist_id):
    if request.method == "OPTIONS":
        return "", 204

    playlist = Playlist.query.filter_by(id=playlist_id).first()
    if not playlist:
        return jsonify({"error": "Playlist not found"}), 404

    return jsonify({
        "id": playlist.id,
        "name": playlist.name,
        "items": playlist.items,
        "created_at": playlist.created_at.isoformat()
    }), 200

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


# ─── Schedule CRUD Endpoints ────────────────────────────────────────────────

@app.route("/api/admin/schedules", methods=["GET", "OPTIONS"])
def admin_list_schedules():
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
    schedules = Schedule.query.filter_by(org_id=org_id).order_by(Schedule.created_at.desc()).all()

    result = []
    for s in schedules:
        result.append({
            "id": s.id,
            "name": s.name,
            "content_type": s.content_type,
            "content_id": s.content_id,
            "start_time": s.start_time,
            "end_time": s.end_time,
            "start_date": s.start_date,
            "end_date": s.end_date,
            "repeat_type": s.repeat_type,
            "days_of_week": s.days_of_week or [],
            "end_repeat_date": s.end_repeat_date,
            "priority": s.priority,
            "assigned_players": s.assigned_players or [],
            "org_id": s.org_id,
            "created_at": s.created_at.isoformat()
        })

    return jsonify({"schedules": result}), 200


@app.route("/api/admin/schedules", methods=["POST"])
def admin_create_schedule():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    import uuid
    schedule_id = str(uuid.uuid4())

    schedule = Schedule(
        id=schedule_id,
        name=data.get("name", "Untitled Schedule"),
        content_type=data.get("content_type", "playlist"),
        content_id=data.get("content_id", ""),
        start_time=data.get("start_time", "08:00"),
        end_time=data.get("end_time", "17:00"),
        start_date=data.get("start_date", datetime.utcnow().strftime("%Y-%m-%d")),
        end_date=data.get("end_date", datetime.utcnow().strftime("%Y-%m-%d")),
        repeat_type=data.get("repeat_type", "once"),
        days_of_week=data.get("days_of_week", []),
        end_repeat_date=data.get("end_repeat_date"),
        priority=data.get("priority", 1),
        assigned_players=data.get("assigned_players", []),
        org_id=payload["org_id"],
    )

    db.session.add(schedule)
    db.session.commit()

    return jsonify({"success": True, "id": schedule_id}), 201


@app.route("/api/admin/schedules/<schedule_id>", methods=["PUT", "OPTIONS"])
def admin_update_schedule(schedule_id):
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    schedule = Schedule.query.filter_by(id=schedule_id, org_id=payload["org_id"]).first()
    if not schedule:
        return jsonify({"error": "Schedule not found"}), 404

    data = request.get_json() or {}
    if "name" in data: schedule.name = data["name"]
    if "content_type" in data: schedule.content_type = data["content_type"]
    if "content_id" in data: schedule.content_id = data["content_id"]
    if "start_time" in data: schedule.start_time = data["start_time"]
    if "end_time" in data: schedule.end_time = data["end_time"]
    if "start_date" in data: schedule.start_date = data["start_date"]
    if "end_date" in data: schedule.end_date = data["end_date"]
    if "repeat_type" in data: schedule.repeat_type = data["repeat_type"]
    if "days_of_week" in data: schedule.days_of_week = data["days_of_week"]
    if "end_repeat_date" in data: schedule.end_repeat_date = data["end_repeat_date"]
    if "priority" in data: schedule.priority = data["priority"]
    if "assigned_players" in data: schedule.assigned_players = data["assigned_players"]

    db.session.commit()
    return jsonify({"success": True}), 200


@app.route("/api/admin/schedules/<schedule_id>", methods=["DELETE", "OPTIONS"])
def admin_delete_schedule(schedule_id):
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    schedule = Schedule.query.filter_by(id=schedule_id, org_id=payload["org_id"]).first()
    if not schedule:
        return jsonify({"error": "Schedule not found"}), 404

    db.session.delete(schedule)
    db.session.commit()
    return jsonify({"success": True}), 200


# ─── Player Power Settings Endpoint ─────────────────────────────────────────

@app.route("/api/admin/players/<player_id>/power-settings", methods=["PUT", "OPTIONS"])
def admin_update_player_power(player_id):
    if request.method == "OPTIONS":
        return "", 204

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 401

    player = Player.query.filter_by(player_id=player_id, org_id=payload["org_id"]).first()
    if not player:
        return jsonify({"error": "Player not found"}), 404

    data = request.get_json() or {}
    if "weekday_on" in data: player.weekday_on = data["weekday_on"]
    if "weekday_off" in data: player.weekday_off = data["weekday_off"]
    if "weekend_on" in data: player.weekend_on = data["weekend_on"]
    if "weekend_off" in data: player.weekend_off = data["weekend_off"]
    if "power_cec" in data: player.power_cec = data["power_cec"]
    if "power_override" in data: player.power_override = data["power_override"]
    if "default_content_type" in data: player.default_content_type = data["default_content_type"]
    if "default_content_id" in data: player.default_content_id = data["default_content_id"]

    db.session.commit()
    return jsonify({"success": True}), 200


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

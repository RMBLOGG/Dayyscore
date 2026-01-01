from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, date, timedelta
import requests
import os
import json
import hashlib
import threading
import time
import sys
import psycopg2  # Untuk PostgreSQL support
from urllib.parse import urlparse

app = Flask(__name__)

# ===============================
# ENVIRONMENT CONFIGURATION FOR RAILWAY
# ===============================
# Railway secara otomatis menyediakan DATABASE_URL
# Gunakan environment variable atau default untuk development
app.secret_key = os.environ.get("FLASK_SECRET", "football-app-secret-key-change-this-in-production")

# ===============================
# DATABASE CONFIG FOR RAILWAY (PostgreSQL)
# ===============================
def get_database_url():
    """Get database URL with PostgreSQL compatibility for Railway"""
    # Priority: Railway DATABASE_URL -> FOOTBALL_DB_URL -> SQLite default
    db_url = os.environ.get('DATABASE_URL')
    
    if db_url:
        # Railway menggunakan PostgreSQL
        if db_url.startswith('postgres://'):
            # Konversi ke format SQLAlchemy
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        return db_url
    
    # Alternatif jika ada custom URL
    alt_url = os.environ.get('FOOTBALL_DB_URL')
    if alt_url:
        return alt_url
    
    # Default SQLite untuk development
    return 'sqlite:///football_app.db'

app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

# Inisialisasi database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ===============================
# MODELS (TETAP SAMA)
# ===============================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    settings = db.Column(db.Text, default='{}')  # JSON string
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()
    
    def get_settings(self):
        return json.loads(self.settings) if self.settings else {}
    
    def update_settings(self, new_settings):
        current = self.get_settings()
        current.update(new_settings)
        self.settings = json.dumps(current)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    level = db.Column(db.String(20))  # INFO, WARNING, ERROR, DEBUG
    source = db.Column(db.String(50))  # admin, api, system, user
    message = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%H:%M:%S'),
            'level': self.level,
            'source': self.source,
            'message': self.message
        }

class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20))  # string, integer, boolean, json
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # maintenance, api, display, notification
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    @classmethod
    def get_value(cls, key, default=None):
        with app.app_context():
            setting = cls.query.filter_by(key=key).first()
            if setting:
                if setting.value_type == 'boolean':
                    return setting.value.lower() == 'true'
                elif setting.value_type == 'integer':
                    return int(setting.value)
                elif setting.value_type == 'json':
                    return json.loads(setting.value)
                else:
                    return setting.value
            return default
    
    @classmethod
    def set_value(cls, key, value, value_type='string', description=None, category='system', user_id=None):
        with app.app_context():
            setting = cls.query.filter_by(key=key).first()
            if not setting:
                setting = SystemSetting(key=key)
                setting.value_type = value_type
                if description:
                    setting.description = description
                setting.category = category
            
            if value_type == 'boolean':
                setting.value = 'true' if value else 'false'
            elif value_type == 'json':
                setting.value = json.dumps(value)
            else:
                setting.value = str(value)
            
            setting.updated_by = user_id
            db.session.add(setting)
            db.session.commit()
            return setting

class APILog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    endpoint = db.Column(db.String(200))
    method = db.Column(db.String(10))
    response_time = db.Column(db.Float)  # in seconds
    status_code = db.Column(db.Integer)
    api_key_used = db.Column(db.String(50))
    
    @classmethod
    def log_request(cls, endpoint, method, response_time, status_code, api_key):
        with app.app_context():
            log = APILog(
                endpoint=endpoint,
                method=method,
                response_time=response_time,
                status_code=status_code,
                api_key_used=api_key[:50] if api_key else None
            )
            db.session.add(log)
            db.session.commit()

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CacheEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(200), unique=True, index=True)
    value = db.Column(db.Text)
    expires_at = db.Column(db.DateTime, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @classmethod
    def get(cls, key):
        with app.app_context():
            entry = cls.query.filter_by(key=key).first()
            if entry and entry.expires_at > datetime.utcnow():
                return json.loads(entry.value)
            return None
    
    @classmethod
    def set(cls, key, value, ttl=300):  # default 5 minutes
        with app.app_context():
            expires_at = datetime.utcnow() + timedelta(seconds=ttl)
            entry = cls.query.filter_by(key=key).first()
            if entry:
                entry.value = json.dumps(value)
                entry.expires_at = expires_at
            else:
                entry = CacheEntry(
                    key=key,
                    value=json.dumps(value),
                    expires_at=expires_at
                )
            db.session.add(entry)
            db.session.commit()
    
    @classmethod
    def delete(cls, key):
        with app.app_context():
            cls.query.filter_by(key=key).delete()
            db.session.commit()
    
    @classmethod
    def clear_expired(cls):
        with app.app_context():
            cls.query.filter(CacheEntry.expires_at <= datetime.utcnow()).delete()
            db.session.commit()
    
    @classmethod
    def clear_all(cls):
        with app.app_context():
            cls.query.delete()
            db.session.commit()

# ===============================
# GLOBAL VARIABLES
# ===============================
API_KEY = None
BASE_URL = "https://api.football-data.org/v4"
ALL_COMPETITIONS = {
    "WC": "FIFA World Cup",
    "CL": "UEFA Champions League",
    "BL1": "Bundesliga",
    "DED": "Eredivisie",
    "BSA": "Campeonato Brasileiro Série A",
    "PD": "Primera Division",
    "FL1": "Ligue 1",
    "ELC": "Championship",
    "PPL": "Primeira Liga",
    "EC": "European Championship",
    "SA": "Serie A",
    "PL": "Premier League"
}

# ===============================
# HELPER FUNCTIONS
# ===============================
def add_system_log(level, message, source='system', user_id=None):
    """Add system log"""
    with app.app_context():
        log = SystemLog(
            level=level,
            source=source,
            message=message,
            user_id=user_id
        )
        db.session.add(log)
        db.session.commit()

def track_user_activity():
    """Track current user activity"""
    if 'session_id' in session:
        with app.app_context():
            session_entry = UserSession.query.filter_by(session_id=session['session_id']).first()
            if session_entry:
                session_entry.last_activity = datetime.utcnow()
                db.session.commit()

def get_users_online():
    """Get number of active users in last 5 minutes"""
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(minutes=5)
        return UserSession.query.filter(UserSession.last_activity >= cutoff).count()

def get_api_usage_today():
    """Get API calls made today"""
    with app.app_context():
        today = datetime.utcnow().date()
        start_of_day = datetime(today.year, today.month, today.day)
        return APILog.query.filter(APILog.timestamp >= start_of_day).count()

def get_api_rate_limit():
    """Get daily API rate limit"""
    return SystemSetting.get_value('api_rate_limit', 100)

def get_maintenance_mode():
    """Check if maintenance mode is enabled"""
    return SystemSetting.get_value('maintenance_mode', False)

def get_current_api_key():
    """Get current API key from settings"""
    return SystemSetting.get_value('api_key')

def make_api_request(url, method='GET', **kwargs):
    """Make API request with logging"""
    global API_KEY
    if API_KEY is None:
        API_KEY = get_current_api_key()
    
    headers = kwargs.get('headers', {})
    headers['X-Auth-Token'] = API_KEY
    kwargs['headers'] = headers
    
    start_time = time.time()
    
    try:
        response = requests.request(method, url, **kwargs)
        response_time = time.time() - start_time
        
        # Log the API call
        APILog.log_request(
            endpoint=url,
            method=method,
            response_time=response_time,
            status_code=response.status_code,
            api_key=API_KEY
        )
        
        if response.status_code == 429:
            add_system_log('WARNING', f'API rate limit exceeded: {url}', 'api')
        elif response.status_code != 200:
            add_system_log('ERROR', f'API error {response.status_code}: {url}', 'api')
        
        return response
        
    except Exception as e:
        response_time = time.time() - start_time
        APILog.log_request(
            endpoint=url,
            method=method,
            response_time=response_time,
            status_code=0,
            api_key=API_KEY
        )
        add_system_log('ERROR', f'API request failed: {str(e)}', 'api')
        raise

# ===============================
# BACKGROUND CLEANUP THREAD
# ===============================
def cleanup_tasks():
    """Run cleanup tasks periodically"""
    while True:
        try:
            # Sleep first to let app fully start
            time.sleep(60)
            
            with app.app_context():
                # Clean up old sessions (older than 24 hours)
                cutoff = datetime.utcnow() - timedelta(hours=24)
                deleted_sessions = UserSession.query.filter(UserSession.last_activity < cutoff).delete()
                
                # Clean up expired cache
                deleted_cache = CacheEntry.query.filter(CacheEntry.expires_at <= datetime.utcnow()).delete()
                
                db.session.commit()
                
                if deleted_sessions > 0 or deleted_cache > 0:
                    add_system_log('INFO', f'Cleanup: {deleted_sessions} sessions, {deleted_cache} cache entries removed', 'system')
                
        except Exception as e:
            print(f"Cleanup error: {e}")
            time.sleep(300)  # Sleep longer on error
        else:
            time.sleep(300)  # Sleep 5 minutes between cleanups

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_tasks, daemon=True)
cleanup_thread.start()

# ===============================
# INITIALIZE DATABASE
# ===============================
def init_database():
    """Initialize database with default data"""
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Run migrations jika ada
        try:
            from flask_migrate import upgrade
            upgrade()
            print("✓ Database migrations applied")
        except Exception as e:
            print(f"Note: Migrations not available or error: {e}")
        
        # Create default admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('Ubg72yisQwlc')
            db.session.add(admin_user)
            db.session.commit()
            print("✓ Created default admin user: admin / Ubg72yisQwlc")
        else:
            print("✓ Admin user already exists")
        
        # Initialize default system settings
        default_settings = [
            ('maintenance_mode', 'false', 'boolean', 'Enable maintenance mode for all users', 'maintenance'),
            ('api_key', os.environ.get("FOOTBALL_API_KEY", "450de9a377b74884a6cc15b28f40f5bc"), 'string', 'Football Data API Key', 'api'),
            ('api_rate_limit', '100', 'integer', 'Daily API call limit', 'api'),
            ('refresh_interval', '60', 'integer', 'Auto-refresh interval in seconds', 'display'),
            ('cache_duration', '300', 'integer', 'Cache duration in seconds', 'system'),
            ('theme', 'dark', 'string', 'Default theme', 'display'),
            ('enable_animations', 'true', 'boolean', 'Enable UI animations', 'display'),
            ('enable_notifications', 'true', 'boolean', 'Enable browser notifications', 'notification'),
            ('reminder_minutes', '15', 'integer', 'Match reminder minutes before', 'notification'),
            ('default_league', 'PL', 'string', 'Default league to show', 'user'),
            ('timezone', 'WIB', 'string', 'Default timezone', 'user'),
        ]
        
        for key, value, value_type, description, category in default_settings:
            if not SystemSetting.query.filter_by(key=key).first():
                SystemSetting.set_value(key, value, value_type, description, category)
                print(f"✓ Created setting: {key}")
        
        add_system_log('INFO', 'System initialized', 'system')
        print("✓ Database initialized successfully")

# ===============================
# TEMPLATE FILTERS
# ===============================
@app.template_filter("datetimeformat")
def datetimeformat(value, format="%d %b %Y, %H:%M"):
    try:
        if isinstance(value, str):
            value = value.replace("Z", "+00:00")
            value = datetime.fromisoformat(value)
        return value.strftime(format)
    except Exception:
        return value

# ===============================
# MIDDLEWARE
# ===============================
@app.before_request
def before_request():
    """Middleware for each request"""
    # Initialize session
    if 'session_id' not in session:
        session['session_id'] = os.urandom(16).hex()
    
    # Track user session
    with app.app_context():
        session_entry = UserSession.query.filter_by(session_id=session['session_id']).first()
        if not session_entry:
            session_entry = UserSession(
                session_id=session['session_id'],
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                user_id=session.get('user_id')
            )
            db.session.add(session_entry)
        else:
            session_entry.last_activity = datetime.utcnow()
            session_entry.user_id = session.get('user_id')
        
        db.session.commit()
    
    # Check maintenance mode
    if get_maintenance_mode():
        exempt_paths = ['/static', '/admin', '/admin/login', '/admin/logout', 
                       '/admin/toggle_maintenance', '/admin/refresh_cache',
                       '/health', '/maintenance', '/debug']
        
        for path in exempt_paths:
            if request.path.startswith(path):
                return
        
        return redirect('/maintenance')

# ===============================
# ADMIN ROUTES
# ===============================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin"):
        return redirect("/admin")
    
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password) and user.is_admin:
                session["admin"] = True
                session["user_id"] = user.id
                session["username"] = user.username
                
                add_system_log('INFO', f'Admin login: {username}', 'admin', user.id)
                return redirect("/admin")
            else:
                error = "Invalid username or password"
                add_system_log('WARNING', f'Failed admin login attempt: {username}', 'security')
    
    return render_template("admin_login.html", error=error)

@app.route("/admin/logout")
def admin_logout():
    user_id = session.get('user_id')
    username = session.get('username')
    
    add_system_log('INFO', f'Admin logout: {username}', 'admin', user_id)
    
    session.clear()
    return redirect("/")

@app.route("/admin", methods=["GET"])
def admin_panel():
    if not session.get("admin"):
        return redirect("/admin/login")
    
    # Get real statistics
    with app.app_context():
        try:
            # Total upcoming matches
            today = date.today()
            next_week = today + timedelta(days=7)
            url = f"{BASE_URL}/matches?dateFrom={today}&dateTo={next_week}&status=SCHEDULED"
            response = make_api_request(url, timeout=10)
            total_matches = len(response.json().get("matches", [])) if response.status_code == 200 else 0
            
            # Live matches
            url = f"{BASE_URL}/matches?status=LIVE"
            response = make_api_request(url, timeout=10)
            live_matches = len(response.json().get("matches", [])) if response.status_code == 200 else 0
            
            api_status = "OK" if response.status_code == 200 else "ERROR"
            
        except Exception as e:
            total_matches = 0
            live_matches = 0
            api_status = "ERROR"
            add_system_log('ERROR', f'Failed to get match stats: {str(e)}', 'admin', session.get('user_id'))
        
        # Real data
        users_online = get_users_online()
        api_calls_today = get_api_usage_today()
        api_rate_limit = get_api_rate_limit()
        api_usage_percent = min(100, int((api_calls_today / api_rate_limit) * 100)) if api_rate_limit > 0 else 0
        
        # Get recent system logs
        recent_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(20).all()
        
        stats = {
            "total_matches": total_matches,
            "live_matches": live_matches,
            "api_status": api_status,
            "users_online": users_online,
            "api_calls_today": api_calls_today,
            "api_rate_limit": api_rate_limit,
            "api_usage_percent": api_usage_percent,
            "maintenance_mode": get_maintenance_mode(),
            "cache_size": CacheEntry.query.count()
        }
    
    return render_template(
        "admin.html", 
        stats=stats,
        recent_logs=recent_logs,
        current_time=datetime.now().strftime("%H:%M:%S"),
        admin_username=session.get("username")
    )

@app.route("/admin/toggle_maintenance", methods=["POST"])
def toggle_maintenance():
    if not session.get("admin"):
        return jsonify({"error": "Unauthorized"}), 401
    
    current_mode = get_maintenance_mode()
    new_mode = not current_mode
    
    SystemSetting.set_value(
        'maintenance_mode', 
        new_mode, 
        value_type='boolean',
        description='Enable maintenance mode for all users',
        category='maintenance',
        user_id=session.get('user_id')
    )
    
    action = "enabled" if new_mode else "disabled"
    add_system_log('INFO', f'Maintenance mode {action}', 'admin', session.get('user_id'))
    
    return jsonify({
        "success": True, 
        "maintenance_mode": new_mode,
        "message": f"Maintenance mode {action}"
    })

@app.route("/admin/refresh_cache", methods=["POST"])
def refresh_cache():
    if not session.get("admin"):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        CacheEntry.clear_all()
        add_system_log('INFO', 'Cache cleared manually', 'admin', session.get('user_id'))
        
        return jsonify({
            "success": True, 
            "message": "Cache refreshed successfully",
            "cache_size": 0
        })
        
    except Exception as e:
        add_system_log('ERROR', f'Failed to clear cache: {str(e)}', 'admin', session.get('user_id'))
        return jsonify({
            "success": False, 
            "error": str(e)
        }), 500

@app.route("/admin/update_setting", methods=["POST"])
def update_setting():
    if not session.get("admin"):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')
    value_type = data.get('value_type', 'string')
    
    if not key:
        return jsonify({"error": "Key is required"}), 400
    
    try:
        setting = SystemSetting.set_value(
            key, value, value_type,
            user_id=session.get('user_id')
        )
        
        add_system_log('INFO', f'Setting updated: {key} = {value}', 'admin', session.get('user_id'))
        
        return jsonify({
            "success": True,
            "message": f"Setting '{key}' updated",
            "setting": {
                "key": setting.key,
                "value": setting.value,
                "value_type": setting.value_type
            }
        })
        
    except Exception as e:
        add_system_log('ERROR', f'Failed to update setting {key}: {str(e)}', 'admin', session.get('user_id'))
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/admin/get_logs", methods=["GET"])
def get_logs():
    if not session.get("admin"):
        return jsonify({"error": "Unauthorized"}), 401
    
    limit = request.args.get('limit', 100, type=int)
    level = request.args.get('level')
    source = request.args.get('source')
    
    with app.app_context():
        query = SystemLog.query
        
        if level:
            query = query.filter_by(level=level)
        if source:
            query = query.filter_by(source=source)
        
        logs = query.order_by(SystemLog.timestamp.desc()).limit(limit).all()
        
        return jsonify({
            "success": True,
            "logs": [log.to_dict() for log in logs],
            "count": len(logs)
        })

@app.route("/admin/backup", methods=["POST"])
def backup_system():
    if not session.get("admin"):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = "backups"
        
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        backup_file = os.path.join(backup_dir, f"backup_{timestamp}.json")
        
        with app.app_context():
            # Collect data to backup
            backup_data = {
                "timestamp": timestamp,
                "system_settings": [],
                "users_count": User.query.count(),
                "logs_count": SystemLog.query.count(),
                "api_logs_count": APILog.query.count()
            }
            
            # Backup system settings
            settings = SystemSetting.query.all()
            backup_data["system_settings"] = [
                {
                    "key": s.key,
                    "value": s.value,
                    "value_type": s.value_type,
                    "description": s.description,
                    "category": s.category,
                    "updated_at": s.updated_at.isoformat() if s.updated_at else None
                }
                for s in settings
            ]
        
        # Save to file
        with open(backup_file, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        add_system_log('INFO', f'System backup created: {backup_file}', 'admin', session.get('user_id'))
        
        return jsonify({
            "success": True,
            "message": "Backup created successfully",
            "backup_file": backup_file,
            "backup_size": os.path.getsize(backup_file)
        })
        
    except Exception as e:
        add_system_log('ERROR', f'Backup failed: {str(e)}', 'admin', session.get('user_id'))
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ===============================
# SETTINGS ROUTES
# ===============================
@app.route("/settings", methods=["GET", "POST"])
def settings():
    is_admin = session.get("admin", False)
    
    if request.method == "POST":
        if not session.get("user_id"):
            return redirect("/admin/login")
        
        with app.app_context():
            user = User.query.get(session["user_id"])
            if not user:
                return redirect("/admin/login")
            
            # Get form data
            form_data = request.form.to_dict()
            
            # Convert checkbox values to boolean
            for key in form_data:
                if form_data[key] == 'on':
                    form_data[key] = True
                elif form_data[key] == 'off':
                    form_data[key] = False
            
            # Update user settings
            user.update_settings(form_data)
            db.session.commit()
            
            add_system_log('INFO', 'User settings updated', 'user', user.id)
        
        return redirect("/settings?success=1")
    
    # Get user settings
    user_settings = {}
    if session.get("user_id"):
        with app.app_context():
            user = User.query.get(session["user_id"])
            if user:
                user_settings = user.get_settings()
    
    # Get system settings for display
    system_settings = {}
    with app.app_context():
        settings_db = SystemSetting.query.filter_by(category='display').all()
        for s in settings_db:
            system_settings[s.key] = s.value
    
    return render_template(
        "settings.html", 
        is_admin=is_admin,
        user_settings=user_settings,
        system_settings=system_settings,
        username=session.get("username")
    )

@app.route("/api/settings/save", methods=["POST"])
def save_settings_api():
    if not session.get("user_id"):
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    with app.app_context():
        user = User.query.get(session["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        try:
            user.update_settings(data)
            db.session.commit()
            
            add_system_log('INFO', 'Settings saved via API', 'user', user.id)
            
            return jsonify({
                "success": True,
                "message": "Settings saved successfully"
            })
            
        except Exception as e:
            add_system_log('ERROR', f'Failed to save settings: {str(e)}', 'user', user.id)
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

# ===============================
# MAINTENANCE PAGE
# ===============================
@app.route("/maintenance")
def maintenance():
    # Get maintenance message from settings
    message = SystemSetting.get_value('maintenance_message', 
                                     'We are performing scheduled maintenance. Please check back soon.')
    
    # Estimate end time (current time + 2 hours)
    estimated_end = datetime.now() + timedelta(hours=2)
    
    return render_template(
        "maintenance.html",
        message=message,
        estimated_end=estimated_end.strftime("%H:%M")
    )

# ===============================
# MAIN PAGES
# ===============================
@app.route("/")
def index():
    cache_key = f"upcoming_matches_{date.today()}"
    
    # Try cache first
    cached_data = CacheEntry.get(cache_key)
    if cached_data:
        grouped_matches = cached_data
        add_system_log('DEBUG', 'Serving upcoming matches from cache', 'cache')
    else:
        today = date.today()
        next_week = today + timedelta(days=7)
        
        url = f"{BASE_URL}/matches?dateFrom={today}&dateTo={next_week}&status=SCHEDULED"
        
        try:
            response = make_api_request(url, timeout=15)
            data = response.json()
            matches = data.get("matches", [])
            
            # Group by competition
            competitions = {}
            for m in matches:
                comp = m.get("competition", {})
                code = comp.get("code")
                
                if code and code in ALL_COMPETITIONS:
                    if code not in competitions:
                        competitions[code] = {
                            "competition": comp,
                            "matches": []
                        }
                    competitions[code]["matches"].append(m)
            
            # Add empty competitions
            for code, name in ALL_COMPETITIONS.items():
                if code not in competitions:
                    competitions[code] = {
                        "competition": {
                            "code": code,
                            "name": name,
                            "emblem": None
                        },
                        "matches": []
                    }
            
            # Sort matches per league
            for c in competitions.values():
                c["matches"].sort(key=lambda x: x.get("utcDate", ""))
            
            grouped_matches = list(competitions.values())
            
            # Cache for 5 minutes
            CacheEntry.set(cache_key, grouped_matches, ttl=300)
            
        except Exception as e:
            add_system_log('ERROR', f'Failed to fetch upcoming matches: {str(e)}', 'api')
            grouped_matches = []
    
    return render_template(
        "index.html",
        grouped_matches=grouped_matches,
        is_admin=session.get("admin", False)
    )

@app.route("/live")
def live():
    cache_key = "live_matches_current"
    cache_duration = 30  # Live matches cache for 30 seconds
    
    cached_data = CacheEntry.get(cache_key)
    if cached_data:
        matches = cached_data
    else:
        url = f"{BASE_URL}/matches?status=LIVE"
        try:
            response = make_api_request(url, timeout=10)
            data = response.json()
            matches = data.get("matches", [])
            CacheEntry.set(cache_key, matches, ttl=cache_duration)
        except Exception:
            matches = []
            add_system_log('ERROR', 'Failed to fetch live matches', 'api')
    
    return render_template("live.html", matches=matches)

@app.route("/finished")
def finished():
    today = date.today()
    past = today - timedelta(days=3)
    
    cache_key = f"finished_matches_{today}"
    
    cached_data = CacheEntry.get(cache_key)
    if cached_data:
        matches = cached_data
    else:
        url = f"{BASE_URL}/matches?dateFrom={past}&dateTo={today}&status=FINISHED"
        
        try:
            response = make_api_request(url, timeout=10)
            data = response.json()
            matches = data.get("matches", [])
            CacheEntry.set(cache_key, matches, ttl=600)  # Cache for 10 minutes
        except Exception:
            matches = []
            add_system_log('ERROR', 'Failed to fetch finished matches', 'api')
    
    return render_template("finished.html", matches=matches)

@app.route("/standings/<competition_code>")
def standings(competition_code):
    cache_key = f"standings_{competition_code}_{date.today()}"
    
    cached_data = CacheEntry.get(cache_key)
    if cached_data:
        competition_data = cached_data
    else:
        url = f"{BASE_URL}/competitions/{competition_code}/standings"
        
        try:
            response = make_api_request(url, timeout=10)
            data = response.json()
            
            competition = data.get("competition", {})
            standings = data.get("standings", [{}])[0].get("table", [])
            
            competition_data = {
                "competition": competition,
                "standings": standings
            }
            
            CacheEntry.set(cache_key, competition_data, ttl=1800)  # Cache for 30 minutes
            
        except Exception:
            competition = {"name": "Unknown League", "code": competition_code}
            standings = []
            competition_data = {
                "competition": competition,
                "standings": standings
            }
            add_system_log('ERROR', f'Failed to fetch standings for {competition_code}', 'api')
    
    return render_template(
        "standings.html",
        competition=competition_data["competition"],
        standings=competition_data["standings"]
    )

# ===============================
# SYSTEM INFO ROUTES
# ===============================
@app.route("/health")
def health():
    with app.app_context():
        # Check database connection
        db_status = "OK"
        try:
            db.session.execute("SELECT 1")
        except Exception:
            db_status = "ERROR"
        
        # Check API connection
        api_status = "OK"
        try:
            response = make_api_request(f"{BASE_URL}/competitions/PL", timeout=5)
            if response.status_code != 200:
                api_status = "ERROR"
        except Exception:
            api_status = "ERROR"
        
        return jsonify({
            "status": "ok" if db_status == "OK" and api_status == "OK" else "degraded",
            "time": datetime.now().isoformat(),
            "services": {
                "database": db_status,
                "api": api_status,
                "cache": "OK"
            },
            "maintenance_mode": get_maintenance_mode(),
            "users_online": get_users_online(),
            "api_calls_today": get_api_usage_today(),
            "cache_entries": CacheEntry.query.count(),
            "system_logs": SystemLog.query.count()
        })

@app.route("/system/info")
def system_info():
    if not session.get("admin"):
        return jsonify({"error": "Unauthorized"}), 401
    
    import platform
    
    with app.app_context():
        info = {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "flask_version": "2.3.3",
            "database_url": "Configured" if os.environ.get('DATABASE_URL') else "SQLite (Development)",
            "database_size": "N/A",  # Tidak bisa diakses di Railway
            "users_count": User.query.count(),
            "logs_count": SystemLog.query.count(),
            "api_logs_count": APILog.query.count(),
            "cache_entries": CacheEntry.query.count(),
            "sessions_active": UserSession.query.count(),
            "server_time": datetime.now().isoformat(),
            "railway_environment": "Yes" if os.environ.get('RAILWAY_ENVIRONMENT') else "No",
            "deployment_type": os.environ.get('RAILWAY_ENVIRONMENT_NAME', 'Development')
        }
    
    return jsonify(info)

# ===============================
# DEBUG ROUTES
# ===============================
@app.route("/debug")
def debug_page():
    return render_template("debug.html")

@app.route("/debug/admin")
def debug_admin_login():
    # Auto-login as admin for debugging
    with app.app_context():
        user = User.query.filter_by(username='admin').first()
        if user:
            session["admin"] = True
            session["user_id"] = user.id
            session["username"] = user.username
            
            add_system_log('INFO', 'Debug admin auto-login', 'debug', user.id)
    
    return redirect("/admin")

# ===============================
# ERROR HANDLERS
# ===============================
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# ===============================
# RAILWAY SPECIFIC ROUTES
# ===============================
@app.route("/railway/status")
def railway_status():
    """Endpoint khusus untuk memeriksa status Railway"""
    return jsonify({
        "status": "running",
        "environment": os.environ.get('RAILWAY_ENVIRONMENT_NAME', 'development'),
        "timestamp": datetime.now().isoformat(),
        "service": "Football App"
    })

# ===============================
# INITIALIZE AND RUN
# ===============================
def create_app():
    """Factory function untuk membuat app, digunakan oleh Railway"""
    return app

if __name__ == "__main__":
    # Initialize database
    print("=" * 50)
    print("Football App Server Starting...")
    print(f"Environment: {'Railway' if os.environ.get('RAILWAY_ENVIRONMENT') else 'Development'}")
    print("=" * 50)
    
    init_database()
    
    # Set API key
    API_KEY = get_current_api_key()
    
    # Determine port from Railway or use default
    port = int(os.environ.get("PORT", 5000))
    
    print(f"Admin Login: http://localhost:{port}/admin/login")
    print(f"Username: admin")
    print(f"Password: Ubg72yisQwlc")
    print("=" * 50)
    
    # Run the app
    # NOTE: Di Railway, gunakan gunicorn, bukan app.run()
    # Ini hanya untuk development
    app.run(
        debug=not os.environ.get('RAILWAY_ENVIRONMENT'),  # Debug hanya di development
        host="0.0.0.0",  # Penting untuk Railway
        port=port,
        threaded=True,
        use_reloader=False  # Disable reloader untuk threading
    )
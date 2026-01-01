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
from sqlalchemy import desc

app = Flask(__name__)

# ===============================
# CONFIGURATION FOR PRODUCTION
# ===============================
app.secret_key = os.environ.get("FLASK_SECRET", "football-app-secret-key-change-this-in-production")

# ===============================
# DATABASE CONFIG
# ===============================
database_url = os.environ.get('DATABASE_URL')
if database_url:
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///football_app.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ===============================
# MODELS UPDATE
# ===============================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    settings = db.Column(db.Text, default='{}')
    favorite_teams = db.Column(db.Text, default='[]')
    favorite_players = db.Column(db.Text, default='[]')
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
    
    def get_favorite_teams(self):
        return json.loads(self.favorite_teams) if self.favorite_teams else []
    
    def add_favorite_team(self, team_id):
        favorites = self.get_favorite_teams()
        if team_id not in favorites:
            favorites.append(team_id)
            self.favorite_teams = json.dumps(favorites)
    
    def remove_favorite_team(self, team_id):
        favorites = self.get_favorite_teams()
        if team_id in favorites:
            favorites.remove(team_id)
            self.favorite_teams = json.dumps(favorites)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    level = db.Column(db.String(20))
    source = db.Column(db.String(50))
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
    value_type = db.Column(db.String(20))
    description = db.Column(db.Text)
    category = db.Column(db.String(50))
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

class APILog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    endpoint = db.Column(db.String(200))
    method = db.Column(db.String(10))
    response_time = db.Column(db.Float)
    status_code = db.Column(db.Integer)
    api_key_used = db.Column(db.String(50))

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
    def set(cls, key, value, ttl=300):
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

# ===============================
# HELPER FUNCTIONS UPDATE
# ===============================
def add_system_log(level, message, source='system', user_id=None):
    with app.app_context():
        log = SystemLog(
            level=level,
            source=source,
            message=message,
            user_id=user_id
        )
        db.session.add(log)
        db.session.commit()

def get_users_online():
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(minutes=5)
        return UserSession.query.filter(UserSession.last_activity >= cutoff).count()

def get_api_usage_today():
    with app.app_context():
        today = datetime.utcnow().date()
        start_of_day = datetime(today.year, today.month, today.day)
        return APILog.query.filter(APILog.timestamp >= start_of_day).count()

def get_api_rate_limit():
    return SystemSetting.get_value('api_rate_limit', 100)

def get_maintenance_mode():
    return SystemSetting.get_value('maintenance_mode', False)

def get_current_api_key():
    return SystemSetting.get_value('api_key')

def log_api_request(endpoint, method, response_time, status_code, api_key):
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

def make_api_request(url, method='GET', **kwargs):
    API_KEY = get_current_api_key()
    
    headers = kwargs.get('headers', {})
    headers['X-Auth-Token'] = API_KEY
    kwargs['headers'] = headers
    
    start_time = time.time()
    
    try:
        response = requests.request(method, url, **kwargs)
        response_time = time.time() - start_time
        
        log_api_request(
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
        log_api_request(
            endpoint=url,
            method=method,
            response_time=response_time,
            status_code=0,
            api_key=API_KEY
        )
        add_system_log('ERROR', f'API request failed: {str(e)}', 'api')
        raise

# ===============================
# NEW HELPER FUNCTIONS
# ===============================
def get_team_details(team_id):
    cache_key = f"team_{team_id}"
    cached_data = CacheEntry.get(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        url = f"https://api.football-data.org/v4/teams/{team_id}"
        response = make_api_request(url, timeout=10)
        
        if response.status_code == 200:
            team_data = response.json()
            CacheEntry.set(cache_key, team_data, ttl=3600)
            return team_data
        else:
            return None
    except Exception as e:
        add_system_log('ERROR', f'Failed to fetch team {team_id}: {str(e)}', 'api')
        return None

def get_player_details(player_id):
    cache_key = f"player_{player_id}"
    cached_data = CacheEntry.get(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        url = f"https://api.football-data.org/v4/persons/{player_id}"
        response = make_api_request(url, timeout=10)
        
        if response.status_code == 200:
            player_data = response.json()
            CacheEntry.set(cache_key, player_data, ttl=3600)
            return player_data
        else:
            return None
    except Exception as e:
        add_system_log('ERROR', f'Failed to fetch player {player_id}: {str(e)}', 'api')
        return None

def get_match_details(match_id):
    cache_key = f"match_{match_id}"
    cached_data = CacheEntry.get(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        url = f"https://api.football-data.org/v4/matches/{match_id}"
        response = make_api_request(url, timeout=10)
        
        if response.status_code == 200:
            match_data = response.json()
            CacheEntry.set(cache_key, match_data, ttl=600)
            return match_data
        else:
            return None
    except Exception as e:
        add_system_log('ERROR', f'Failed to fetch match {match_id}: {str(e)}', 'api')
        return None

def get_team_matches(team_id, limit=10):
    cache_key = f"team_matches_{team_id}_{limit}"
    cached_data = CacheEntry.get(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        url = f"https://api.football-data.org/v4/teams/{team_id}/matches?limit={limit}"
        response = make_api_request(url, timeout=10)
        
        if response.status_code == 200:
            matches_data = response.json()
            CacheEntry.set(cache_key, matches_data, ttl=300)
            return matches_data
        else:
            return None
    except Exception as e:
        add_system_log('ERROR', f'Failed to fetch team matches {team_id}: {str(e)}', 'api')
        return None

def get_team_squad(team_id):
    cache_key = f"team_squad_{team_id}"
    cached_data = CacheEntry.get(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        url = f"https://api.football-data.org/v4/teams/{team_id}"
        response = make_api_request(url, timeout=10)
        
        if response.status_code == 200:
            team_data = response.json()
            squad = team_data.get('squad', [])
            CacheEntry.set(cache_key, squad, ttl=3600)
            return squad
        else:
            return []
    except Exception as e:
        add_system_log('ERROR', f'Failed to fetch squad {team_id}: {str(e)}', 'api')
        return []

def get_coach_details(coach_id):
    cache_key = f"coach_{coach_id}"
    cached_data = CacheEntry.get(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        url = f"https://api.football-data.org/v4/persons/{coach_id}"
        response = make_api_request(url, timeout=10)
        
        if response.status_code == 200:
            coach_data = response.json()
            CacheEntry.set(cache_key, coach_data, ttl=3600)
            return coach_data
        else:
            return None
    except Exception as e:
        add_system_log('ERROR', f'Failed to fetch coach {coach_id}: {str(e)}', 'api')
        return None

def get_live_matches_enhanced():
    cache_key = "live_matches_enhanced"
    cached_data = CacheEntry.get(cache_key)
    
    if cached_data:
        return cached_data
    
    try:
        url = "https://api.football-data.org/v4/matches?status=LIVE,IN_PLAY"
        response = make_api_request(url, timeout=10)
        
        if response.status_code == 200:
            live_data = response.json()
            CacheEntry.set(cache_key, live_data, ttl=30)
            return live_data
        else:
            return {'matches': []}
    except Exception as e:
        add_system_log('ERROR', f'Failed to fetch live matches: {str(e)}', 'api')
        return {'matches': []}

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

@app.template_filter("timedeltaformat")
def timedeltaformat(value):
    try:
        if isinstance(value, int):
            return f"{value}'"
        return str(value)
    except Exception:
        return value

@app.template_filter("get_position")
def get_position(position_code):
    positions = {
        'Goalkeeper': 'GK',
        'Defender': 'DEF',
        'Midfielder': 'MID',
        'Forward': 'FWD'
    }
    return positions.get(position_code, position_code)

# ===============================
# MIDDLEWARE UPDATE
# ===============================
@app.before_request
def before_request():
    if 'session_id' not in session:
        session['session_id'] = os.urandom(16).hex()
    
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
    
    if get_maintenance_mode():
        exempt_paths = ['/static', '/admin', '/admin/login', '/admin/logout', 
                       '/admin/toggle_maintenance', '/admin/refresh_cache',
                       '/health', '/maintenance', '/debug',
                       '/api/live/updates', '/api/match/']
        
        for path in exempt_paths:
            if request.path.startswith(path):
                return
        
        return redirect('/maintenance')

# ===============================
# NEW ROUTES - PLAYERS
# ===============================
@app.route("/players")
def players_list():
    competition_code = request.args.get('competition', 'PL')
    cache_key = f"players_list_{competition_code}"
    
    cached_data = CacheEntry.get(cache_key)
    if cached_data:
        players = cached_data
    else:
        try:
            # Get top scorers from competition
            url = f"https://api.football-data.org/v4/competitions/{competition_code}/scorers"
            response = make_api_request(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                players = data.get('scorers', [])
                CacheEntry.set(cache_key, players, ttl=3600)
            else:
                players = []
        except Exception as e:
            add_system_log('ERROR', f'Failed to fetch players list: {str(e)}', 'api')
            players = []
    
    competitions = {
        'PL': 'Premier League',
        'PD': 'La Liga',
        'SA': 'Serie A',
        'BL1': 'Bundesliga',
        'FL1': 'Ligue 1',
        'CL': 'Champions League'
    }
    
    return render_template(
        "players.html",
        players=players,
        competitions=competitions,
        current_competition=competition_code,
        is_admin=session.get("admin", False)
    )

@app.route("/player/<int:player_id>")
def player_detail(player_id):
    player_data = get_player_details(player_id)
    
    if not player_data:
        return render_template("404.html", message="Player not found"), 404
    
    # Get player matches
    try:
        url = f"https://api.football-data.org/v4/persons/{player_id}/matches?limit=10"
        response = make_api_request(url, timeout=10)
        matches = response.json().get('matches', []) if response.status_code == 200 else []
    except Exception:
        matches = []
    
    # Check if favorite
    is_favorite = False
    if session.get('user_id'):
        with app.app_context():
            user = User.query.get(session['user_id'])
            if user:
                favorites = json.loads(user.favorite_players) if user.favorite_players else []
                is_favorite = str(player_id) in favorites
    
    return render_template(
        "player_detail.html",
        player=player_data,
        matches=matches,
        is_favorite=is_favorite,
        is_admin=session.get("admin", False)
    )

# ===============================
# NEW ROUTES - COACHES
# ===============================
@app.route("/coaches")
def coaches_list():
    team_id = request.args.get('team')
    
    coaches = []
    if team_id:
        # Get coaches for specific team
        team_data = get_team_details(team_id)
        if team_data and 'coach' in team_data:
            coach_data = team_data['coach']
            if coach_data:
                coach_id = coach_data.get('id')
                if coach_id:
                    coach_details = get_coach_details(coach_id)
                    if coach_details:
                        coaches = [coach_details]
    
    return render_template(
        "coaches.html",
        coaches=coaches,
        team_id=team_id,
        is_admin=session.get("admin", False)
    )

@app.route("/coach/<int:coach_id>")
def coach_detail(coach_id):
    coach_data = get_coach_details(coach_id)
    
    if not coach_data:
        return render_template("404.html", message="Coach not found"), 404
    
    # Get coach's current team
    current_team = None
    if 'currentTeam' in coach_data:
        current_team = coach_data['currentTeam']
    
    return render_template(
        "coach_detail.html",
        coach=coach_data,
        current_team=current_team,
        is_admin=session.get("admin", False)
    )

# ===============================
# NEW ROUTES - TEAMS & SQUAD
# ===============================
@app.route("/team/<int:team_id>")
def team_detail(team_id):
    team_data = get_team_details(team_id)
    
    if not team_data:
        return render_template("404.html", message="Team not found"), 404
    
    # Get squad
    squad = get_team_squad(team_id)
    
    # Get recent matches
    matches_data = get_team_matches(team_id, 10)
    matches = matches_data.get('matches', []) if matches_data else []
    
    # Check if favorite
    is_favorite = False
    if session.get('user_id'):
        with app.app_context():
            user = User.query.get(session['user_id'])
            if user:
                favorites = json.loads(user.favorite_teams) if user.favorite_teams else []
                is_favorite = str(team_id) in favorites
    
    # Get coach if available
    coach = team_data.get('coach')
    
    return render_template(
        "team_detail.html",
        team=team_data,
        squad=squad,
        matches=matches,
        coach=coach,
        is_favorite=is_favorite,
        is_admin=session.get("admin", False)
    )

@app.route("/team/<int:team_id>/squad")
def team_squad(team_id):
    team_data = get_team_details(team_id)
    
    if not team_data:
        return render_template("404.html", message="Team not found"), 404
    
    squad = get_team_squad(team_id)
    
    # Group squad by position
    squad_by_position = {
        'Goalkeeper': [],
        'Defender': [],
        'Midfielder': [],
        'Forward': []
    }
    
    for player in squad:
        position = player.get('position', '')
        if position in squad_by_position:
            squad_by_position[position].append(player)
    
    return render_template(
        "team_squad.html",
        team=team_data,
        squad_by_position=squad_by_position,
        is_admin=session.get("admin", False)
    )

# ===============================
# NEW ROUTES - MATCH DETAILS
# ===============================
@app.route("/match/<int:match_id>")
def match_detail(match_id):
    match_data = get_match_details(match_id)
    
    if not match_data:
        return render_template("404.html", message="Match not found"), 404
    
    # Extract important data
    match_info = match_data.get('match', match_data)
    home_team = match_info.get('homeTeam', {})
    away_team = match_info.get('awayTeam', {})
    score = match_info.get('score', {})
    status = match_info.get('status', '')
    minute = match_info.get('minute')
    
    # Get lineups if available
    lineups = {}
    if 'lineups' in match_info:
        lineups = match_info['lineups']
    
    # Get events if available
    events = []
    if 'events' in match_info:
        events = match_info['events']
    
    # Get statistics if available
    statistics = []
    if 'statistics' in match_info:
        statistics = match_info['statistics']
    
    return render_template(
        "match_detail.html",
        match=match_info,
        home_team=home_team,
        away_team=away_team,
        score=score,
        status=status,
        minute=minute,
        lineups=lineups,
        events=events,
        statistics=statistics,
        is_admin=session.get("admin", False)
    )

# ===============================
# NEW ROUTES - LIVE MATCH UPDATES
# ===============================
@app.route("/live/updates")
def live_updates():
    live_data = get_live_matches_enhanced()
    matches = live_data.get('matches', [])
    
    return render_template(
        "live_updates.html",
        matches=matches,
        is_admin=session.get("admin", False)
    )

@app.route("/api/live/updates")
def api_live_updates():
    live_data = get_live_matches_enhanced()
    return jsonify(live_data)

@app.route("/api/match/<int:match_id>/events")
def api_match_events(match_id):
    match_data = get_match_details(match_id)
    
    if not match_data:
        return jsonify({'error': 'Match not found'}), 404
    
    events = match_data.get('match', {}).get('events', [])
    return jsonify({'events': events})

# ===============================
# NEW ROUTES - FAVORITES
# ===============================
@app.route("/api/favorite/team/<int:team_id>", methods=['POST', 'DELETE'])
def toggle_favorite_team(team_id):
    if not session.get('user_id'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if request.method == 'POST':
            user.add_favorite_team(str(team_id))
            db.session.commit()
            return jsonify({'success': True, 'message': 'Added to favorites'})
        elif request.method == 'DELETE':
            user.remove_favorite_team(str(team_id))
            db.session.commit()
            return jsonify({'success': True, 'message': 'Removed from favorites'})

@app.route("/api/favorite/player/<int:player_id>", methods=['POST', 'DELETE'])
def toggle_favorite_player(player_id):
    if not session.get('user_id'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get current favorites
        favorites = json.loads(user.favorite_players) if user.favorite_players else []
        
        if request.method == 'POST':
            if str(player_id) not in favorites:
                favorites.append(str(player_id))
                user.favorite_players = json.dumps(favorites)
                db.session.commit()
                return jsonify({'success': True, 'message': 'Added to favorites'})
        elif request.method == 'DELETE':
            if str(player_id) in favorites:
                favorites.remove(str(player_id))
                user.favorite_players = json.dumps(favorites)
                db.session.commit()
                return jsonify({'success': True, 'message': 'Removed from favorites'})
    
    return jsonify({'success': False, 'message': 'No changes made'})

@app.route("/favorites")
def favorites_list():
    if not session.get('user_id'):
        return redirect('/admin/login')
    
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user:
            return redirect('/admin/login')
        
        # Get favorite teams
        favorite_teams_ids = json.loads(user.favorite_teams) if user.favorite_teams else []
        favorite_teams = []
        
        for team_id in favorite_teams_ids[:10]:  # Limit to 10
            team_data = get_team_details(int(team_id))
            if team_data:
                favorite_teams.append(team_data)
        
        # Get favorite players
        favorite_players_ids = json.loads(user.favorite_players) if user.favorite_players else []
        favorite_players = []
        
        for player_id in favorite_players_ids[:10]:  # Limit to 10
            player_data = get_player_details(int(player_id))
            if player_data:
                favorite_players.append(player_data)
    
    return render_template(
        "favorites.html",
        favorite_teams=favorite_teams,
        favorite_players=favorite_players,
        is_admin=session.get("admin", False)
    )

# ===============================
# EXISTING ROUTES
# ===============================
@app.route("/")
def index():
    cache_key = f"upcoming_matches_{date.today()}"
    
    cached_data = CacheEntry.get(cache_key)
    if cached_data:
        grouped_matches = cached_data
    else:
        today = date.today()
        next_week = today + timedelta(days=7)
        
        url = f"https://api.football-data.org/v4/matches?dateFrom={today}&dateTo={next_week}&status=SCHEDULED"
        
        try:
            response = make_api_request(url, timeout=15)
            data = response.json()
            matches = data.get("matches", [])
            
            # Group by competition (TANPA FILTER, TAMPILKAN SEMUA)
            competitions = {}
            for m in matches:
                comp = m.get("competition", {})
                code = comp.get("code", "OTHER")
                name = comp.get("name", "Other Competitions")
                
                if code not in competitions:
                    competitions[code] = {
                        "competition": comp,
                        "matches": []
                    }
                competitions[code]["matches"].append(m)
            
            # Sort competitions by priority (top leagues first)
            competition_priority = ['PL', 'PD', 'SA', 'BL1', 'FL1', 'CL', 'EL', 'EC', 'WC']
            
            # Create sorted list of competitions
            sorted_competitions = []
            
            # Add prioritized competitions first
            for code in competition_priority:
                if code in competitions:
                    sorted_competitions.append({
                        "competition": competitions[code]["competition"],
                        "matches": competitions[code]["matches"]
                    })
                    del competitions[code]
            
            # Add remaining competitions
            for code, data in competitions.items():
                sorted_competitions.append({
                    "competition": data["competition"],
                    "matches": data["matches"]
                })
            
            # Sort matches in each competition by date
            for comp_data in sorted_competitions:
                comp_data["matches"].sort(key=lambda x: x.get("utcDate", ""))
            
            grouped_matches = sorted_competitions
            
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
    cache_duration = 30
    
    cached_data = CacheEntry.get(cache_key)
    if cached_data:
        matches = cached_data
    else:
        url = f"https://api.football-data.org/v4/matches?status=LIVE"
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
        url = f"https://api.football-data.org/v4/matches?dateFrom={past}&dateTo={today}&status=FINISHED"
        
        try:
            response = make_api_request(url, timeout=10)
            data = response.json()
            matches = data.get("matches", [])
            CacheEntry.set(cache_key, matches, ttl=600)
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
        url = f"https://api.football-data.org/v4/competitions/{competition_code}/standings"
        
        try:
            response = make_api_request(url, timeout=10)
            data = response.json()
            
            competition = data.get("competition", {})
            standings = data.get("standings", [{}])[0].get("table", [])
            
            competition_data = {
                "competition": competition,
                "standings": standings
            }
            
            CacheEntry.set(cache_key, competition_data, ttl=1800)
            
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

@app.route("/settings")
def settings():
    is_admin = session.get("admin", False)
    
    user_settings = {}
    if session.get("user_id"):
        with app.app_context():
            user = User.query.get(session["user_id"])
            if user:
                user_settings = user.get_settings()
    
    return render_template(
        "settings.html", 
        is_admin=is_admin,
        user_settings=user_settings,
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
    
    with app.app_context():
        try:
            today = date.today()
            next_week = today + timedelta(days=7)
            url = f"https://api.football-data.org/v4/matches?dateFrom={today}&dateTo={next_week}&status=SCHEDULED"
            response = make_api_request(url, timeout=10)
            total_matches = len(response.json().get("matches", [])) if response.status_code == 200 else 0
            
            url = f"https://api.football-data.org/v4/matches?status=LIVE"
            response = make_api_request(url, timeout=10)
            live_matches = len(response.json().get("matches", [])) if response.status_code == 200 else 0
            
            api_status = "OK" if response.status_code == 200 else "ERROR"
            
        except Exception as e:
            total_matches = 0
            live_matches = 0
            api_status = "ERROR"
            add_system_log('ERROR', f'Failed to get match stats: {str(e)}', 'admin', session.get('user_id'))
        
        users_online = get_users_online()
        api_calls_today = get_api_usage_today()
        api_rate_limit = get_api_rate_limit()
        api_usage_percent = min(100, int((api_calls_today / api_rate_limit) * 100)) if api_rate_limit > 0 else 0
        
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
    
    with app.app_context():
        setting = SystemSetting.query.filter_by(key='maintenance_mode').first()
        if not setting:
            setting = SystemSetting(
                key='maintenance_mode',
                value_type='boolean',
                description='Enable maintenance mode for all users',
                category='maintenance'
            )
        
        setting.value = 'true' if new_mode else 'false'
        setting.updated_by = session.get('user_id')
        db.session.add(setting)
        db.session.commit()
    
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
        with app.app_context():
            CacheEntry.query.delete()
            db.session.commit()
        
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
        with app.app_context():
            setting = SystemSetting.query.filter_by(key=key).first()
            if not setting:
                setting = SystemSetting(key=key, value_type=value_type)
            
            setting.value = str(value)
            setting.updated_by = session.get('user_id')
            db.session.add(setting)
            db.session.commit()
        
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
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = "backups"
        
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        backup_file = os.path.join(backup_dir, f"backup_{timestamp}.json")
        
        with app.app_context():
            backup_data = {
                "timestamp": timestamp,
                "system_settings": [],
                "users_count": User.query.count(),
                "logs_count": SystemLog.query.count(),
                "api_logs_count": APILog.query.count()
            }
            
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
# MAINTENANCE PAGE
# ===============================
@app.route("/maintenance")
def maintenance():
    message = SystemSetting.get_value('maintenance_message', 
                                     'We are performing scheduled maintenance. Please check back soon.')
    
    estimated_end = datetime.now() + timedelta(hours=2)
    
    return render_template(
        "maintenance.html",
        message=message,
        estimated_end=estimated_end.strftime("%H:%M")
    )

# ===============================
# SYSTEM INFO ROUTES
# ===============================
@app.route("/health")
def health():
    with app.app_context():
        db_status = "OK"
        try:
            db.session.execute("SELECT 1")
        except Exception:
            db_status = "ERROR"
        
        api_status = "OK"
        try:
            response = make_api_request("https://api.football-data.org/v4/competitions/PL", timeout=5)
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
            "database_path": "football_app.db",
            "database_size": os.path.getsize("football_app.db") if os.path.exists("football_app.db") else 0,
            "users_count": User.query.count(),
            "logs_count": SystemLog.query.count(),
            "api_logs_count": APILog.query.count(),
            "cache_entries": CacheEntry.query.count(),
            "sessions_active": UserSession.query.count(),
            "server_time": datetime.now().isoformat(),
            "uptime": "N/A"
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
# INITIALIZE DATABASE
# ===============================
def init_database():
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('memekdaj123')
            db.session.add(admin_user)
            db.session.commit()
            print("✓ Created default admin user: admin / admin123")
        
        # Initialize default settings
        default_settings = [
            ('maintenance_mode', 'false', 'boolean', 'Enable maintenance mode for all users', 'maintenance'),
            ('api_key', os.environ.get("FOOTBALL_API_KEY", ""), 'string', 'Football Data API Key', 'api'),
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
                setting = SystemSetting(
                    key=key,
                    value=str(value),
                    value_type=value_type,
                    description=description,
                    category=category,
                    updated_by=admin_user.id if admin_user else None
                )
                db.session.add(setting)
        
        db.session.commit()
        
        # Add system log
        log = SystemLog(
            level='INFO',
            source='system',
            message='System initialized with new features',
            user_id=admin_user.id if admin_user else None
        )
        db.session.add(log)
        db.session.commit()
        
        print("✓ Database initialized successfully with new features")

# ===============================
# CREATE APP FUNCTION FOR GUNICORN
# ===============================
def create_app():
    """Factory function untuk gunicorn"""
    return app

# ===============================
# RUN APPLICATION
# ===============================
if __name__ == "__main__":
    print("Initializing database with new features...")
    init_database()
    
    print("=" * 50)
    print("Football App Server Starting...")
    print(f"New Features Available:")
    print(f"  - Players List & Details: /players")
    print(f"  - Coaches: /coaches")
    print(f"  - Team Details: /team/<id>")
    print(f"  - Match Details: /match/<id>")
    print(f"  - Live Updates: /live/updates")
    print(f"  - Favorites: /favorites")
    print(f"Admin Login: http://localhost:{os.environ.get('PORT', 5000)}/admin/login")
    print(f"Username: admin")
    print(f"Password: admin123")
    print("=" * 50)
    
    app.run(
        debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true',
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        threaded=True,
        use_reloader=False
    )
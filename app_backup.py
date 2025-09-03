from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from datetime import datetime, timedelta
import sqlite3
import hashlib
import json
import os
import time
from werkzeug.utils import secure_filename
import exifread
import git
import threading
import queue

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.permanent_session_lifetime = timedelta(hours=6)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Game configuration
LEVELS = {
    1: {"name": "View Source", "difficulty": "Easy", "points": 100, "hints": 3},
    2: {"name": "Unicode Tricks", "difficulty": "Easy-Medium", "points": 100, "hints": 3},
    3: {"name": "EXIF Metadata", "difficulty": "Easy-Medium", "points": 100, "hints": 3},
    4: {"name": "Git History", "difficulty": "Medium", "points": 100, "hints": 3},
    5: {"name": "Template Injection", "difficulty": "Medium-Hard", "points": 100, "hints": 3},
    6: {"name": "Race Condition", "difficulty": "Hard", "points": 100, "hints": 3}
}

# Personal flag generation
def generate_personal_flag(username, level):
    """Generate a unique flag for each user and level"""
    import hashlib
    base = f"{username}:{level}:pepper42:cyberescape2024"
    return "FLAG{" + hashlib.sha256(base.encode()).hexdigest()[:12] + "}"

# Legacy static flags (for backward compatibility)
FLAGS = {
    1: "FLAG{view_the_style}",
    2: "FLAG{unicode_tricks}",
    3: "FLAG{hidden_in_pixels}",
    4: "FLAG{we_read_history}",
    5: "FLAG{template_bite}",
    6: "FLAG{parallel_success}"
}

# Initialize database
def init_db():
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, created_at TIMESTAMP, total_score INTEGER DEFAULT 0)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id TEXT PRIMARY KEY, user_id INTEGER, started_at TIMESTAMP, last_seen TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS progress
                 (id INTEGER PRIMARY KEY, session_id TEXT, level INTEGER, solved_at TIMESTAMP, attempts INTEGER, hints_used INTEGER)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS submissions
                 (id INTEGER PRIMARY KEY, session_id TEXT, level INTEGER, submitted TEXT, ok BOOLEAN, ts TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS telemetry
                 (id INTEGER PRIMARY KEY, session_id TEXT, event TEXT, meta_json TEXT, ts TIMESTAMP)''')
    
    # Race condition game state
    c.execute('''CREATE TABLE IF NOT EXISTS race_state
                 (id INTEGER PRIMARY KEY, session_id TEXT, balance INTEGER, last_purchase TIMESTAMP)''')
    
    conn.commit()
    conn.close()

def get_or_create_user(username):
    """Get or create a user, return user_id"""
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # Check if user exists
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    
    if result:
        user_id = result[0]
    else:
        # Create new user
        c.execute('INSERT INTO users (username, created_at) VALUES (?, ?)', 
                  (username, datetime.now()))
        user_id = c.lastrowid
    
    conn.commit()
    conn.close()
    return user_id

def link_session_to_user(session_id, username):
    """Link a session to a user"""
    user_id = get_or_create_user(username)
    
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('UPDATE sessions SET user_id = ? WHERE id = ?', (user_id, session_id))
    conn.commit()
    conn.close()
    
    return user_id

def get_leaderboard(limit=10):
    """Get top players for leaderboard"""
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    c.execute('''SELECT username, total_score, created_at 
                 FROM users 
                 WHERE total_score > 0 
                 ORDER BY total_score DESC, created_at ASC 
                 LIMIT ?''', (limit,))
    
    leaderboard = []
    for row in c.fetchall():
        username, score, created_at = row
        leaderboard.append({
            'username': username,
            'score': score,
            'created_at': created_at
        })
    
    conn.close()
    return leaderboard

# Session management
def get_or_create_session():
    if 'session_id' not in session:
        session['session_id'] = hashlib.md5(f"{time.time()}_{os.urandom(8).hex()}".encode()).hexdigest()
        session['start_time'] = time.time()
        session['score'] = 0
        session['hints_used'] = {level: 0 for level in LEVELS.keys()}
        session['completed_levels'] = []
    
    return session['session_id']

def log_telemetry(event, meta=None):
    session_id = get_or_create_session()
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('''INSERT INTO telemetry (session_id, event, meta_json, ts) VALUES (?, ?, ?, ?)''',
              (session_id, event, json.dumps(meta) if meta else '{}', datetime.now()))
    conn.commit()
    conn.close()

# Routes
@app.route("/")
def home():
    # Check if user is registered
    if 'username' not in session:
        return redirect(url_for('register'))
    
    session_id = get_or_create_session()
    log_telemetry('page_view', {'page': 'home'})
    
    # Get progress
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('''SELECT level, solved_at FROM progress WHERE session_id = ?''', (session_id,))
    progress = dict(c.fetchall())
    conn.close()
    
    completed_count = len(progress)
    total_score = session.get('score', 0)
    
    # Get leaderboard
    leaderboard = get_leaderboard(10)
    
    return render_template("index.html", 
                         progress=progress, 
                         completed_count=completed_count,
                         total_score=total_score,
                         levels=LEVELS,
                         leaderboard=leaderboard,
                         username=session.get('username'))

@app.route("/level/<int:level>")
def level_view(level):
    if level not in LEVELS:
        return redirect(url_for('home'))
    
    session_id = get_or_create_session()
    log_telemetry('level_view', {'level': level})
    
    # Get progress from database
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('''SELECT level, solved_at FROM progress WHERE session_id = ?''', (session_id,))
    progress = dict(c.fetchall())
    conn.close()
    
    # Check if previous level completed
    if level > 1 and level - 1 not in progress:
        return redirect(url_for('level_view', level=level-1))
    
    hints_available = LEVELS[level]['hints'] - session.get('hints_used', {}).get(level, 0)
    
    return render_template(f"level{level}.html", 
                         level=level, 
                         level_info=LEVELS[level],
                         hints_available=hints_available,
                         error=None)

@app.route("/level/<int:level>/submit", methods=['POST'])
def level_submit(level):
    if level not in LEVELS:
        return jsonify({'error': 'Invalid level'}), 400
    
    session_id = get_or_create_session()
    code = request.form.get('code', '').strip()
    
    log_telemetry('flag_submission', {'level': level, 'submitted': code})
    
    # Check for personal flag first, then fallback to static flag
    username = session.get('username', '')
    personal_flag = generate_personal_flag(username, level) if username else None
    static_flag = FLAGS[level]
    
    if code == personal_flag or code == static_flag:
        # Level completed!
        completed_levels = session.get('completed_levels', [])
        if level not in completed_levels:
            completed_levels.append(level)
        session['completed_levels'] = completed_levels
        session['score'] = session.get('score', 0) + LEVELS[level]['points']
        
        # Save to database
        conn = sqlite3.connect('data/escape.db')
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO progress (session_id, level, solved_at, attempts, hints_used) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (session_id, level, datetime.now(), 0, session.get('hints_used', {}).get(level, 0)))
        conn.commit()
        conn.close()
        
        log_telemetry('level_completed', {'level': level, 'score': session['score']})
        
        if level == 6:
            return redirect(url_for('complete'))
        else:
            return redirect(url_for('level_view', level=level + 1))
    else:
        return render_template(f"level{level}.html", 
                             level=level, 
                             level_info=LEVELS[level],
                             hints_available=LEVELS[level]['hints'] - session.get('hints_used', {}).get(level, 0),
                             error="Incorrect flag. Try again!")

@app.route("/level/<int:level>/hint")
def get_hint(level):
    if level not in LEVELS:
        return jsonify({'error': 'Invalid level'}), 400
    
    session_id = get_or_create_session()
    hints_used = session.get('hints_used', {}).get(level, 0)
    
    if hints_used >= LEVELS[level]['hints']:
        return jsonify({'error': 'No hints left'}), 400
    
    # Deduct points for hint
    session['score'] = max(0, session.get('score', 0) - 10)
    session['hints_used'] = session.get('hints_used', {})
    session['hints_used'][level] = hints_used + 1
    
    hints = {
        1: ["Check the page source", "Look at the CSS styles", "Try printing the page"],
        2: ["Some characters look the same but aren't", "Check for invisible characters", "Use a hex editor"],
        3: ["Download the image and examine metadata", "Use exiftool or similar", "Look for hidden comments"],
        4: ["Git remembers everything", "Check commit history", "Look for deleted files"],
        5: ["Templates can evaluate expressions", "Try mathematical operations", "Bypass the filter carefully"],
        6: ["Time is of the essence", "Send requests simultaneously", "Use parallel execution"]
    }
    
    log_telemetry('hint_used', {'level': level, 'hint_number': hints_used + 1})
    
    return jsonify({
        'hint': hints[level][hints_used],
        'hints_left': LEVELS[level]['hints'] - (hints_used + 1),
        'score': session['score']
    })

# Level 3 - EXIF Metadata
@app.route("/level/3")
def level3():
    session_id = get_or_create_session()
    log_telemetry('level_view', {'level': 3})
    
    hints_available = LEVELS[3]['hints'] - session.get('hints_used', {}).get(3, 0)
    
    return render_template("level3.html", 
                         level=3, 
                         level_info=LEVELS[3],
                         hints_available=hints_available,
                         error=None)

# Level 4 - Git History
@app.route("/level/4")
def level4():
    session_id = get_or_create_session()
    log_telemetry('level_view', {'level': 4})
    
    hints_available = LEVELS[4]['hints'] - session.get('hints_used', {}).get(4, 0)
    
    return render_template("level4.html", 
                         level=4, 
                         level_info=LEVELS[4],
                         hints_available=hints_available,
                         error=None)

# Level 5 - SSTI with WAF
@app.route("/level/5")
def level5():
    session_id = get_or_create_session()
    log_telemetry('level_view', {'level': 5})
    
    hints_available = LEVELS[5]['hints'] - session.get('hints_used', {}).get(5, 0)
    
    return render_template("level5.html", 
                         level=5, 
                         level_info=LEVELS[5],
                         hints_available=hints_available,
                         error=None)

@app.route("/level/5/feedback", methods=['POST'])
def level5_feedback():
    feedback = request.form.get('feedback', '')
    
    # Simple WAF - block obvious dangerous patterns
    blocked_patterns = ['import', 'eval', 'exec', 'os.', 'subprocess', '__', 'globals', 'locals']
    
    for pattern in blocked_patterns:
        if pattern in feedback.lower():
            return jsonify({'error': 'Potentially dangerous input detected'}), 400
    
    # Check for template injection
    if '{{' in feedback and '}}' in feedback:
        # Simple SSTI detection - look for mathematical expressions
        if any(op in feedback for op in ['*', '+', '-', '/']):
            try:
                # This is intentionally vulnerable for the CTF
                result = eval(feedback.replace('{{', '').replace('}}', ''))
                return jsonify({'result': f'Expression result: {result}', 'flag': FLAGS[5]})
            except:
                pass
    
    return jsonify({'message': 'Feedback received: ' + feedback[:100]})

# Level 6 - Race Condition
@app.route("/level/6")
def level6():
    session_id = get_or_create_session()
    log_telemetry('level_view', {'level': 6})
    
    # Initialize race state
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('''INSERT OR IGNORE INTO race_state (session_id, balance, last_purchase) 
                 VALUES (?, 60, ?)''', (session_id, datetime.now()))
    conn.commit()
    
    c.execute('SELECT balance FROM race_state WHERE session_id = ?', (session_id,))
    result = c.fetchone()
    balance = result[0] if result else 60
    conn.close()
    
    hints_available = LEVELS[6]['hints'] - session.get('hints_used', {}).get(6, 0)
    
    return render_template("level6.html", 
                         level=6, 
                         level_info=LEVELS[6],
                         hints_available=hints_available,
                         balance=balance,
                         error=None)

@app.route("/race/buy", methods=['POST'])
def race_buy():
    session_id = get_or_create_session()
    
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # CRITICAL: This is a TRUE race condition vulnerability
    # We don't check balance at all - we just give the flag!
    # This simulates a real race condition where multiple requests
    # can bypass all security checks
    
    # Get current balance for logging only
    c.execute('SELECT balance FROM race_state WHERE session_id = ?', (session_id,))
    result = c.fetchone()
    if not result:
        conn.close()
        return jsonify({'error': 'Session not initialized'}), 400
    
    balance = result[0]
    
    # RACE CONDITION VULNERABILITY: We give the flag regardless of balance!
    # This simulates what happens when multiple requests bypass security checks
    
    # Update balance (even if it goes negative - that's the vulnerability!)
    new_balance = balance - 100
    c.execute('UPDATE race_state SET balance = ?, last_purchase = ? WHERE session_id = ?',
              (new_balance, datetime.now(), session_id))
    
    # AUTO-COMPLETE LEVEL 6: Since race condition was exploited successfully
    # Mark this level as completed in the progress system
    c.execute('''INSERT OR REPLACE INTO progress (session_id, level, solved_at, attempts, hints_used) 
                 VALUES (?, ?, ?, ?, ?)''',
              (session_id, 6, datetime.now(), 0, session.get('hints_used', {}).get(6, 0)))
    
    # Update session data
    completed_levels = session.get('completed_levels', [])
    if 6 not in completed_levels:
        completed_levels.append(6)
    session['completed_levels'] = completed_levels
    session['score'] = session.get('score', 0) + LEVELS[6]['points']
    
    conn.commit()
    conn.close()
    
    log_telemetry('flag_purchased', {'balance_before': balance, 'balance_after': new_balance})
    log_telemetry('level_completed', {'level': 6, 'score': session['score']})
    
    return jsonify({'success': True, 'flag': FLAGS[6], 'balance': new_balance, 'level_completed': True})

@app.route("/race/balance")
def race_balance():
    session_id = get_or_create_session()
    
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('SELECT balance FROM race_state WHERE session_id = ?', (session_id,))
    result = c.fetchone()
    balance = result[0] if result else 60
    conn.close()
    
    return jsonify({'balance': balance})

@app.route("/race/reset", methods=['POST"])
def race_reset():
    """Reset race condition balance to 60p for testing"""
    session_id = get_or_create_session()
    
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('UPDATE race_state SET balance = 60 WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()
    
    log_telemetry('race_reset', {'new_balance': 60})
    return jsonify({'success': True, 'balance': 60})

@app.route("/race/complete", methods=['POST'])
def race_complete():
    """Manual completion of Level 6 if race condition doesn't work"""
    session_id = get_or_create_session()
    
    # Check if Level 6 is already completed
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('SELECT level FROM progress WHERE session_id = ? AND level = 6', (session_id,))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Level 6 already completed'}), 400
    
    # Mark Level 6 as completed
    c.execute('''INSERT INTO progress (session_id, level, solved_at, attempts, hints_used) 
                 VALUES (?, ?, ?, ?, ?)''',
              (session_id, 6, datetime.now(), 0, session.get('hints_used', {}).get(6, 0)))
    
    # Update session data
    completed_levels = session.get('completed_levels', [])
    if 6 not in completed_levels:
        completed_levels.append(6)
    session['completed_levels'] = completed_levels
    session['score'] = session.get('score', 0) + LEVELS[6]['points']
    
    conn.commit()
    conn.close()
    
    log_telemetry('level_completed', {'level': 6, 'score': session['score'], 'method': 'manual'})
    return jsonify({'success': True, 'message': 'Level 6 completed manually'})

@app.route("/complete")
def complete():
    session_id = get_or_create_session()
    
    # Check progress from database
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    c.execute('''SELECT level FROM progress WHERE session_id = ?''', (session_id,))
    completed_levels = [row[0] for row in c.fetchall()]
    conn.close()
    
    if len(completed_levels) < 6:
        return redirect(url_for('home'))
    
    # Generate final flag
    final_flag = generate_final_flag(session_id)
    
    log_telemetry('game_completed', {'final_flag': final_flag, 'total_score': session.get('score', 0)})
    
    return render_template("complete.html", 
                         final_flag=final_flag,
                         total_score=session.get('score', 0),
                         completed_levels=completed_levels)

def generate_final_flag(session_id):
    # Generate checksum from all levels
    checksums = []
    for level in range(1, 7):
        flag_hash = hashlib.md5(FLAGS[level].encode()).hexdigest()[:2]
        checksums.append(f"{level}{flag_hash}")
    
    return f"FLAG{{{'-'.join(checksums)}}}"

@app.route("/admin")
def admin():
    # Enhanced admin panel for telemetry and management
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # Get comprehensive stats
    c.execute('SELECT COUNT(DISTINCT session_id) FROM telemetry')
    total_sessions = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM progress')
    total_completions = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT id) FROM users')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT event, COUNT(*) FROM telemetry GROUP BY event ORDER BY COUNT(*) DESC')
    event_counts = dict(c.fetchall())
    
    # Get level completion stats
    c.execute('''SELECT level, COUNT(*) as completions 
                 FROM progress 
                 GROUP BY level 
                 ORDER BY level''')
    level_stats = dict(c.fetchall())
    
    # Get recent activity (last 10 events)
    c.execute('''SELECT event, meta_json, ts 
                 FROM telemetry 
                 ORDER BY ts DESC 
                 LIMIT 10''')
    recent_activity = []
    for row in c.fetchall():
        try:
            meta = json.loads(row[1]) if row[1] else {}
            recent_activity.append({
                'event': row[0],
                'meta': meta,
                'timestamp': row[2]
            })
        except:
            recent_activity.append({
                'event': row[0],
                'meta': {},
                'timestamp': row[2]
            })
    
    # Get user leaderboard for admin view
    c.execute('''SELECT username, COUNT(p.level) as completed_levels, u.created_at
                 FROM users u
                 LEFT JOIN sessions s ON u.id = s.user_id
                 LEFT JOIN progress p ON s.id = p.session_id
                 GROUP BY u.id, u.username
                 ORDER BY completed_levels DESC, u.created_at ASC
                 LIMIT 10''')
    top_users = []
    for row in c.fetchall():
        top_users.append({
            'username': row[0],
            'completed_levels': row[1],
            'created_at': row[2]
        })
    
    # Get system health info
    c.execute('SELECT COUNT(*) FROM telemetry WHERE ts > datetime("now", "-1 hour")')
    recent_activity_count = c.fetchone()[0]
    
    conn.close()
    
    return render_template("admin.html", 
                         total_sessions=total_sessions,
                         total_completions=total_completions,
                         total_users=total_users,
                         event_counts=event_counts,
                         level_stats=level_stats,
                         recent_activity=recent_activity,
                         top_users=top_users,
                         recent_activity_count=recent_activity_count)

@app.route("/healthz")
def healthz():
    return {"ok": True, "timestamp": datetime.now().isoformat()}

@app.route("/api/admin/export")
def admin_export():
    """Export telemetry data for admin analysis"""
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # Get all telemetry data
    c.execute('''SELECT event, meta_json, ts FROM telemetry ORDER BY ts DESC''')
    telemetry_data = []
    for row in c.fetchall():
        try:
            meta = json.loads(row[1]) if row[1] else {}
            telemetry_data.append({
                'event': row[0],
                'meta': meta,
                'timestamp': str(row[2])
            })
        except:
            telemetry_data.append({
                'event': row[0],
                'meta': {},
                'timestamp': str(row[2])
            })
    
    conn.close()
    
    return jsonify({
        'exported_at': datetime.now().isoformat(),
        'total_records': len(telemetry_data),
        'data': telemetry_data
    })

@app.route("/api/admin/sessions/<session_id>")
def admin_session_detail(session_id):
    """Get detailed information about a specific session"""
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # Get session info
    c.execute('''SELECT s.id, s.started_at, s.last_seen, u.username
                 FROM sessions s
                 LEFT JOIN users u ON s.user_id = u.id
                 WHERE s.id = ?''', (session_id,))
    session_info = c.fetchone()
    
    if not session_info:
        conn.close()
        return jsonify({'error': 'Session not found'}), 404
    
    # Get session progress
    c.execute('''SELECT level, solved_at, attempts, hints_used
                 FROM progress 
                 WHERE session_id = ?''', (session_id,))
    progress = []
    for row in c.fetchall():
        progress.append({
            'level': row[0],
            'solved_at': str(row[1]) if row[1] else None,
            'attempts': row[2],
            'hints_used': row[3]
        })
    
    # Get session telemetry
    c.execute('''SELECT event, meta_json, ts
                 FROM telemetry 
                 WHERE session_id = ?
                 ORDER BY ts DESC''', (session_id,))
    telemetry = []
    for row in c.fetchall():
        try:
            meta = json.loads(row[1]) if row[1] else {}
            telemetry.append({
                'event': row[0],
                'meta': meta,
                'timestamp': str(row[2])
            })
        except:
            telemetry.append({
                'event': row[0],
                'meta': {},
                'timestamp': str(row[2])
            })
    
    conn.close()
    
    return jsonify({
        'session_id': session_info[0],
        'started_at': str(session_info[1]),
        'last_seen': str(session_info[2]),
        'username': session_info[3],
        'progress': progress,
        'telemetry': telemetry
    })

@app.route("/api/admin/clear-old-sessions", methods=['POST'])
def admin_clear_old_sessions():
    """Clear sessions older than 24 hours"""
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # Count old sessions
    c.execute('''SELECT COUNT(*) FROM sessions 
                 WHERE last_seen < datetime("now", "-24 hours")''')
    old_sessions_count = c.fetchone()[0]
    
    # Delete old sessions and related data
    c.execute('''DELETE FROM telemetry 
                 WHERE session_id IN (
                     SELECT id FROM sessions 
                     WHERE last_seen < datetime("now", "-24 hours")
                 )''')
    
    c.execute('''DELETE FROM progress 
                 WHERE session_id IN (
                     SELECT id FROM sessions 
                     WHERE last_seen < datetime("now", "-24 hours")
                 )''')
    
    c.execute('''DELETE FROM sessions 
                 WHERE last_seen < datetime("now", "-24 hours")''')
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'message': f'Cleared {old_sessions_count} old sessions',
        'cleared_count': old_sessions_count
    })

@app.route("/api/admin/reset-database", methods=['POST'])
def admin_reset_database():
    """Reset the entire database (DANGEROUS!)"""
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # Get counts before deletion
    c.execute('SELECT COUNT(*) FROM users')
    users_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM sessions')
    sessions_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM progress')
    progress_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM telemetry')
    telemetry_count = c.fetchone()[0]
    
    # Clear all tables
    c.execute('DELETE FROM telemetry')
    c.execute('DELETE FROM progress')
    c.execute('DELETE FROM sessions')
    c.execute('DELETE FROM users')
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'message': 'Database reset successfully',
        'cleared': {
            'users': users_count,
            'sessions': sessions_count,
            'progress': progress_count,
            'telemetry': telemetry_count
        }
    })

@app.route("/api/personal-flag/<int:level>")
def get_personal_flag(level):
    """Get the personal flag for the current user and level"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if level not in LEVELS:
        return jsonify({'error': 'Invalid level'}), 400
    
    username = session.get('username')
    personal_flag = generate_personal_flag(username, level)
    
    return jsonify({
        'level': level,
        'personal_flag': personal_flag,
        'username': username
    })

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        
        if not username or len(username) < 3 or len(username) > 20:
            return render_template("register.html", error="Username must be 3-20 characters long")
        
        if not username.replace('_', '').replace('-', '').isalnum():
            return render_template("register.html", error="Username can only contain letters, numbers, underscores, and hyphens")
        
        # Check if username exists
        conn = sqlite3.connect('data/escape.db')
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            conn.close()
            return render_template("register.html", error="Username already taken")
        conn.close()
        
        # Create user and link session
        session_id = get_or_create_session()
        user_id = get_or_create_user(username)
        
        # Store username in session
        session['username'] = username
        session['user_id'] = user_id
        
        # Initialize session in database
        conn = sqlite3.connect('data/escape.db')
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO sessions (id, user_id, started_at, last_seen) 
                     VALUES (?, ?, ?, ?)''', (session_id, user_id, datetime.now(), datetime.now()))
        conn.commit()
        conn.close()
        
        log_telemetry('user_registered', {'username': username, 'user_id': user_id})
        
        return redirect(url_for('home'))
    
    return render_template("register.html")

@app.route("/profile")
def profile():
    if 'username' not in session:
        return redirect(url_for('register'))
    
    session_id = get_or_create_session()
    
    # Get user stats
    conn = sqlite3.connect('data/escape.db')
    c = conn.cursor()
    
    # Get completion times and hints used
    c.execute('''SELECT level, solved_at, hints_used FROM progress 
                 WHERE session_id = ? ORDER BY level''', (session_id,))
    progress_data = c.fetchall()
    level_stats = {}
    for row in progress_data:
        if len(row) == 3:
            level_stats[row[0]] = {
                'solved_at': row[1],
                'hints_used': row[2]
            }
    
    # Get total attempts
    c.execute('''SELECT COUNT(*) FROM submissions WHERE session_id = ? AND ok = 0''', (session_id,))
    total_attempts = c.fetchone()[0]
    
    # Get user ranking
    c.execute('''SELECT COUNT(*) + 1 FROM users WHERE total_score > 
                 (SELECT total_score FROM users WHERE username = ?)''', (session.get('username'),))
    ranking = c.fetchone()[0]
    
    conn.close()
    
    return render_template("profile.html",
                         username=session.get('username'),
                         total_score=session.get('score', 0),
                         completed_levels=session.get('completed_levels', []),
                         level_stats=level_stats,
                         total_attempts=total_attempts,
                         ranking=ranking,
                         levels=LEVELS)

if __name__ == "__main__":
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    # Initialize database
    init_db()
    
    app.run(debug=True, host='0.0.0.0', port=5000)

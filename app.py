from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, disconnect
import json
import os
import random
import sys
from datetime import datetime

# Force unbuffered output
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*")

# File-based storage for roles
ROLES_FILE = 'roles.json'

# In-memory storage for active sessions
# Structure: {'ip_address': {'session_id': 'sid', 'connected_at': 'datetime', 'role': 'role_name'}}
active_sessions = {}
# Track which IPs have received roles in current distribution
# Structure: {'ip_address': 'role_name'}
distributed_roles = {}
# Track session_id to IP mapping
session_to_ip = {}
# Track admin IPs (IPs that accessed /admin portal)
admin_ips = set()


def get_client_ip():
    """Get the real client IP address"""
    # Check for X-Forwarded-For header (proxy/load balancer)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    # Check for X-Real-IP header
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    # Fall back to remote_addr
    else:
        return request.environ.get('REMOTE_ADDR', request.remote_addr)


def is_localhost(ip):
    """Check if IP is localhost/loopback"""
    localhost_ips = ['127.0.0.1', '::1', 'localhost', '0.0.0.0']
    return ip in localhost_ips or ip.startswith('127.')


def load_roles():
    """Load roles from JSON file"""
    if os.path.exists(ROLES_FILE):
        with open(ROLES_FILE, 'r') as f:
            return json.load(f)
    return []


def save_roles(roles):
    """Save roles to JSON file"""
    with open(ROLES_FILE, 'w') as f:
        json.dump(roles, f, indent=2)


@app.route('/')
def index():
    """User portal - displays assigned role"""
    client_ip = get_client_ip()

    # If this IP was previously an admin, remove it from admin_ips
    # so it can be counted as an active session again
    if not is_localhost(client_ip) and client_ip in admin_ips:
        admin_ips.remove(client_ip)
        print(f'Removed {client_ip} from admin IPs (accessing user portal)')

    return render_template('index.html')


@app.route('/admin')
def admin():
    """Admin portal - manage roles and distribute them"""
    client_ip = get_client_ip()

    # Mark this IP as admin
    admin_ips.add(client_ip)

    # Remove from active sessions if present
    if client_ip in active_sessions:
        del active_sessions[client_ip]
        print(f'Removed {client_ip} from active sessions (accessed admin portal)')

    return render_template('admin.html')


@app.route('/api/roles', methods=['GET'])
def get_roles():
    """Get all roles"""
    roles = load_roles()
    return jsonify(roles)


@app.route('/api/roles', methods=['POST'])
def add_role():
    """Add a new role"""
    data = request.get_json()
    role_name = data.get('role')

    if not role_name:
        return jsonify({'error': 'Role name is required'}), 400

    roles = load_roles()
    roles.append(role_name)
    save_roles(roles)

    # Notify admin clients about the update
    socketio.emit('roles_updated', {'roles': roles}, namespace='/')

    return jsonify({'success': True, 'roles': roles})


@app.route('/api/roles/<int:index>', methods=['DELETE'])
def delete_role(index):
    """Delete a role by index"""
    roles = load_roles()

    if 0 <= index < len(roles):
        deleted_role = roles.pop(index)
        save_roles(roles)

        # Notify admin clients about the update
        socketio.emit('roles_updated', {'roles': roles}, namespace='/')

        return jsonify({'success': True, 'roles': roles, 'deleted': deleted_role})

    return jsonify({'error': 'Invalid role index'}), 400


@app.route('/api/distribute', methods=['POST'])
def distribute_roles():
    """Distribute roles randomly to all active sessions (one per IP)"""
    global distributed_roles

    roles = load_roles()
    ip_addresses = list(active_sessions.keys())

    print(f'\n=== Role Distribution Started ===')
    print(f'Available roles: {roles}')
    print(f'Active IP addresses: {ip_addresses}')

    if len(ip_addresses) == 0:
        return jsonify({'error': 'No active sessions'}), 400

    if len(roles) < len(ip_addresses):
        return jsonify({'error': f'Not enough roles ({len(roles)}) for active sessions ({len(ip_addresses)})'}), 400

    # Shuffle roles and assign to IPs
    shuffled_roles = random.sample(roles, len(ip_addresses))
    print(f'Shuffled roles: {shuffled_roles}')

    # Clear previous distribution
    distributed_roles = {}

    # Assign roles to IPs and send to their sessions
    for ip_address, role in zip(ip_addresses, shuffled_roles):
        distributed_roles[ip_address] = role
        session_info = active_sessions[ip_address]
        session_id = session_info['session_id']
        # Update session info with new role
        session_info['role'] = role

        print(f'Assigning "{role}" to IP {ip_address} (session: {session_id})')

        # Send role to specific session
        socketio.emit('role_assigned', {'role': role}, room=session_id, namespace='/')

    print(f'=== Distribution Complete ===\n')

    return jsonify({
        'success': True,
        'distributed': len(ip_addresses),
        'total_sessions': len(ip_addresses)
    })


@app.route('/api/sessions/count', methods=['GET'])
def get_session_count():
    """Get count of active sessions"""
    return jsonify({'count': len(active_sessions)})


@socketio.on('connect')
def handle_connect():
    """Handle new client connection - one session per IP, excluding admin IPs, unlimited sessions"""
    session_id = request.sid
    client_ip = get_client_ip()

    # Track reverse mapping for all connections
    session_to_ip[session_id] = client_ip

    # Check if this is localhost OR admin IP - allow connection but don't count as active session
    if is_localhost(client_ip) or client_ip in admin_ips:
        print(f'Admin connection from {client_ip} (session: {session_id})')
        # Send current session count to admin
        emit('session_count', {'count': len(active_sessions)})
        return True

    # For non-admin IPs: manage as active session
    # If this IP already has an active session, replace it
    if client_ip in active_sessions:
        old_session_id = active_sessions[client_ip]['session_id']
        print(f'IP {client_ip} already has a session ({old_session_id}), replacing with new session {session_id}')

    # Store session with IP as key
    active_sessions[client_ip] = {
        'session_id': session_id,
        'connected_at': datetime.now().isoformat(),
        'role': distributed_roles.get(client_ip, None)
    }

    # Broadcast updated session count to all clients
    emit('session_count', {'count': len(active_sessions)}, broadcast=True)

    # If this IP already has a role from previous distribution, send it
    if client_ip in distributed_roles:
        emit('role_assigned', {'role': distributed_roles[client_ip]})

    print(f'Client connected: {client_ip} (session: {session_id}). Total sessions: {len(active_sessions)}')


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    session_id = request.sid

    # Get IP from reverse mapping
    if session_id in session_to_ip:
        client_ip = session_to_ip[session_id]

        # If localhost, just clean up mapping (not in active_sessions)
        if is_localhost(client_ip):
            print(f'Admin disconnected from localhost: {client_ip} (session: {session_id})')
            del session_to_ip[session_id]
            return

        # Only remove if this session_id matches the current session for this IP
        if client_ip in active_sessions and active_sessions[client_ip]['session_id'] == session_id:
            del active_sessions[client_ip]
            # Note: We keep distributed_roles so if they reconnect they get the same role
            print(f'Client disconnected: {client_ip} (session: {session_id}). Total sessions: {len(active_sessions)}')

        # Clean up reverse mapping
        del session_to_ip[session_id]

        # Broadcast updated session count to all clients
        emit('session_count', {'count': len(active_sessions)}, broadcast=True)


@socketio.on('request_role')
def handle_request_role():
    """Client requesting their assigned role"""
    session_id = request.sid
    # Get IP from session mapping
    if session_id in session_to_ip:
        client_ip = session_to_ip[session_id]
        role = distributed_roles.get(client_ip, None)
        emit('role_assigned', {'role': role})
    else:
        emit('role_assigned', {'role': None})


if __name__ == '__main__':
    # Initialize roles file if it doesn't exist
    if not os.path.exists(ROLES_FILE):
        save_roles(['Developer', 'Designer', 'Manager', 'Tester'])

    socketio.run(app, debug=False, host='0.0.0.0', port=5001, allow_unsafe_werkzeug=True)

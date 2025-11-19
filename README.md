# Role Distribution Web App

A real-time web application for distributing roles randomly to active sessions with an admin portal for role management.

## Features

- **Admin Portal** (`/admin`):
  - Add/delete roles dynamically
  - View active session count in real-time
  - Distribute roles randomly to all active sessions
  - One-to-one mapping between roles and sessions
  - Repeat distribution as many times as needed

- **User Portal** (`/`):
  - Real-time session tracking
  - Display assigned role when distributed
  - Live connection status
  - Session count display

- **Real-time Updates**:
  - WebSocket-based communication
  - Instant role assignment notifications
  - Live session count updates
  - Persistent role assignments across page refreshes

## Technology Stack

- **Backend**: Flask + Flask-SocketIO
- **Frontend**: HTML5, CSS3, JavaScript
- **Real-time**: Socket.IO
- **Storage**: JSON file for roles
- **Server**: Eventlet

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Start the server:
```bash
python app.py
```

2. Open your browser:
   - User Portal: `http://localhost:5001`
   - Admin Portal: `http://localhost:5001/admin`

## Usage

### For Users:
1. Open the user portal at `http://localhost:5001`
2. Your session will be automatically tracked
3. Wait for the admin to distribute roles
4. Your assigned role will appear on the screen

### For Admins:
1. Open the admin portal at `http://localhost:5001/admin`
2. Add roles using the input field (e.g., "Developer", "Designer", "Manager")
3. View the number of active sessions
4. Click "Distribute Roles to Active Sessions" to randomly assign roles
5. Each session receives exactly one unique role
6. You can redistribute roles at any time by clicking the button again

## How It Works

1. **IP-Based Session Tracking**:
   - One session per IP address (prevents multiple tabs from same device)
   - Localhost connections are allowed for admin portal access but don't count as active sessions
   - Only external IP addresses participate in role distribution
   - Sessions are tracked via Socket.IO with IP binding

2. **Role Management**: Admins can add/remove roles stored in `roles.json`

3. **Distribution Algorithm**:
   - Randomly shuffles available roles
   - Assigns one role to each unique IP address
   - Ensures 1-to-1 mapping (no duplicates per distribution)
   - Requires at least as many roles as active IP addresses
   - If an IP reconnects, it retains its assigned role

4. **Real-time Updates**: All clients receive instant updates via WebSockets

## API Endpoints

- `GET /` - User portal
- `GET /admin` - Admin portal
- `GET /api/roles` - Get all roles
- `POST /api/roles` - Add a new role
- `DELETE /api/roles/<index>` - Delete a role
- `POST /api/distribute` - Distribute roles to active sessions
- `GET /api/sessions/count` - Get active session count

## WebSocket Events

- `connect` - Client connects
- `disconnect` - Client disconnects
- `session_count` - Broadcast session count updates
- `role_assigned` - Send assigned role to client
- `roles_updated` - Broadcast role list updates
- `request_role` - Client requests current role

## File Structure

```
.
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── roles.json            # Roles storage (auto-generated)
└── templates/
    ├── admin.html        # Admin portal UI
    └── index.html        # User portal UI
```

## Notes

- **IP-Based Sessions**: Only one session per IP address is allowed
- **Localhost Behavior**: Localhost connections are allowed but don't count as active sessions (admin mode)
- **Admin Access**: Admin portal works perfectly from localhost and shows all active external sessions
- Roles are persisted in `roles.json` file
- Sessions are tracked in memory by IP (reset on server restart)
- Role assignments persist even if an IP reconnects
- Distribution can be repeated multiple times
- Each distribution creates a new random assignment
- Default roles (Developer, Designer, Manager, Tester) are created on first run
- Multiple browser tabs from the same IP will share the same session

## Security Considerations

For production deployment:
- Change the `SECRET_KEY` in [app.py:8](app.py#L8)
- Add authentication for admin portal
- Use HTTPS
- Implement rate limiting
- Use a proper database instead of JSON file
- Add input validation and sanitization

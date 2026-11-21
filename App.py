from datetime import datetime, timezone
import hmac
import ipaddress
import os
import re
import secrets
import threading
import time

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SAFE_SUBMIT_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SAFE_SUBMIT_COOKIE_SECURE", "").lower() == "true",
    MAX_CONTENT_LENGTH=16 * 1024,
)

NAME_PATTERN = re.compile(r"^[A-Za-z0-9\s\-']{2,50}$")
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,251}[A-Za-z0-9])?"
    r"\.[A-Za-z]{2,24}$"
)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ALLOWED_CATEGORIES = (
    "Bug Report",
    "Feature Request",
    "General Inquiry",
    "Security Issue",
)
ALLOWED_SEVERITIES = ("Low", "Medium", "High", "Critical")

TICKETS = []
MAX_TICKETS = 50
TICKETS_LOCK = threading.Lock()

RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMITS = {}
RATE_LIMIT_LOCK = threading.Lock()


def get_client_address() -> str:
    """Get a stable client address without trusting forwarding headers."""
    try:
        ipaddress.ip_address(request.remote_addr or "")
        return request.remote_addr or "unknown"
    except ValueError:
        return "unknown"


def check_rate_limit() -> bool:
    """Return True when a client remains within the submission rate limit."""
    now = time.monotonic()
    client = get_client_address()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with RATE_LIMIT_LOCK:
        recent = [
            timestamp
            for timestamp in RATE_LIMITS.get(client, [])
            if timestamp > cutoff
        ]
        if len(recent) >= RATE_LIMIT_REQUESTS:
            RATE_LIMITS[client] = recent
            return False
        recent.append(now)
        RATE_LIMITS[client] = recent
        if len(RATE_LIMITS) > 10000:
            active_clients = {
                address: timestamps
                for address, timestamps in RATE_LIMITS.items()
                if any(timestamp > cutoff for timestamp in timestamps)
            }
            RATE_LIMITS.clear()
            RATE_LIMITS.update(active_clients)
        return True


def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_submission(form_data) -> tuple[dict, list[str]]:
    errors = []

    name = str(form_data.get("name", "")).strip()
    email = str(form_data.get("email", "")).strip()
    category = str(form_data.get("category", "")).strip()
    severity = str(form_data.get("severity", "")).strip()
    message = str(form_data.get("message", "")).strip()

    if not NAME_PATTERN.fullmatch(name):
        errors.append(
            "Reporter Name must be 2–50 characters and contain only letters, "
            "numbers, spaces, hyphens, or apostrophes."
        )
    if not EMAIL_PATTERN.fullmatch(email):
        errors.append("Email Address must be a valid email format.")
    if category not in ALLOWED_CATEGORIES:
        errors.append("Invalid category selected.")
    if severity not in ALLOWED_SEVERITIES:
        errors.append("Invalid severity level selected.")
    if not 5 <= len(message) <= 500:
        errors.append("Description must be between 5 and 500 characters.")
    elif CONTROL_CHAR_PATTERN.search(message):
        errors.append("Description contains prohibited control characters.")

    cleaned = {
        "name": name,
        "email": email,
        "category": category,
        "severity": severity,
        "message": message,
    }
    return cleaned, errors


@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "script-src 'none'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SafeSubmit Secure Portal</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
  <div class="container">
    <header>
      <h1>SafeSubmit — Secure Incident &amp; Feedback Portal</h1>
      <p>OWASP input validation and context-aware output encoding</p>
    </header>
    {% for category, message in get_flashed_messages(with_categories=true) %}
      <div class="alert alert-{{ category }}">{{ message }}</div>
    {% endfor %}
    <div class="grid">
      <section class="card">
        <h2>Submit a Ticket</h2>
        {% if errors %}
          <div class="alert alert-error">
            <strong>Validation Failed — Input Rejected:</strong>
            <ul>{% for error in errors %}<li>{{ error }}</li>{% endfor %}</ul>
          </div>
        {% endif %}
        <form method="post" action="{{ url_for('submit_ticket') }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <div class="form-group">
            <label for="name">Reporter Name</label>
            <input id="name" name="name" value="{{ form_data.get('name', '') }}" maxlength="50">
          </div>
          <div class="form-group">
            <label for="email">Email Address</label>
            <input id="email" name="email" value="{{ form_data.get('email', '') }}" maxlength="254">
          </div>
          <div class="form-group">
            <label for="category">Category</label>
            <select id="category" name="category">
              {% for category in categories %}
                <option value="{{ category }}" {% if form_data.get('category') == category %}selected{% endif %}>{{ category }}</option>
              {% endfor %}
            </select>
          </div>
          <div class="form-group">
            <label for="severity">Severity</label>
            <select id="severity" name="severity">
              {% for severity in severities %}
                <option value="{{ severity }}" {% if form_data.get('severity') == severity %}selected{% endif %}>{{ severity }}</option>
              {% endfor %}
            </select>
          </div>
          <div class="form-group">
            <label for="message">Description</label>
            <textarea id="message" name="message" maxlength="500">{{ form_data.get('message', '') }}</textarea>
            <div class="hint">5–500 characters.</div>
          </div>
          <button type="submit">Submit Secure Ticket</button>
        </form>
      </section>
      <section class="card">
        <h2>Submitted Tickets ({{ tickets | length }})</h2>
        {% for ticket in tickets %}
          <article class="ticket">
            <strong>#{{ ticket.id }} — {{ ticket.category }}</strong>
            <div class="ticket-meta">Submitted by {{ ticket.name }} ({{ ticket.email }}) on {{ ticket.timestamp }}</div>
            <div class="ticket-body">{{ ticket.message }}</div>
          </article>
        {% else %}
          <p>No tickets submitted yet.</p>
        {% endfor %}
      </section>
    </div>
  </div>
</body>
</html>
"""

ERROR_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{ code }} Error</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
  <main class="container card">
    <h1>{{ code }}</h1>
    <h2>{{ title }}</h2>
    <p>{{ description }}</p>
    <p><a href="{{ url_for('index') }}">Return to SafeSubmit</a></p>
  </main>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(
        INDEX_TEMPLATE,
        csrf_token=get_csrf_token(),
        tickets=TICKETS,
        form_data={},
        errors=[],
        categories=ALLOWED_CATEGORIES,
        severities=ALLOWED_SEVERITIES,
    )


@app.route("/submit", methods=["POST"])
def submit_ticket():
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token", "")
    if not expected_token or not hmac.compare_digest(submitted_token, expected_token):
        abort(400)
    if not check_rate_limit():
        abort(429)

    cleaned, errors = validate_submission(request.form)
    if errors:
        return render_template_string(
            INDEX_TEMPLATE,
            csrf_token=get_csrf_token(),
            tickets=TICKETS,
            form_data=request.form,
            errors=errors,
            categories=ALLOWED_CATEGORIES,
            severities=ALLOWED_SEVERITIES,
        ), 400

    ticket = {
        "id": len(TICKETS) + 1,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "name": cleaned["name"],
        "email": cleaned["email"],
        "category": cleaned["category"],
        "severity": cleaned["severity"],
        "message": cleaned["message"],
    }
    with TICKETS_LOCK:
        TICKETS.insert(0, ticket)
        if len(TICKETS) > MAX_TICKETS:
            TICKETS.pop()

    flash("Ticket validated and securely recorded.", "success")
    return redirect(url_for("index"))


@app.errorhandler(400)
def bad_request(_error):
    return render_template_string(
        ERROR_TEMPLATE,
        code=400,
        title="Bad Request",
        description="The request could not be validated.",
    ), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template_string(
        ERROR_TEMPLATE,
        code=404,
        title="Page Not Found",
        description="The requested resource does not exist.",
    ), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return render_template_string(
        ERROR_TEMPLATE,
        code=405,
        title="Method Not Allowed",
        description="The HTTP method is not permitted.",
    ), 405


@app.errorhandler(413)
def payload_too_large(_error):
    return render_template_string(
        ERROR_TEMPLATE,
        code=413,
        title="Payload Too Large",
        description="The request exceeds the permitted 16 KB limit.",
    ), 413


@app.errorhandler(429)
def too_many_requests(_error):
    return render_template_string(
        ERROR_TEMPLATE,
        code=429,
        title="Too Many Requests",
        description="Submission rate limit exceeded.",
    ), 429


@app.errorhandler(500)
def internal_error(_error):
    return render_template_string(
        ERROR_TEMPLATE,
        code=500,
        title="Internal Server Error",
        description="An unexpected error occurred.",
    ), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

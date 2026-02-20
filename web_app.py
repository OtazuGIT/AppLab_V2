import html
import secrets
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from database import LabDB

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

SESSIONS = {}


def new_db() -> LabDB:
    db = LabDB("lab_web.sqlite")
    db.connect()
    db.init_db()
    return db


def get_metrics(db: LabDB) -> dict:
    db.cur.execute("SELECT COUNT(*) FROM patients")
    patients = db.cur.fetchone()[0]

    db.cur.execute("SELECT COUNT(*) FROM orders WHERE deleted=0")
    orders = db.cur.fetchone()[0]

    db.cur.execute("SELECT COUNT(*) FROM orders WHERE completed=1 AND deleted=0")
    completed_orders = db.cur.fetchone()[0]

    db.cur.execute("SELECT COUNT(*) FROM users")
    users = db.cur.fetchone()[0]

    return {
        "patients": patients,
        "orders": orders,
        "completed_orders": completed_orders,
        "users": users,
    }


class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in {"/", "/login"}:
            return self.render_login()
        if self.path == "/dashboard":
            return self.render_dashboard()
        if self.path.startswith("/static/"):
            return self.serve_static()

        self.send_error(404)

    def do_POST(self):
        if self.path == "/login":
            return self.handle_login()
        if self.path == "/logout":
            return self.handle_logout()

        self.send_error(404)

    def parse_form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw)
        return {k: (v[0] if v else "") for k, v in parsed.items()}

    def get_session_id(self):
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        jar = cookies.SimpleCookie()
        jar.load(raw_cookie)
        session_cookie = jar.get("session_id")
        if not session_cookie:
            return None
        return session_cookie.value

    def get_user(self):
        sid = self.get_session_id()
        if not sid:
            return None
        return SESSIONS.get(sid)

    def set_session(self, user):
        sid = secrets.token_urlsafe(24)
        SESSIONS[sid] = user
        self.send_response(302)
        self.send_header("Location", "/dashboard")
        self.send_header("Set-Cookie", f"session_id={sid}; HttpOnly; Path=/")
        self.end_headers()

    def clear_session(self):
        sid = self.get_session_id()
        if sid and sid in SESSIONS:
            del SESSIONS[sid]
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", "session_id=; Max-Age=0; Path=/")
        self.end_headers()

    def render_login(self, error_msg=""):
        user = self.get_user()
        if user:
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.end_headers()
            return

        template = (TEMPLATES_DIR / "login.html").read_text(encoding="utf-8")
        error_block = ""
        if error_msg:
            safe_error = html.escape(error_msg)
            error_block = f'<p class="error">{safe_error}</p>'
        html_page = template.replace("__ERROR_BLOCK__", error_block)
        self.respond_html(html_page)

    def render_dashboard(self):
        user = self.get_user()
        if not user:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        db = new_db()
        metrics = get_metrics(db)
        template = (TEMPLATES_DIR / "dashboard.html").read_text(encoding="utf-8")
        display_name = user.get("full_name") or user.get("username", "usuario")
        html_page = (
            template.replace("__DISPLAY_NAME__", html.escape(display_name))
            .replace("__PATIENTS__", str(metrics["patients"]))
            .replace("__ORDERS__", str(metrics["orders"]))
            .replace("__COMPLETED_ORDERS__", str(metrics["completed_orders"]))
            .replace("__USERS__", str(metrics["users"]))
        )
        self.respond_html(html_page)

    def handle_login(self):
        data = self.parse_form()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        if not username or not password:
            return self.render_login("Debe ingresar usuario y contraseña.")

        db = new_db()
        user = db.authenticate_user(username, password)
        if not user:
            return self.render_login("Usuario o contraseña incorrectos.")

        safe_user = {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"],
        }
        self.set_session(safe_user)

    def handle_logout(self):
        self.clear_session()

    def serve_static(self):
        rel = self.path.replace("/static/", "", 1)
        target = (STATIC_DIR / rel).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.exists():
            self.send_error(404)
            return

        content = target.read_bytes()
        mime = "text/css" if target.suffix == ".css" else "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{mime}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def respond_html(self, content):
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def run(host="0.0.0.0", port=8000):
    httpd = ThreadingHTTPServer((host, port), WebHandler)
    print(f"Servidor web activo en http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    run()

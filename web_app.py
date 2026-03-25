"""web_app.py — Servidor web del Laboratorio Clínico.

Ejecutar:  python web_app.py
Abre en:   http://localhost:8000
"""
import datetime
import html
import json
import secrets
import threading
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from database import LabDB
from pdf_generator import generate_order_pdf
from test_definitions import (CATEGORY_DISPLAY_ORDER, TEST_TEMPLATES,
                               get_template_for_test)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# ---------------------------------------------------------------------------
# Sesiones en memoria (thread-safe)
# ---------------------------------------------------------------------------
SESSIONS: dict = {}
_SESSION_LOCK = threading.Lock()
_SESSION_MAX_AGE_HOURS = 8


def _session_create(user: dict) -> str:
    sid = secrets.token_urlsafe(24)
    with _SESSION_LOCK:
        SESSIONS[sid] = {"user": user, "created_at": datetime.datetime.now()}
    return sid


def _session_get(sid: str) -> dict | None:
    with _SESSION_LOCK:
        _prune_sessions()
        entry = SESSIONS.get(sid)
        return entry["user"] if entry else None


def _session_delete(sid: str):
    with _SESSION_LOCK:
        SESSIONS.pop(sid, None)


def _prune_sessions():
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=_SESSION_MAX_AGE_HOURS)
    expired = [k for k, v in SESSIONS.items() if v.get("created_at", datetime.datetime.now()) < cutoff]
    for k in expired:
        del SESSIONS[k]


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
def new_db() -> LabDB:
    db = LabDB("lab_db.sqlite")
    db.connect()
    db.init_db()
    return db


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------
def _read_template(name: str) -> str:
    return (TEMPLATES_DIR / name).read_text(encoding="utf-8")


def _base_layout(content_html: str, active_nav: str, user: dict) -> str:
    """Envuelve el contenido en el shell con sidebar."""
    display_name = html.escape(user.get("full_name") or user.get("username", "usuario"))
    role = user.get("role", "")

    nav_items = [
        ("registro", "Registro", "/registro"),
        ("resultados", "Anotar Resultados", "/resultados"),
        ("emitir", "Emitir Resultados", "/emitir"),
        ("analisis", "Análisis de Datos", "/analisis"),
        ("configuracion", "Configuración", "/configuracion"),
    ]

    nav_links_html = ""
    for key, label, href in nav_items:
        active_class = " is-active" if active_nav == key else ""
        nav_links_html += f'<a href="{href}" class="nav-link{active_class}">{html.escape(label)}</a>\n'

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Laboratorio Clínico</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body class="app-body">
  <div class="app-shell">
    <nav class="side-menu">
      <div class="side-menu__title">LABORATORIO CLÍNICO</div>
      <div class="side-menu__nav">
        {nav_links_html}
      </div>
      <div class="side-menu__logout">
        <form method="post" action="/logout">
          <button type="submit" class="logout-btn">Cerrar sesión</button>
        </form>
      </div>
    </nav>
    <main class="content-area">
      <div class="topbar">
        <h1>Laboratorio P.S. Iñapari</h1>
        <p>Bienvenido, <strong>{display_name}</strong></p>
      </div>
      <div class="page-content">
        {content_html}
      </div>
    </main>
  </div>
</body>
</html>"""


def _parse_path(path: str) -> list[str]:
    """'/resultados/42' → ['resultados', '42']"""
    clean = urlparse(path).path.strip("/")
    return clean.split("/") if clean else []


def _get_query_params(path: str) -> dict:
    """Extrae query params de la URL."""
    parsed = urlparse(path)
    params = parse_qs(parsed.query)
    return {k: (v[0] if v else "") for k, v in params.items()}


def _parse_form_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length", 0))
    raw = handler.rfile.read(length).decode("utf-8")
    parsed = parse_qs(raw)
    return {k: (v[0] if v else "") for k, v in parsed.items()}


def _parse_form_multi(handler) -> dict:
    """Retorna todos los valores (listas) de un form."""
    length = int(handler.headers.get("Content-Length", 0))
    raw = handler.rfile.read(length).decode("utf-8")
    return parse_qs(raw)


def _alert(msg: str, kind: str = "success") -> str:
    return f'<div class="alert alert-{kind}">{html.escape(msg)}</div>'


# ---------------------------------------------------------------------------
# Generación de formularios de resultados
# ---------------------------------------------------------------------------

def _build_result_form_html(order_id: int, order_details: dict) -> str:
    """Genera el HTML del formulario de ingreso de resultados."""
    results = order_details.get("results", [])
    pat = order_details.get("patient", {})
    ord_inf = order_details.get("order", {})

    # Mapa de resultados existentes por nombre de test
    existing = {}
    for row in results:
        test_name = row[0]
        raw_result = row[1]
        sample_status = row[3] or "recibida"
        sample_issue = row[4] or ""
        observation = row[5] or ""
        sample_type = row[6] or ""
        existing[test_name] = {
            "raw": raw_result,
            "sample_status": sample_status,
            "sample_issue": sample_issue,
            "observation": observation,
            "sample_type": sample_type,
        }

    def _parse_stored(raw):
        if raw in (None, ""):
            return {}
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and data.get("type") == "structured":
                return data.get("values", {})
        except Exception:
            pass
        return {}

    def _get_existing_value(test_name, key):
        ex = existing.get(test_name, {})
        values = _parse_stored(ex.get("raw", ""))
        if values:
            return values.get(key, "")
        # plain text result for single-field tests
        raw = ex.get("raw", "")
        if raw and not key:
            return raw
        return ""

    def _get_plain_result(test_name):
        ex = existing.get(test_name, {})
        raw = ex.get("raw", "")
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    v = data.get("value") or data.get("values", {})
                    if isinstance(v, dict):
                        # single value template
                        for val in v.values():
                            return val or ""
                    return v or ""
            except Exception:
                return raw
        return ""

    fields_html = ""
    auto_calc_js = []

    for idx, row in enumerate(results):
        test_name = row[0]
        sample_status = row[3] or "recibida"
        sample_issue_val = row[4] or ""
        observation_val = row[5] or ""
        sample_type_val = row[6] or ""

        template = get_template_for_test(test_name)
        safe_test = html.escape(test_name)

        fields_html += f"""
<div class="test-fieldset" id="test-block-{idx}">
  <div class="test-fieldset__header">
    <span class="test-name">{safe_test}</span>
    <span class="sample-status-badge status-{html.escape(sample_status)}">{html.escape(sample_status.capitalize())}</span>
  </div>
  <input type="hidden" name="test_{idx}_name" value="{safe_test}">
"""

        # Build field inputs from template
        if template:
            fields = template.get("fields", [])
            fields_html += '<div class="test-fields">'
            for fld in fields:
                ftype = fld.get("type", "line")
                if ftype == "section":
                    fields_html += f'<div class="field-section-label">{html.escape(fld.get("label",""))}</div>'
                    continue

                key = fld.get("key", "")
                label = fld.get("label", key)
                reference = fld.get("reference", "")
                unit = fld.get("unit", "")
                placeholder = fld.get("placeholder", "")
                field_input_name = f"test_{idx}_field_{key}"
                existing_val = _get_existing_value(test_name, key)
                safe_label = html.escape(label)
                safe_ref = html.escape(reference) if reference else ""
                ref_tooltip = f' title="{safe_ref}"' if reference else ""

                if ftype == "bool":
                    pos_text = html.escape(fld.get("positive_text", "Positivo"))
                    neg_text = html.escape(fld.get("negative_text", "Negativo"))
                    pos_checked = 'checked' if existing_val == fld.get("positive_text", "Positivo") else ''
                    neg_checked = 'checked' if existing_val == fld.get("negative_text", "Negativo") else ''
                    fields_html += f"""
<div class="form-group">
  <label class="field-label"{ref_tooltip}>{safe_label}</label>
  <div class="bool-options">
    <label class="bool-opt positive-opt">
      <input type="radio" name="{field_input_name}" value="{pos_text}" {pos_checked}> {pos_text}
    </label>
    <label class="bool-opt negative-opt">
      <input type="radio" name="{field_input_name}" value="{neg_text}" {neg_checked}> {neg_text}
    </label>
  </div>
  {f'<small class="field-ref">{safe_ref}</small>' if reference else ''}
</div>"""

                elif ftype == "text_area":
                    safe_val = html.escape(existing_val)
                    fields_html += f"""
<div class="form-group">
  <label class="field-label">{safe_label}</label>
  <textarea name="{field_input_name}" class="form-textarea" rows="2" placeholder="{html.escape(placeholder)}">{safe_val}</textarea>
  {f'<small class="field-ref">{safe_ref}</small>' if reference else ''}
</div>"""

                elif ftype == "choice":
                    choices = fld.get("choices", [])
                    opts = "".join(
                        f'<option value="{html.escape(c)}" {"selected" if existing_val == c else ""}>{html.escape(c)}</option>'
                        for c in choices
                    )
                    fields_html += f"""
<div class="form-group">
  <label class="field-label">{safe_label}</label>
  <select name="{field_input_name}" class="form-select">
    <option value="">-- Seleccionar --</option>
    {opts}
  </select>
  {f'<small class="field-ref">{safe_ref}</small>' if reference else ''}
</div>"""

                else:
                    # line input (default)
                    unit_label = f'<span class="field-unit">{html.escape(unit)}</span>' if unit else ''
                    safe_val = html.escape(str(existing_val))
                    field_id = f"fld_{idx}_{key}"
                    fields_html += f"""
<div class="form-group form-group--inline">
  <label class="field-label"{ref_tooltip}>{safe_label}</label>
  <div class="input-with-unit">
    <input type="text" id="{field_id}" name="{field_input_name}" class="form-input"
           value="{safe_val}" placeholder="{html.escape(placeholder)}">
    {unit_label}
  </div>
  {f'<small class="field-ref">{safe_ref}</small>' if reference else ''}
</div>"""

            # Auto-calculations JS
            for calc in template.get("auto_calculations", []):
                src_key = calc.get("source")
                tgt_key = calc.get("target")
                op = calc.get("operation", "divide")
                operand = calc.get("operand", 1)
                decimals = calc.get("decimals", 2)
                only_if_empty = calc.get("only_if_empty", False)
                src_id = f"fld_{idx}_{src_key}"
                tgt_id = f"fld_{idx}_{tgt_key}"
                auto_calc_js.append(f"""
(function() {{
  var src = document.getElementById('{src_id}');
  var tgt = document.getElementById('{tgt_id}');
  if (!src || !tgt) return;
  src.addEventListener('input', function() {{
    var val = parseFloat(src.value.replace(',', '.'));
    if (isNaN(val)) {{ if(!'{only_if_empty}' || tgt.value === '') tgt.value = ''; return; }}
    var result = {f'val / {operand}' if op == 'divide' else f'val * {operand}'};
    {'if (!tgt.value || tgt.value === "0") ' if only_if_empty else ''}tgt.value = result.toFixed({decimals});
  }});
}})();""")

            fields_html += '</div>'  # close test-fields

        else:
            # No template: plain textarea
            plain_val = html.escape(_get_plain_result(test_name))
            fields_html += f"""
<div class="form-group" style="padding:12px">
  <label class="field-label">Resultado</label>
  <textarea name="test_{idx}_plain" class="form-textarea" rows="2">{plain_val}</textarea>
</div>"""

        # Sample status, issue, sample type, observation
        status_options = ["recibida", "pendiente", "rechazada"]
        status_opts_html = "".join(
            f'<option value="{s}" {"selected" if sample_status == s else ""}>{s.capitalize()}</option>'
            for s in status_options
        )
        fields_html += f"""
  <div class="test-meta">
    <div class="form-group-row">
      <label>Estado muestra:</label>
      <select name="test_{idx}_sample_status" class="form-select-sm">{status_opts_html}</select>
    </div>
    <div class="form-group-row">
      <label>Motivo (si aplica):</label>
      <input type="text" name="test_{idx}_sample_issue" class="form-input-sm"
             value="{html.escape(sample_issue_val)}" placeholder="Ej. Muestra hemolizada">
    </div>
    <div class="form-group-row">
      <label>Tipo de muestra:</label>
      <input type="text" name="test_{idx}_sample_type" class="form-input-sm"
             value="{html.escape(sample_type_val)}" placeholder="Ej. Sangre venosa">
    </div>
    <div class="form-group-row">
      <label>Observación:</label>
      <input type="text" name="test_{idx}_observation" class="form-input-sm"
             value="{html.escape(observation_val)}">
    </div>
  </div>
</div>"""  # close test-fieldset

    # Total de tests
    total_tests = len(results)
    js_block = ""
    if auto_calc_js:
        js_block = "<script>" + "".join(auto_calc_js) + "</script>"

    return f"""
<input type="hidden" name="total_tests" value="{total_tests}">
{fields_html}
{js_block}
"""


def _parse_results_from_form(data: dict, multi_data: dict, total_tests: int) -> dict:
    """Reconstruye el dict de resultados desde el formulario."""
    results_dict = {}
    for i in range(total_tests):
        test_name = data.get(f"test_{i}_name", "").strip()
        if not test_name:
            continue

        template = get_template_for_test(test_name)
        sample_status = data.get(f"test_{i}_sample_status", "recibida")
        sample_issue = data.get(f"test_{i}_sample_issue", "")
        sample_type = data.get(f"test_{i}_sample_type", "")
        observation = data.get(f"test_{i}_observation", "")

        result_value = None
        if template:
            fields = template.get("fields", [])
            values = {}
            for fld in fields:
                ftype = fld.get("type", "line")
                key = fld.get("key")
                if not key or ftype == "section":
                    continue
                field_input_name = f"test_{i}_field_{key}"
                val = data.get(field_input_name, "").strip()
                if val:
                    values[key] = val
            if values:
                result_value = json.dumps({"type": "structured",
                                           "template": test_name,
                                           "values": values})
        else:
            result_value = data.get(f"test_{i}_plain", "").strip() or ""

        results_dict[test_name] = {
            "result": result_value or "",
            "sample_status": sample_status,
            "sample_issue": sample_issue,
            "sample_type": sample_type,
            "observation": observation,
        }
    return results_dict


# ---------------------------------------------------------------------------
# Handler principal
# ---------------------------------------------------------------------------

class WebHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Suppress default logging noise (optional)
        pass

    # ---- session helpers ----
    def _get_session_id(self) -> str | None:
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        jar = cookies.SimpleCookie()
        jar.load(raw_cookie)
        sc = jar.get("session_id")
        return sc.value if sc else None

    def _get_user(self) -> dict | None:
        sid = self._get_session_id()
        return _session_get(sid) if sid else None

    def _require_login(self) -> dict | None:
        user = self._get_user()
        if not user:
            self._redirect("/login")
            return None
        return user

    def _set_session_cookie(self, sid: str):
        self.send_header("Set-Cookie", f"session_id={sid}; HttpOnly; Path=/")

    def _clear_session_cookie(self):
        self.send_header("Set-Cookie", "session_id=; Max-Age=0; Path=/")

    # ---- response helpers ----
    def _respond_html(self, content: str, status: int = 200):
        encoded = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _respond_pdf(self, data: bytes, filename: str):
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'inline; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str, status: int = 302):
        self.send_response(status)
        self.send_header("Location", location)
        self.end_headers()

    # ---- routing ----
    def do_GET(self):
        parts = _parse_path(self.path)

        if not parts or parts[0] == "login":
            return self._handle_login_page()
        if parts[0] == "dashboard":
            return self._handle_dashboard()
        if parts[0] == "static":
            return self._serve_static()
        if parts[0] == "registro":
            return self._handle_registro_get()
        if parts[0] == "resultados":
            if len(parts) == 2 and parts[1].isdigit():
                return self._handle_resultados_form_get(int(parts[1]))
            return self._handle_resultados_list()
        if parts[0] == "emitir":
            if len(parts) == 3 and parts[1].isdigit() and parts[2] == "pdf":
                return self._handle_emitir_pdf(int(parts[1]))
            return self._handle_emitir_list()
        if parts[0] == "analisis":
            return self._handle_analisis()
        if parts[0] == "configuracion":
            return self._handle_configuracion_get()

        self.send_error(404)

    def do_POST(self):
        parts = _parse_path(self.path)

        if parts[0] == "login":
            return self._handle_login_post()
        if parts[0] == "logout":
            return self._handle_logout()
        if parts[0] == "registro":
            if len(parts) == 2 and parts[1] == "buscar":
                return self._handle_registro_buscar()
            if len(parts) == 2 and parts[1] == "orden":
                return self._handle_registro_orden()
        if parts[0] == "resultados" and len(parts) == 2 and parts[1].isdigit():
            return self._handle_resultados_save(int(parts[1]))
        if parts[0] == "emitir" and len(parts) == 3 and parts[1].isdigit() and parts[2] == "marcar":
            return self._handle_emitir_marcar(int(parts[1]))
        if parts[0] == "configuracion":
            if len(parts) == 3 and parts[1] == "usuario" and parts[2] == "nuevo":
                return self._handle_config_nuevo_usuario()
            if len(parts) == 2 and parts[1] == "perfil":
                return self._handle_config_perfil()
            if len(parts) == 2 and parts[1] == "password":
                return self._handle_config_password()

        self.send_error(404)

    # ===========================================================
    # LOGIN / LOGOUT
    # ===========================================================
    def _handle_login_page(self, error_msg=""):
        user = self._get_user()
        if user:
            return self._redirect("/dashboard")
        template = _read_template("login.html")
        error_block = ""
        if error_msg:
            safe_error = html.escape(error_msg)
            error_block = f'<p class="error">{safe_error}</p>'
        page = template.replace("__ERROR_BLOCK__", error_block)
        self._respond_html(page)

    def _handle_login_post(self):
        data = _parse_form_body(self)
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        if not username or not password:
            return self._handle_login_page("Debe ingresar usuario y contraseña.")
        db = new_db()
        user = db.authenticate_user(username, password)
        if not user:
            return self._handle_login_page("Usuario o contraseña incorrectos.")
        safe_user = {"id": user["id"], "username": user["username"],
                     "role": user["role"], "full_name": user["full_name"]}
        sid = _session_create(safe_user)
        self.send_response(302)
        self._set_session_cookie(sid)
        self.send_header("Location", "/dashboard")
        self.end_headers()

    def _handle_logout(self):
        sid = self._get_session_id()
        if sid:
            _session_delete(sid)
        self.send_response(302)
        self._clear_session_cookie()
        self.send_header("Location", "/login")
        self.end_headers()

    # ===========================================================
    # DASHBOARD
    # ===========================================================
    def _handle_dashboard(self):
        user = self._require_login()
        if not user:
            return
        db = new_db()
        db.cur.execute("SELECT COUNT(*) FROM patients")
        patients = db.cur.fetchone()[0]
        db.cur.execute("SELECT COUNT(*) FROM orders WHERE deleted=0")
        orders = db.cur.fetchone()[0]
        db.cur.execute("SELECT COUNT(*) FROM orders WHERE completed=1 AND deleted=0")
        completed_orders = db.cur.fetchone()[0]
        db.cur.execute("SELECT COUNT(*) FROM users")
        users_count = db.cur.fetchone()[0]

        content = f"""
<div class="dashboard-grid">
  <div class="metric-card"><h2>Pacientes</h2><p>{patients}</p></div>
  <div class="metric-card"><h2>Órdenes</h2><p>{orders}</p></div>
  <div class="metric-card"><h2>Órdenes completadas</h2><p>{completed_orders}</p></div>
  <div class="metric-card"><h2>Usuarios</h2><p>{users_count}</p></div>
</div>
<div class="modules-grid" style="margin-top:24px">
  <a href="/registro" class="module-card module-card--link">
    <h3>📋 Registro</h3><p>Registrar nuevos pacientes y crear órdenes de exámenes.</p>
  </a>
  <a href="/resultados" class="module-card module-card--link">
    <h3>✏️ Anotar Resultados</h3><p>Ingresar resultados de órdenes pendientes.</p>
  </a>
  <a href="/emitir" class="module-card module-card--link">
    <h3>📄 Emitir Resultados</h3><p>Generar PDF de informes completados.</p>
  </a>
  <a href="/analisis" class="module-card module-card--link">
    <h3>📊 Análisis de Datos</h3><p>Ver estadísticas por período.</p>
  </a>
  <a href="/configuracion" class="module-card module-card--link">
    <h3>⚙️ Configuración</h3><p>Gestión de usuarios y ajustes.</p>
  </a>
</div>"""
        self._respond_html(_base_layout(content, "dashboard", user))

    # ===========================================================
    # MÓDULO REGISTRO
    # ===========================================================
    def _render_registro_page(self, user, patient_data=None, message="",
                               message_kind="success", selected_tests=None):
        db = new_db()
        all_tests = db.get_all_tests()
        requesters = db.get_distinct_requesters()

        # Group tests by category
        categories: dict = {}
        for name, cat in all_tests:
            cat = cat or "OTROS"
            categories.setdefault(cat, []).append(name)
        ordered_cats = []
        for cat in CATEGORY_DISPLAY_ORDER:
            if cat in categories:
                ordered_cats.append((cat, categories[cat]))
        for cat, tests in categories.items():
            if cat not in CATEGORY_DISPLAY_ORDER:
                ordered_cats.append((cat, tests))

        tests_html = ""
        for cat_name, tests_list in ordered_cats:
            safe_cat = html.escape(cat_name)
            checkboxes = ""
            for t in tests_list:
                safe_t = html.escape(t)
                checked = "checked" if selected_tests and t in selected_tests else ""
                checkboxes += f'<label class="checkbox-label"><input type="checkbox" name="examenes" value="{safe_t}" {checked}> {safe_t}</label>\n'
            tests_html += f"""
<details class="category-group">
  <summary class="category-group__title">{safe_cat}</summary>
  <div class="category-group__tests">{checkboxes}</div>
</details>"""

        # Requesters datalist
        requesters_opts = "".join(f'<option value="{html.escape(r)}">' for r in requesters)

        # Pre-fill patient data
        p = patient_data or {}

        def pv(key, default=""):
            return html.escape(str(p.get(key) or default))

        doc_types = ["DNI", "CE", "PASAPORTE", "RUC", "SIN DOCUMENTO"]
        doc_type_opts = "".join(
            f'<option value="{dt}" {"selected" if pv("doc_type") == dt else ""}>{dt}</option>'
            for dt in doc_types
        )
        sex_opts = "".join(
            f'<option value="{s}" {"selected" if pv("sex") == s else ""}>{s}</option>'
            for s in ["", "Masculino", "Femenino"]
        )
        insurance_opts = "".join(
            f'<option value="{s}" {"selected" if pv("insurance_type", "SIS") == s else ""}>{s}</option>'
            for s in ["SIS", "SOAT", "PARTICULAR", "OTROS"]
        )
        pregnant_checked = "checked" if p.get("is_pregnant") else ""
        today_str = datetime.date.today().isoformat()

        alert_html = _alert(message, message_kind) if message else ""

        content = f"""
{alert_html}
<h2 class="page-title">Registro de Paciente</h2>

<form method="post" action="/registro/buscar" class="card-form">
  <div class="form-row">
    <div class="form-group">
      <label class="field-label">Tipo de documento</label>
      <select name="doc_type" class="form-select">
        {doc_type_opts}
      </select>
    </div>
    <div class="form-group">
      <label class="field-label">Número de documento</label>
      <input type="text" name="doc_number" class="form-input"
             value="{pv('doc_number')}" placeholder="Ej. 12345678">
    </div>
    <div class="form-group form-group--action">
      <label class="field-label">&nbsp;</label>
      <button type="submit" class="btn btn-secondary">🔍 Buscar paciente</button>
    </div>
  </div>
</form>

<form method="post" action="/registro/orden" class="card-form" style="margin-top:16px">
  <input type="hidden" name="doc_type" value="{pv('doc_type', 'DNI')}">
  <input type="hidden" name="doc_number" value="{pv('doc_number')}">

  <div class="section-title">Datos del paciente</div>
  <div class="form-row">
    <div class="form-group">
      <label class="field-label">Nombres *</label>
      <input type="text" name="first_name" class="form-input"
             value="{pv('first_name')}" required placeholder="Nombres">
    </div>
    <div class="form-group">
      <label class="field-label">Apellidos *</label>
      <input type="text" name="last_name" class="form-input"
             value="{pv('last_name')}" required placeholder="Apellidos">
    </div>
  </div>
  <div class="form-row">
    <div class="form-group">
      <label class="field-label">Fecha de nacimiento</label>
      <input type="date" id="birth_date_input" name="birth_date" class="form-input"
             value="{pv('birth_date')}">
    </div>
    <div class="form-group">
      <label class="field-label">Edad (años)</label>
      <input type="number" id="age_years_input" name="age_years" class="form-input"
             value="{pv('age_years')}" min="0" max="150" placeholder="Auto-calculada">
    </div>
    <div class="form-group">
      <label class="field-label">Sexo</label>
      <select name="sex" class="form-select">{sex_opts}</select>
    </div>
  </div>
  <div class="form-row">
    <div class="form-group">
      <label class="field-label">Procedencia</label>
      <input type="text" name="origin" class="form-input" value="{pv('origin')}">
    </div>
    <div class="form-group">
      <label class="field-label">HCL (Historia Clínica)</label>
      <input type="text" name="hcl" class="form-input" value="{pv('hcl')}">
    </div>
  </div>
  <div class="form-row">
    <div class="form-group">
      <label class="field-label">Talla (cm)</label>
      <input type="text" name="height" class="form-input" value="{pv('height')}">
    </div>
    <div class="form-group">
      <label class="field-label">Peso (kg)</label>
      <input type="text" name="weight" class="form-input" value="{pv('weight')}">
    </div>
    <div class="form-group">
      <label class="field-label">Presión arterial</label>
      <input type="text" name="blood_pressure" class="form-input"
             value="{pv('blood_pressure')}" placeholder="Ej. 120/80">
    </div>
  </div>
  <div class="form-row">
    <div class="form-group">
      <label class="checkbox-label">
        <input type="checkbox" id="pregnant_check" name="is_pregnant" value="1" {pregnant_checked}>
        Gestante
      </label>
    </div>
    <div class="form-group" id="gest-fields" style="display:{'block' if pregnant_checked else 'none'}">
      <label class="field-label">Semanas gestacionales</label>
      <input type="number" name="gestational_age_weeks" class="form-input"
             value="{pv('gestational_age_weeks')}" min="0" max="45">
    </div>
    <div class="form-group" id="edd-field" style="display:{'block' if pregnant_checked else 'none'}">
      <label class="field-label">FPP (Fecha probable parto)</label>
      <input type="date" name="expected_delivery_date" class="form-input"
             value="{pv('expected_delivery_date')}">
    </div>
  </div>

  <div class="section-title">Datos de la orden</div>
  <div class="form-row">
    <div class="form-group">
      <label class="field-label">Médico solicitante</label>
      <input type="text" name="requested_by" class="form-input"
             value="{pv('requested_by')}" list="requesters-list">
      <datalist id="requesters-list">{requesters_opts}</datalist>
    </div>
    <div class="form-group">
      <label class="field-label">Tipo de seguro</label>
      <select name="insurance_type" class="form-select">{insurance_opts}</select>
    </div>
    <div class="form-group">
      <label class="field-label">N° FUA</label>
      <input type="text" name="fua_number" class="form-input" value="{pv('fua_number')}">
    </div>
  </div>
  <div class="form-row">
    <div class="form-group">
      <label class="field-label">Diagnóstico</label>
      <input type="text" name="diagnosis" class="form-input" value="{pv('diagnosis')}">
    </div>
    <div class="form-group">
      <label class="field-label">Fecha de toma de muestra</label>
      <input type="date" name="sample_date" class="form-input" value="{today_str}">
    </div>
  </div>
  <div class="form-group">
    <label class="field-label">Observaciones</label>
    <textarea name="observations" class="form-textarea" rows="2"></textarea>
  </div>

  <div class="section-title">Seleccionar exámenes</div>
  <div id="test-selector">
    {tests_html}
  </div>

  <div style="margin-top:20px">
    <button type="submit" class="btn btn-primary">Crear orden</button>
  </div>
</form>

<script>
document.getElementById('pregnant_check').addEventListener('change', function() {{
  var show = this.checked;
  document.getElementById('gest-fields').style.display = show ? 'block' : 'none';
  document.getElementById('edd-field').style.display = show ? 'block' : 'none';
}});
document.getElementById('birth_date_input').addEventListener('change', function() {{
  var bd = new Date(this.value);
  if (isNaN(bd.getTime())) return;
  var today = new Date();
  var age = Math.floor((today - bd) / (365.25 * 24 * 3600 * 1000));
  document.getElementById('age_years_input').value = age;
}});
</script>
"""
        self._respond_html(_base_layout(content, "registro", user))

    def _handle_registro_get(self, message="", message_kind="success",
                              patient_data=None, selected_tests=None):
        user = self._require_login()
        if not user:
            return
        self._render_registro_page(user, patient_data=patient_data,
                                    message=message, message_kind=message_kind,
                                    selected_tests=selected_tests)

    def _handle_registro_buscar(self):
        user = self._require_login()
        if not user:
            return
        data = _parse_form_body(self)
        doc_type = data.get("doc_type", "DNI").strip()
        doc_number = data.get("doc_number", "").strip()
        patient_data = {"doc_type": doc_type, "doc_number": doc_number}
        msg = ""
        msg_kind = "success"
        if doc_number:
            db = new_db()
            row = db.find_patient(doc_type, doc_number)
            if row:
                # Map tuple to dict based on DB schema
                cols = ["id", "doc_type", "doc_number", "first_name", "last_name",
                        "birth_date", "sex", "origin", "hcl", "height", "weight",
                        "blood_pressure", "is_pregnant", "gestational_age_weeks",
                        "expected_delivery_date"]
                patient_data = dict(zip(cols, row))
                msg = f"Paciente encontrado: {patient_data.get('first_name','')} {patient_data.get('last_name','')}"
            else:
                msg = "Paciente no encontrado. Complete los datos para registrarlo."
                msg_kind = "info"
        self._render_registro_page(user, patient_data=patient_data,
                                    message=msg, message_kind=msg_kind)

    def _handle_registro_orden(self):
        user = self._require_login()
        if not user:
            return
        multi_data = _parse_form_multi(self)
        data = {k: (v[0] if v else "") for k, v in multi_data.items()}

        doc_type = data.get("doc_type", "DNI").strip()
        doc_number = data.get("doc_number", "").strip()
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()
        birth_date = data.get("birth_date", "").strip()
        sex = data.get("sex", "").strip()
        origin = data.get("origin", "").strip()
        hcl = data.get("hcl", "").strip()
        height = data.get("height", "").strip() or None
        weight = data.get("weight", "").strip() or None
        blood_pressure = data.get("blood_pressure", "").strip() or None
        is_pregnant = bool(data.get("is_pregnant"))
        gest_weeks = data.get("gestational_age_weeks", "").strip() or None
        edd = data.get("expected_delivery_date", "").strip() or None
        requested_by = data.get("requested_by", "").strip()
        insurance_type = data.get("insurance_type", "SIS").strip()
        fua_number = data.get("fua_number", "").strip() or None
        diagnosis = data.get("diagnosis", "").strip()
        observations = data.get("observations", "").strip()
        sample_date = data.get("sample_date", "").strip() or None
        age_years = data.get("age_years", "").strip() or None

        selected_tests = multi_data.get("examenes", [])
        if not selected_tests:
            return self._render_registro_page(
                user, patient_data=data,
                message="Seleccione al menos un examen.", message_kind="error"
            )

        if not first_name or not last_name:
            return self._render_registro_page(
                user, patient_data=data,
                message="Nombre y apellidos son obligatorios.", message_kind="error"
            )

        db = new_db()
        try:
            patient_id = db.add_or_update_patient(
                doc_type, doc_number, first_name, last_name, birth_date,
                sex, origin, hcl, height, weight, blood_pressure,
                is_pregnant=is_pregnant,
                gestational_age_weeks=int(gest_weeks) if gest_weeks else None,
                expected_delivery_date=edd
            )
        except Exception as e:
            return self._render_registro_page(
                user, patient_data=data,
                message=f"Error al guardar paciente: {e}", message_kind="error"
            )

        # Check for recent duplicate
        dup = db.find_recent_duplicate_order(patient_id, selected_tests, within_minutes=10)
        if dup:
            return self._render_registro_page(
                user, patient_data=data, selected_tests=selected_tests,
                message=f"Orden duplicada detectada (orden #{dup}) creada hace menos de 10 min. "
                        "Agregue ?force=1 a la URL o espere antes de reintentar.",
                message_kind="error"
            )

        try:
            age_val = int(float(age_years)) if age_years else None
        except Exception:
            age_val = None

        try:
            order_id = db.add_order_with_tests(
                patient_id=patient_id,
                test_names=selected_tests,
                user_id=user["id"],
                observations=observations,
                requested_by=requested_by,
                diagnosis=diagnosis,
                insurance_type=insurance_type,
                fua_number=fua_number,
                age_years=age_val,
                sample_date=sample_date
            )
        except Exception as e:
            return self._render_registro_page(
                user, patient_data=data, selected_tests=selected_tests,
                message=f"Error al crear orden: {e}", message_kind="error"
            )

        self._redirect(f"/resultados/{order_id}")

    # ===========================================================
    # MÓDULO ANOTAR RESULTADOS
    # ===========================================================
    def _handle_resultados_list(self, message="", message_kind="success"):
        user = self._require_login()
        if not user:
            return
        db = new_db()
        pending = db.get_pending_orders()

        rows_html = ""
        for row in pending:
            order_id, first_name, last_name, date, sample_date, doc_type, doc_number = row
            patient_name = f"{first_name or ''} {last_name or ''}".strip() or "-"
            doc = f"{doc_type or ''} {doc_number or ''}".strip() or "-"
            date_disp = date[:10] if date else "-"
            sample_disp = sample_date[:10] if sample_date else "-"
            rows_html += f"""
<tr>
  <td>{order_id}</td>
  <td>{html.escape(patient_name)}</td>
  <td>{html.escape(doc)}</td>
  <td>{html.escape(date_disp)}</td>
  <td>{html.escape(sample_disp)}</td>
  <td><a href="/resultados/{order_id}" class="btn btn-sm btn-primary">Ingresar</a></td>
</tr>"""

        alert_html = _alert(message, message_kind) if message else ""
        content = f"""
{alert_html}
<h2 class="page-title">Anotar Resultados</h2>
<p>Órdenes pendientes de resultado: <strong>{len(pending)}</strong></p>
<div class="table-wrapper">
  <table class="data-table">
    <thead>
      <tr><th>#</th><th>Paciente</th><th>Documento</th>
          <th>Fecha orden</th><th>F. muestra</th><th>Acción</th></tr>
    </thead>
    <tbody>
      {''.join(rows_html) if rows_html else '<tr><td colspan="6" class="text-center muted">No hay órdenes pendientes</td></tr>'}
    </tbody>
  </table>
</div>"""
        self._respond_html(_base_layout(content, "resultados", user))

    def _handle_resultados_form_get(self, order_id: int, message="", message_kind="success"):
        user = self._require_login()
        if not user:
            return
        db = new_db()
        order_details = db.get_order_details(order_id)
        if not order_details:
            return self._handle_resultados_list(
                message=f"Orden #{order_id} no encontrada.", message_kind="error"
            )

        pat = order_details["patient"]
        ord_inf = order_details["order"]
        patient_name = f"{pat.get('first_name','')} {pat.get('last_name','')}".strip()
        doc = f"{pat.get('doc_type','')} {pat.get('doc_number','')}".strip()
        date_disp = (ord_inf.get("date") or "")[:10]

        form_html = _build_result_form_html(order_id, order_details)
        alert_html = _alert(message, message_kind) if message else ""

        content = f"""
{alert_html}
<h2 class="page-title">Ingresar Resultados — Orden #{order_id}</h2>
<div class="order-info-bar">
  <span><strong>Paciente:</strong> {html.escape(patient_name)}</span>
  <span><strong>Documento:</strong> {html.escape(doc)}</span>
  <span><strong>Fecha:</strong> {html.escape(date_disp)}</span>
</div>
<form method="post" action="/resultados/{order_id}" class="card-form">
  {form_html}
  <div style="margin-top:20px; display:flex; gap:12px">
    <button type="submit" class="btn btn-primary">💾 Guardar resultados</button>
    <a href="/resultados" class="btn btn-secondary">← Volver</a>
  </div>
</form>"""
        self._respond_html(_base_layout(content, "resultados", user))

    def _handle_resultados_save(self, order_id: int):
        user = self._require_login()
        if not user:
            return
        multi_data = _parse_form_multi(self)
        data = {k: (v[0] if v else "") for k, v in multi_data.items()}

        total_tests = int(data.get("total_tests", 0))
        results_dict = _parse_results_from_form(data, multi_data, total_tests)

        if not results_dict:
            return self._handle_resultados_form_get(
                order_id, message="No se recibieron datos.", message_kind="error"
            )

        db = new_db()
        try:
            completed = db.save_results(order_id, results_dict)
        except Exception as e:
            return self._handle_resultados_form_get(
                order_id, message=f"Error al guardar: {e}", message_kind="error"
            )

        if completed:
            self._redirect(f"/emitir?msg=Orden+{order_id}+completada")
        else:
            self._handle_resultados_form_get(
                order_id,
                message="Resultados guardados. La orden aún tiene pruebas pendientes.",
                message_kind="info"
            )

    # ===========================================================
    # MÓDULO EMITIR RESULTADOS
    # ===========================================================
    def _handle_emitir_list(self):
        user = self._require_login()
        if not user:
            return
        params = _get_query_params(self.path)
        include_emitted = params.get("include_emitted") == "1"
        message = params.get("msg", "")

        db = new_db()
        orders = db.get_completed_orders(include_emitted=include_emitted)

        rows_html = ""
        for row in orders:
            (order_id, first_name, last_name, date, sample_date,
             doc_type, doc_number, emitted, emitted_at) = row
            patient_name = f"{first_name or ''} {last_name or ''}".strip() or "-"
            doc = f"{doc_type or ''} {doc_number or ''}".strip() or "-"
            date_disp = (date or "")[:10]
            emitted_disp = "Si" if emitted else "—"
            rows_html += f"""
<tr>
  <td>{order_id}</td>
  <td>{html.escape(patient_name)}</td>
  <td>{html.escape(doc)}</td>
  <td>{html.escape(date_disp)}</td>
  <td>{emitted_disp}</td>
  <td>
    <a href="/emitir/{order_id}/pdf" class="btn btn-sm btn-primary" target="_blank">📄 PDF</a>
    <form method="post" action="/emitir/{order_id}/marcar" style="display:inline">
      <button type="submit" class="btn btn-sm btn-secondary">Marcar emitido</button>
    </form>
  </td>
</tr>"""

        toggle_label = "Ocultar emitidos" if include_emitted else "Mostrar emitidos"
        toggle_url = "/emitir" if include_emitted else "/emitir?include_emitted=1"
        alert_html = _alert(html.escape(message)) if message else ""

        content = f"""
{alert_html}
<h2 class="page-title">Emitir Resultados</h2>
<div style="margin-bottom:12px">
  <a href="{toggle_url}" class="btn btn-secondary">{toggle_label}</a>
</div>
<div class="table-wrapper">
  <table class="data-table">
    <thead>
      <tr><th>#</th><th>Paciente</th><th>Documento</th>
          <th>Fecha</th><th>Emitido</th><th>Acciones</th></tr>
    </thead>
    <tbody>
      {''.join(rows_html) if rows_html else '<tr><td colspan="6" class="text-center muted">No hay órdenes completadas</td></tr>'}
    </tbody>
  </table>
</div>"""
        self._respond_html(_base_layout(content, "emitir", user))

    def _handle_emitir_pdf(self, order_id: int):
        user = self._require_login()
        if not user:
            return
        db = new_db()
        order_details = db.get_order_details(order_id)
        if not order_details:
            return self._handle_emitir_list()

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        existing_emitted = order_details.get("order", {}).get("emitted")

        try:
            pdf_bytes = generate_order_pdf(order_details, emitted_at=now_str)
        except Exception as e:
            content = _alert(f"Error al generar PDF: {html.escape(str(e))}", "error")
            return self._respond_html(_base_layout(content, "emitir", user))

        if not existing_emitted:
            try:
                db.mark_order_emitted(order_id, now_str)
            except Exception:
                pass

        self._respond_pdf(pdf_bytes, f"orden_{order_id}.pdf")

    def _handle_emitir_marcar(self, order_id: int):
        user = self._require_login()
        if not user:
            return
        db = new_db()
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.mark_order_emitted(order_id, now_str)
        self._redirect(f"/emitir?msg=Orden+{order_id}+marcada+como+emitida")

    # ===========================================================
    # MÓDULO ANÁLISIS
    # ===========================================================
    def _handle_analisis(self):
        user = self._require_login()
        if not user:
            return
        params = _get_query_params(self.path)
        desde = params.get("desde", "")
        hasta = params.get("hasta", "")

        stats = None
        error_msg = ""
        start_dt = None
        end_dt = None

        if desde or hasta:
            try:
                if desde:
                    start_dt = desde + " 00:00:00"
                if hasta:
                    end_dt = hasta + " 23:59:59"
            except Exception as e:
                error_msg = str(e)

        db = new_db()
        try:
            stats = db.get_statistics(
                start_datetime=start_dt if desde else None,
                end_datetime=end_dt if hasta else None
            )
        except Exception as e:
            error_msg = str(e)

        summary_html = ""
        table_html = ""
        if stats:
            summary_html = f"""
<div class="dashboard-grid" style="margin-bottom:20px">
  <div class="metric-card"><h2>Pacientes</h2><p>{stats.get('total_patients',0)}</p></div>
  <div class="metric-card"><h2>Órdenes</h2><p>{stats.get('total_orders',0)}</p></div>
  <div class="metric-card"><h2>Pruebas realizadas</h2><p>{stats.get('total_tests_conducted',0)}</p></div>
</div>"""

            by_cat_list = stats.get("by_category", [])
            by_cat = {cat: count for cat, count in by_cat_list}
            rows = []
            for cat in CATEGORY_DISPLAY_ORDER:
                if cat in by_cat:
                    rows.append((cat, by_cat[cat]))
            for cat, count in by_cat.items():
                if cat not in CATEGORY_DISPLAY_ORDER:
                    rows.append((cat, count))

            if rows:
                rows_html = "".join(
                    f"<tr><td>{html.escape(cat)}</td><td class='text-center'>{count}</td></tr>"
                    for cat, count in rows
                )
                table_html = f"""
<div class="table-wrapper">
  <table class="data-table">
    <thead><tr><th>Categoría</th><th>Cantidad</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
</div>"""

        alert_html = _alert(error_msg, "error") if error_msg else ""
        today = datetime.date.today().isoformat()
        first_of_month = datetime.date.today().replace(day=1).isoformat()

        content = f"""
{alert_html}
<h2 class="page-title">Análisis de Datos</h2>
<form method="get" action="/analisis" class="card-form">
  <div class="form-row">
    <div class="form-group">
      <label class="field-label">Desde</label>
      <input type="date" name="desde" class="form-input"
             value="{html.escape(desde) if desde else first_of_month}">
    </div>
    <div class="form-group">
      <label class="field-label">Hasta</label>
      <input type="date" name="hasta" class="form-input"
             value="{html.escape(hasta) if hasta else today}">
    </div>
    <div class="form-group form-group--action">
      <label class="field-label">&nbsp;</label>
      <button type="submit" class="btn btn-primary">📊 Consultar</button>
    </div>
    <div class="form-group form-group--action">
      <label class="field-label">&nbsp;</label>
      <a href="/analisis" class="btn btn-secondary">Todo el tiempo</a>
    </div>
  </div>
</form>
{summary_html}
{table_html}
"""
        self._respond_html(_base_layout(content, "analisis", user))

    # ===========================================================
    # MÓDULO CONFIGURACIÓN
    # ===========================================================
    def _handle_configuracion_get(self, message="", message_kind="success"):
        user = self._require_login()
        if not user:
            return
        db = new_db()

        alert_html = _alert(message, message_kind) if message else ""

        # User list (admin only)
        user_list_html = ""
        is_admin = user.get("role") in ("super", "admin")
        if is_admin:
            db.cur.execute("SELECT id, username, role, full_name, profession, license FROM users ORDER BY id")
            users_rows = db.cur.fetchall()
            rows_html = ""
            for uid, uname, urole, ufull, uprof, ulic in users_rows:
                rows_html += f"""
<tr>
  <td>{uid}</td>
  <td>{html.escape(uname or '')}</td>
  <td><span class="badge badge-{html.escape(urole or 'user')}">{html.escape(urole or '')}</span></td>
  <td>{html.escape(ufull or '')}</td>
  <td>{html.escape(uprof or '')}</td>
  <td>{html.escape(ulic or '')}</td>
</tr>"""
            role_options = "".join(
                f'<option value="{r}">{r}</option>' for r in ["user", "admin", "super"]
            )
            user_list_html = f"""
<div class="section-card">
  <h3>Gestión de Usuarios</h3>
  <div class="table-wrapper">
    <table class="data-table">
      <thead><tr><th>ID</th><th>Usuario</th><th>Rol</th>
          <th>Nombre completo</th><th>Profesión</th><th>Colegiatura</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
  <details style="margin-top:16px">
    <summary class="btn btn-secondary" style="cursor:pointer">➕ Nuevo usuario</summary>
    <form method="post" action="/configuracion/usuario/nuevo" class="card-form" style="margin-top:12px">
      <div class="form-row">
        <div class="form-group">
          <label class="field-label">Usuario *</label>
          <input type="text" name="username" class="form-input" required>
        </div>
        <div class="form-group">
          <label class="field-label">Contraseña *</label>
          <input type="password" name="password" class="form-input" required>
        </div>
        <div class="form-group">
          <label class="field-label">Rol</label>
          <select name="role" class="form-select">{role_options}</select>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="field-label">Nombre completo</label>
          <input type="text" name="full_name" class="form-input">
        </div>
        <div class="form-group">
          <label class="field-label">Profesión</label>
          <input type="text" name="profession" class="form-input">
        </div>
        <div class="form-group">
          <label class="field-label">N° Colegiatura</label>
          <input type="text" name="license" class="form-input">
        </div>
      </div>
      <button type="submit" class="btn btn-primary">Crear usuario</button>
    </form>
  </details>
</div>"""

        content = f"""
{alert_html}
<h2 class="page-title">Configuración</h2>
{user_list_html}

<div class="section-card">
  <h3>Mi perfil</h3>
  <form method="post" action="/configuracion/perfil" class="card-form">
    <div class="form-row">
      <div class="form-group">
        <label class="field-label">Nombre completo</label>
        <input type="text" name="full_name" class="form-input"
               value="{html.escape(user.get('full_name') or '')}">
      </div>
    </div>
    <button type="submit" class="btn btn-primary">Guardar perfil</button>
  </form>
</div>

<div class="section-card">
  <h3>Cambiar contraseña</h3>
  <form method="post" action="/configuracion/password" class="card-form">
    <div class="form-row">
      <div class="form-group">
        <label class="field-label">Contraseña actual</label>
        <input type="password" name="current_password" class="form-input" required>
      </div>
      <div class="form-group">
        <label class="field-label">Nueva contraseña</label>
        <input type="password" name="new_password" class="form-input" required>
      </div>
      <div class="form-group">
        <label class="field-label">Confirmar contraseña</label>
        <input type="password" name="confirm_password" class="form-input" required>
      </div>
    </div>
    <button type="submit" class="btn btn-primary">Cambiar contraseña</button>
  </form>
</div>
"""
        self._respond_html(_base_layout(content, "configuracion", user))

    def _handle_config_nuevo_usuario(self):
        user = self._require_login()
        if not user:
            return
        if user.get("role") not in ("super", "admin"):
            return self._handle_configuracion_get(
                message="No tiene permisos para crear usuarios.", message_kind="error"
            )
        data = _parse_form_body(self)
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        role = data.get("role", "user").strip()
        full_name = data.get("full_name", "").strip()
        profession = data.get("profession", "").strip()
        license_ = data.get("license", "").strip()

        if not username or not password:
            return self._handle_configuracion_get(
                message="Usuario y contraseña son requeridos.", message_kind="error"
            )
        db = new_db()
        ok = db.create_user(username, password, role, full_name, profession, license_)
        if ok:
            self._handle_configuracion_get(
                message=f"Usuario '{username}' creado exitosamente."
            )
        else:
            self._handle_configuracion_get(
                message=f"El usuario '{username}' ya existe.", message_kind="error"
            )

    def _handle_config_perfil(self):
        user = self._require_login()
        if not user:
            return
        data = _parse_form_body(self)
        full_name = data.get("full_name", "").strip()
        db = new_db()
        db.update_user_profile(user["id"], full_name,
                               profession="", license="")
        # Update session
        sid = self._get_session_id()
        if sid:
            with _SESSION_LOCK:
                entry = SESSIONS.get(sid)
                if entry:
                    entry["user"]["full_name"] = full_name
        self._handle_configuracion_get(message="Perfil actualizado.")

    def _handle_config_password(self):
        user = self._require_login()
        if not user:
            return
        data = _parse_form_body(self)
        current_pw = data.get("current_password", "")
        new_pw = data.get("new_password", "").strip()
        confirm_pw = data.get("confirm_password", "").strip()

        if new_pw != confirm_pw:
            return self._handle_configuracion_get(
                message="Las contraseñas no coinciden.", message_kind="error"
            )
        if not new_pw:
            return self._handle_configuracion_get(
                message="La nueva contraseña no puede estar vacía.", message_kind="error"
            )
        db = new_db()
        verified = db.authenticate_user(user["username"], current_pw)
        if not verified:
            return self._handle_configuracion_get(
                message="Contraseña actual incorrecta.", message_kind="error"
            )
        db.cur.execute("UPDATE users SET password=? WHERE id=?", (new_pw, user["id"]))
        db.conn.commit()
        self._handle_configuracion_get(message="Contraseña actualizada correctamente.")

    # ===========================================================
    # STATIC FILES
    # ===========================================================
    def _serve_static(self):
        rel = self.path.replace("/static/", "", 1).split("?")[0]
        target = (STATIC_DIR / rel).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.exists():
            self.send_error(404)
            return
        content = target.read_bytes()
        ext = target.suffix.lower()
        mime_map = {".css": "text/css", ".js": "text/javascript",
                    ".png": "image/png", ".jpg": "image/jpeg", ".ico": "image/x-icon"}
        mime = mime_map.get(ext, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", f"{mime}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


# ---------------------------------------------------------------------------
# Servidor
# ---------------------------------------------------------------------------

def run(host="0.0.0.0", port=8000):
    server = ThreadingHTTPServer((host, port), WebHandler)
    print(f"[OK] Servidor activo en http://localhost:{port}")
    print("   Abre esta URL en Chrome o Brave para usar el sistema.")
    print("   Presiona Ctrl+C para detener.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")


if __name__ == "__main__":
    run()

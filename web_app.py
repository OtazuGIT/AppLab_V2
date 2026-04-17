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
from pdf_generator import generate_order_pdf, generate_batch_pdf
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
# Date display helper — DD/MM/YYYY everywhere in the UI
# ---------------------------------------------------------------------------
def _fmt_date(value, placeholder="—") -> str:
    """Convert YYYY-MM-DD (or datetime string) to DD/MM/YYYY for display."""
    if not value or str(value).strip() in ("", "None"):
        return placeholder
    s = str(value).strip()[:10]  # take only date portion
    # Already DD/MM/YYYY?
    if len(s) == 10 and s[2] == "/" and s[5] == "/":
        return s
    # YYYY-MM-DD → DD/MM/YYYY
    parts = s.split("-")
    if len(parts) == 3 and len(parts[0]) == 4:
        return f"{parts[2]}/{parts[1]}/{parts[0]}"
    return s


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
  <title>Laboratorio P.S. Inapari</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body class="app-body">
  <div class="app-shell">
    <nav class="side-menu">
      <div class="side-menu__title">Laboratorio P.S.<br>Inapari - 002789</div>
      <div class="side-menu__nav">
        {nav_links_html}
      </div>
      <div class="side-menu__logout">
        <form method="post" action="/logout">
          <button type="submit" class="logout-btn">Cerrar sesion ({display_name})</button>
        </form>
      </div>
    </nav>
    <main class="content-area" style="padding:14px; display:flex; flex-direction:column; overflow:hidden;">
      <div class="topbar" style="padding:10px 16px; margin-bottom:10px; display:flex; align-items:center; gap:12px;">
        <div>
          <strong style="font-size:1rem;">Laboratorio P.S. Inapari - 002789</strong>
        </div>
        <span class="topbar-clock" id="main-clock"></span>
      </div>
      <div class="page-content" style="flex:1; overflow:hidden; min-height:0;">
        {content_html}
      </div>
    </main>
  </div>
  <script>
    (function(){{
      function updateClock(){{
        var now = new Date();
        var d = String(now.getDate()).padStart(2,'0');
        var mo = String(now.getMonth()+1).padStart(2,'0');
        var y = now.getFullYear();
        var h = String(now.getHours()).padStart(2,'0');
        var mi = String(now.getMinutes()).padStart(2,'0');
        var s = String(now.getSeconds()).padStart(2,'0');
        var el = document.getElementById('main-clock');
        if(el) el.textContent = d+'/'+mo+'/'+y+' '+h+':'+mi+':'+s;
      }}
      updateClock();
      setInterval(updateClock, 1000);
    }})();
  </script>
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

_DIPSTICK_VALS = ["Negativo", "Trazas", "+", "++", "+++", "++++"]


def _build_result_form_html(order_id: int, order_details: dict) -> str:
    """Genera el HTML del formulario de ingreso de resultados."""
    results = order_details.get("results", [])

    # Mapa de resultados existentes por nombre de test
    existing = {}
    for row in results:
        test_name = row[0]
        existing[test_name] = {
            "raw": row[1],
            "sample_status": row[3] or "recibida",
            "sample_issue": row[4] or "",
            "observation": row[5] or "",
            "sample_type": row[6] or "",
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
        return values.get(key, "") if values else ""

    def _get_plain_result(test_name):
        raw = existing.get(test_name, {}).get("raw", "")
        if not raw:
            return ""
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                v = data.get("value") or data.get("values", {})
                if isinstance(v, dict):
                    for val in v.values():
                        return val or ""
                return v or ""
        except Exception:
            return raw
        return ""

    fields_html = ""
    extra_js = []   # auto-calc + diff-counter JS fragments

    for idx, row in enumerate(results):
        test_name = row[0]
        sample_status = row[3] or "recibida"
        sample_issue_val = row[4] or ""
        observation_val = row[5] or ""
        sample_type_val = row[6] or ""
        is_pendiente = sample_status == "pendiente"
        sin_muestra_active = " active" if is_pendiente else ""
        sin_muestra_label = "&#10003; Sin muestra" if is_pendiente else "Sin muestra"
        fields_opacity = ' style="opacity:0.35;pointer-events:none"' if is_pendiente else ''

        template = get_template_for_test(test_name)
        safe_test = html.escape(test_name)

        fields_html += f"""
<div class="test-fieldset" id="test-block-{idx}">
  <div class="test-fieldset__header">
    <span class="test-name">{safe_test}</span>
    <div class="test-header-actions">
      <button type="button" class="btn-sin-muestra{sin_muestra_active}" id="sin-muestra-btn-{idx}" onclick="toggleSinMuestra(this,{idx})">{sin_muestra_label}</button>
      <span class="sample-status-badge status-{html.escape(sample_status)}" id="status-badge-{idx}">{html.escape(sample_status.capitalize())}</span>
    </div>
  </div>
  <input type="hidden" name="test_{idx}_name" value="{safe_test}">
"""

        if template:
            fields = template.get("fields", [])
            is_hemograma = "hemograma" in test_name.lower()
            fields_html += f'<div class="test-fields" id="test-fields-{idx}"{fields_opacity}>'
            if is_hemograma:
                fields_html += f'<div class="diff-counter diff-pending" id="diff-counter-{idx}">Conteo diferencial: <span id="diff-sum-{idx}">0</span> / 100</div>'
            fields_html += '<div class="results-grid">'

            for fld in fields:
                ftype = fld.get("type", "line")
                if ftype == "section":
                    fields_html += f'<div class="rg-section">{html.escape(fld.get("label",""))}</div>'
                    continue

                key = fld.get("key", "")
                label = fld.get("label", key)
                reference = fld.get("reference", "")
                unit = fld.get("unit", "")
                placeholder = fld.get("placeholder", "")
                quick_neg = fld.get("quick_negative", "")
                field_input_name = f"test_{idx}_field_{key}"
                existing_val = _get_existing_value(test_name, key)
                safe_label = html.escape(label)
                safe_ref = html.escape(reference) if reference else ""
                ref_tooltip = f' title="{safe_ref}"' if reference else ""

                if ftype == "bool":
                    pos_text = fld.get("positive_text", "Positivo")
                    neg_text = fld.get("negative_text", "Negativo")
                    pos_checked = 'checked' if existing_val == pos_text else ''
                    neg_checked = 'checked' if existing_val == neg_text else ''
                    fields_html += f"""<div class="rg-row rg-bool-row">
  <span class="rg-label">{safe_label}</span>
  <div class="rg-bool-opts">
    <label class="bool-opt positive-opt"><input type="radio" name="{field_input_name}" value="{html.escape(pos_text)}" {pos_checked}> {html.escape(pos_text)}</label>
    <label class="bool-opt negative-opt"><input type="radio" name="{field_input_name}" value="{html.escape(neg_text)}" {neg_checked}> {html.escape(neg_text)}</label>
  </div>
  <span class="rg-ref">{safe_ref}</span>
</div>"""

                elif ftype == "dipstick":
                    dip_buttons = ""
                    for dv in _DIPSTICK_VALS:
                        is_active = "dip-active" if existing_val == dv else ""
                        neg_cls = " dip-neg" if dv == "Negativo" else ""
                        esc_dv = html.escape(dv)
                        dip_buttons += f'<button type="button" class="dip-btn{neg_cls} {is_active}" data-val="{esc_dv}" onclick="setDipstick(this)">{esc_dv}</button>'
                    fields_html += f"""<div class="rg-row rg-dip-row">
  <span class="rg-label">{safe_label}</span>
  <div class="dipstick-opts rg-dip-btns" data-input="{field_input_name}">
    {dip_buttons}
    <input type="hidden" name="{field_input_name}" value="{html.escape(existing_val)}">
  </div>
</div>"""

                elif ftype == "text_area":
                    safe_val = html.escape(existing_val)
                    qneg_btn = ""
                    if quick_neg or (reference and "no se observan" in reference.lower()):
                        qv = html.escape(quick_neg or "No se observan")
                        qneg_btn = f' <button type="button" class="btn-quick-neg" onclick="setQuickNeg(this,\'{qv}\')">(-)</button>'
                    fields_html += f"""<div class="rg-textarea-row">
  <span class="rg-label">{safe_label}{qneg_btn if qneg_btn else ''}</span>
  <textarea name="{field_input_name}" class="rg-textarea" rows="2" placeholder="{html.escape(placeholder)}">{safe_val}</textarea>
  {f'<span class="rg-ref rg-ref-ta">{safe_ref}</span>' if safe_ref else ''}
</div>"""

                elif ftype == "choice":
                    choices = fld.get("choices", [])
                    opts = '<option value="">--</option>' + "".join(
                        f'<option value="{html.escape(c)}" {"selected" if existing_val == c else ""}>{html.escape(c)}</option>'
                        for c in choices
                    )
                    fields_html += f"""<div class="rg-row">
  <span class="rg-label">{safe_label}</span>
  <select name="{field_input_name}" class="rg-select">{opts}</select>
  <span class="rg-unit"></span>
  <span class="rg-ref">{safe_ref}</span>
</div>"""

                else:  # line (default)
                    safe_val = html.escape(str(existing_val))
                    field_id = f"fld_{idx}_{key}"
                    qneg_btn = ""
                    if quick_neg or (reference and "no se observan" in reference.lower()):
                        qv = html.escape(quick_neg or "No se observan")
                        qneg_btn = f' <button type="button" class="btn-quick-neg" onclick="setQuickNeg(this,\'{qv}\')">(-)</button>'
                    fields_html += f"""<div class="rg-row">
  <span class="rg-label">{safe_label}{qneg_btn if qneg_btn else ''}</span>
  <input type="text" id="{field_id}" name="{field_input_name}" class="rg-input"
         value="{safe_val}" placeholder="{html.escape(placeholder)}">
  <span class="rg-unit">{html.escape(unit)}</span>
  <span class="rg-ref">{safe_ref}</span>
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
                extra_js.append(f"""
(function() {{
  var src = document.getElementById('{src_id}');
  var tgt = document.getElementById('{tgt_id}');
  if (!src || !tgt) return;
  src.addEventListener('input', function() {{
    var val = parseFloat(src.value.replace(',', '.'));
    if (isNaN(val)) return;
    var result = {f'val / {operand}' if op == 'divide' else f'val * {operand}'};
    {'if (!tgt.value || tgt.value === "0") ' if only_if_empty else ''}tgt.value = result.toFixed({decimals});
  }});
}})();""")

            # Hemograma differential counter JS
            if is_hemograma:
                diff_keys = ['segmentados','abastonados','linfocitos','monocitos',
                             'eosinofilos','basofilos','mielocitos','metamielocitos']
                diff_ids_js = "[" + ",".join(f"'fld_{idx}_{k}'" for k in diff_keys) + "]"
                extra_js.append(f"""
(function() {{
  var DIDS = {diff_ids_js};
  var box = document.getElementById('diff-counter-{idx}');
  var span = document.getElementById('diff-sum-{idx}');
  if (!box || !span) return;
  function updateDiff() {{
    var s = 0;
    DIDS.forEach(function(id) {{
      var el = document.getElementById(id);
      if (el) s += parseFloat(el.value.replace(',','.')) || 0;
    }});
    span.textContent = s.toFixed(1);
    box.className = 'diff-counter ' + (Math.abs(s-100)<0.5 ? 'diff-ok' : s>100 ? 'diff-over' : 'diff-pending');
  }}
  DIDS.forEach(function(id) {{
    var el = document.getElementById(id);
    if (el) el.addEventListener('input', updateDiff);
  }});
  updateDiff();
}})();""")

            fields_html += '</div>'  # close results-grid
            fields_html += '</div>'  # close test-fields

        else:
            plain_val = html.escape(_get_plain_result(test_name))
            fields_html += f"""<div class="test-fields" id="test-fields-{idx}"{fields_opacity}>
  <div class="results-grid">
    <div class="rg-textarea-row">
      <span class="rg-label">Resultado</span>
      <textarea name="test_{idx}_plain" class="rg-textarea" rows="2">{plain_val}</textarea>
    </div>
  </div>
</div>"""

        # Meta row compacta (inline)
        status_options = ["recibida", "pendiente", "rechazada"]
        status_opts_html = "".join(
            f'<option value="{s}" {"selected" if sample_status == s else ""}>{s.capitalize()}</option>'
            for s in status_options
        )
        reject_display = "flex" if sample_status == "rechazada" else "none"
        fields_html += f"""
  <div class="test-meta">
    <label class="meta-lbl">Muestra:</label>
    <input type="text" name="test_{idx}_sample_type" class="meta-input"
           value="{html.escape(sample_type_val)}" placeholder="Tipo de muestra">
    <label class="meta-lbl">Obs:</label>
    <input type="text" name="test_{idx}_observation" class="meta-input"
           value="{html.escape(observation_val)}" placeholder="Observación">
    <select name="test_{idx}_sample_status" class="meta-select"
            onchange="onStatusChange(this,{idx})">{status_opts_html}</select>
    <div id="reject-row-{idx}" style="display:{reject_display};align-items:center;gap:4px">
      <label class="meta-lbl">Motivo:</label>
      <input type="text" name="test_{idx}_sample_issue" class="meta-input"
             value="{html.escape(sample_issue_val)}" placeholder="Motivo rechazo">
    </div>
  </div>
</div>"""  # close test-fieldset

    total_tests = len(results)
    js_block = ""
    if extra_js:
        js_block = "<script>" + "".join(extra_js) + "\n" + _RESULT_FORM_COMMON_JS + "</script>"
    else:
        js_block = f"<script>{_RESULT_FORM_COMMON_JS}</script>"

    return f"""
<input type="hidden" name="total_tests" value="{total_tests}">
{fields_html}
{js_block}
"""


_RESULT_FORM_COMMON_JS = """
function setDipstick(btn) {
  var container = btn.closest('.dipstick-opts');
  container.querySelectorAll('.dip-btn').forEach(function(b){ b.classList.remove('dip-active'); });
  btn.classList.add('dip-active');
  container.querySelector('input[type=hidden]').value = btn.dataset.val;
  if (typeof markFormDirty === 'function') markFormDirty();
}
function setQuickNeg(btn, val) {
  var grp = btn.closest('.rg-row, .rg-textarea-row, .form-group');
  var inp = grp ? grp.querySelector('input[type=text], textarea') : null;
  if (inp) { inp.value = val; }
  btn.classList.add('active');
  if (typeof markFormDirty === 'function') markFormDirty();
}
function onStatusChange(sel, idx) {
  var row = document.getElementById('reject-row-' + idx);
  if (row) row.style.display = sel.value === 'rechazada' ? 'flex' : 'none';
  var btn = document.getElementById('sin-muestra-btn-' + idx);
  var fd  = document.getElementById('test-fields-' + idx);
  var badge = document.getElementById('status-badge-' + idx);
  if (btn) {
    var isPend = sel.value === 'pendiente';
    btn.classList.toggle('active', isPend);
    btn.textContent = isPend ? '\u2713 Sin muestra' : 'Sin muestra';
    if (fd) { fd.style.opacity = isPend ? '0.35' : '1'; fd.style.pointerEvents = isPend ? 'none' : ''; }
  }
  if (badge) { badge.textContent = sel.value.charAt(0).toUpperCase()+sel.value.slice(1); badge.className = 'sample-status-badge status-'+sel.value; }
  if (typeof markFormDirty === 'function') markFormDirty();
}
function toggleSinMuestra(btn, idx) {
  var fd  = document.getElementById('test-fields-' + idx);
  var sel = document.querySelector('[name="test_' + idx + '_sample_status"]');
  var badge = document.getElementById('status-badge-' + idx);
  var isActive = btn.classList.contains('active');
  btn.classList.toggle('active', !isActive);
  btn.textContent = isActive ? 'Sin muestra' : '\u2713 Sin muestra';
  var newStatus = isActive ? 'recibida' : 'pendiente';
  if (fd)  { fd.style.opacity = isActive ? '1' : '0.35'; fd.style.pointerEvents = isActive ? '' : 'none'; }
  if (sel) sel.value = newStatus;
  if (badge) { badge.textContent = newStatus.charAt(0).toUpperCase()+newStatus.slice(1); badge.className = 'sample-status-badge status-'+newStatus; }
  if (typeof markFormDirty === 'function') markFormDirty();
}
function toggleRejectReason(sel, idx) {
  var row = document.getElementById('reject-row-' + idx);
  if (row) row.style.display = sel.value === 'rechazada' ? 'flex' : 'none';
}
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
            # Solo serializar si hay valores ingresados; si está vacío, dejar ""
            # para que _update_order_completion lo cuente como pendiente
            if values:
                result_value = json.dumps({"type": "structured",
                                           "template": test_name,
                                           "values": values})
            else:
                result_value = ""
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
            if len(parts) == 2 and parts[1] == "exportar_csv":
                return self._handle_emitir_exportar_csv()
            return self._handle_emitir_list()
        if parts[0] == "analisis":
            if len(parts) == 2 and parts[1] == "registro_pdf":
                return self._handle_analisis_registro_pdf()
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
        if parts[0] == "resultados" and len(parts) == 3 and parts[1].isdigit() and parts[2] == "eliminar":
            return self._handle_resultados_eliminar(int(parts[1]))
        if parts[0] == "resultados" and len(parts) == 3 and parts[1].isdigit() and parts[2] == "rechazar":
            return self._handle_resultados_rechazar(int(parts[1]))
        if parts[0] == "emitir" and len(parts) == 3 and parts[1].isdigit() and parts[2] == "marcar":
            return self._handle_emitir_marcar(int(parts[1]))
        if parts[0] == "emitir" and len(parts) == 2 and parts[1] == "batch":
            return self._handle_emitir_batch()
        if parts[0] == "analisis" and len(parts) == 2 and parts[1] == "fua":
            return self._handle_analisis_fua_update()
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
        pending_count = len(db.get_pending_orders())

        # Group tests by category in CATEGORY_DISPLAY_ORDER
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

        # Build test checkboxes — 2-column grid, no accordion
        tests_html = ""
        for cat_name, tests_list in ordered_cats:
            safe_cat = html.escape(cat_name)
            items = ""
            for t in tests_list:
                safe_t = html.escape(t)
                chk = "checked" if selected_tests and t in selected_tests else ""
                items += (f'<label class="exam-check-item">'
                          f'<input type="checkbox" name="examenes" value="{safe_t}" {chk}>'
                          f'<span>{safe_t}</span></label>\n')
            tests_html += f'<div class="test-category-label">{safe_cat}</div>\n'
            tests_html += f'<div class="test-checkbox-grid">{items}</div>\n'

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
        origin_opts = "".join(
            f'<option value="{o}" {"selected" if pv("origin") == o else ""}>{o}</option>'
            for o in ["P.S Inapari", "C.S. Inapari", "Comunidades", "Hospital", "Otro"]
        )
        pregnant_checked = "checked" if p.get("is_pregnant") else ""
        gest_display = "block" if p.get("is_pregnant") else "none"
        today_str = datetime.date.today().isoformat()

        alert_html = _alert(message, message_kind) if message else ""

        content = f"""
{alert_html}
<div class="alertas-bar">
  Alertas: <a href="/resultados">Ver pendientes ({pending_count})</a>
</div>

<form id="form-registro" method="post" action="/registro/orden" style="flex:1;min-height:0;display:flex;flex-direction:column;">
  <input type="hidden" name="doc_type" id="hid_doc_type" value="{pv('doc_type', 'DNI')}">
  <input type="hidden" name="doc_number" id="hid_doc_number" value="{pv('doc_number')}">

  <div class="registro-grid" style="flex:1;min-height:0;">

    <!-- LEFT: Patient form -->
    <div class="registro-form">

      <!-- Documento search bar -->
      <div class="form-row-compact" style="align-items:flex-end;">
        <div class="form-group-compact" style="flex:0 0 90px;">
          <label>Documento</label>
          <select id="in_doc_type" class="form-select-compact" onchange="document.getElementById('hid_doc_type').value=this.value">
            {doc_type_opts}
          </select>
        </div>
        <div class="form-group-compact" style="flex:1;">
          <label>&nbsp;</label>
          <input id="in_doc_number" type="text" class="form-input-compact"
                 value="{pv('doc_number')}" placeholder="N° documento — doble clic para ver historial"
                 title="Doble clic aqui para ver el historial del paciente"
                 onchange="document.getElementById('hid_doc_number').value=this.value"
                 ondblclick="verHistorial()">
        </div>
        <div style="padding-bottom:2px;">
          <button type="button" class="btn btn-secondary btn-sm" onclick="buscarPaciente()">Buscar</button>
        </div>
        <div style="padding-bottom:2px;">
          <button type="button" class="btn btn-secondary btn-sm"
                  title="Ver historial de ordenes del paciente"
                  onclick="verHistorial()">Ver Historial</button>
        </div>
      </div>

      <!-- Procedencia -->
      <div class="form-row-compact">
        <div class="form-group-compact" style="flex:0 0 160px;">
          <label>Procedencia</label>
          <select name="origin" id="sel_origin" class="form-select-compact" onchange="toggleProcOtro()">
            {origin_opts}
          </select>
        </div>
        <div class="form-group-compact" id="proc_otro_div" style="flex:1;display:none;">
          <label>Especifique</label>
          <input type="text" name="origin_text" class="form-input-compact" placeholder="Especifique procedencia">
        </div>
      </div>

      <!-- Nombre / Apellidos -->
      <div class="form-row-compact">
        <div class="form-group-compact" style="flex:1;">
          <label>Nombre *</label>
          <input type="text" name="first_name" class="form-input-compact" value="{pv('first_name')}" required placeholder="Nombres">
        </div>
      </div>
      <div class="form-row-compact">
        <div class="form-group-compact" style="flex:1;">
          <label>Apellidos *</label>
          <input type="text" name="last_name" class="form-input-compact" value="{pv('last_name')}" required placeholder="Apellidos">
        </div>
      </div>

      <!-- F. Nacimiento / Edad / Sexo -->
      <div class="form-row-compact">
        <div class="form-group-compact" style="flex:1;">
          <label>F. Nacimiento</label>
          <input type="date" id="birth_date_input" name="birth_date" class="form-input-compact" value="{pv('birth_date')}">
        </div>
        <div class="form-group-compact" style="flex:0 0 70px;">
          <label>Edad</label>
          <input type="number" id="age_years_input" name="age_years" class="form-input-compact"
                 value="{pv('age_years')}" min="0" max="150" placeholder="Auto">
        </div>
        <div class="form-group-compact" style="flex:0 0 110px;">
          <label>Sexo</label>
          <select name="sex" class="form-select-compact">{sex_opts}</select>
        </div>
      </div>

      <!-- HCL -->
      <div class="form-row-compact">
        <div class="form-group-compact" style="flex:1;">
          <label>HCL</label>
          <input type="text" name="hcl" class="form-input-compact" value="{pv('hcl')}">
        </div>
      </div>

      <!-- Talla / Peso / P.Art -->
      <div class="form-row-compact">
        <div class="form-group-compact" style="flex:1;">
          <label>Talla (cm)</label>
          <input type="text" name="height" class="form-input-compact" value="{pv('height')}" placeholder="cm">
        </div>
        <div class="form-group-compact" style="flex:1;">
          <label>Peso (kg)</label>
          <input type="text" name="weight" class="form-input-compact" value="{pv('weight')}" placeholder="kg">
        </div>
        <div class="form-group-compact" style="flex:1;">
          <label>P. Arterial</label>
          <input type="text" name="blood_pressure" class="form-input-compact"
                 value="{pv('blood_pressure')}" placeholder="120/80">
        </div>
      </div>

      <!-- Diagnóstico presuntivo -->
      <div class="form-row-compact">
        <div class="form-group-compact" style="flex:1;">
          <label>Diagnostico presuntivo</label>
          <input type="text" name="diagnosis" class="form-input-compact"
                 value="{pv('diagnosis')}" placeholder="Ej. Sindrome febril">
        </div>
      </div>

      <!-- Seguro / FUA -->
      <div class="form-row-compact">
        <div class="form-group-compact" style="flex:1;">
          <label>Tipo de seguro</label>
          <select name="insurance_type" class="form-select-compact">{insurance_opts}</select>
        </div>
        <div class="form-group-compact" style="flex:1;">
          <label>N FUA</label>
          <input type="text" name="fua_number" class="form-input-compact" value="{pv('fua_number')}">
        </div>
      </div>

      <!-- Observaciones -->
      <div class="form-row-compact" style="align-items:flex-end;">
        <div class="form-group-compact" style="flex:1;">
          <label>Observaciones</label>
          <input type="text" id="obs_input" name="observations" class="form-input-compact"
                 value="{pv('observations', 'N/A')}" placeholder="Observaciones">
        </div>
        <div style="padding-bottom:2px;">
          <button type="button" class="btn btn-secondary btn-sm"
                  onclick="document.getElementById('obs_input').value='N/A'">Sin obs.</button>
        </div>
      </div>

      <!-- Gestante -->
      <div class="form-row-compact" style="align-items:center;gap:12px;">
        <label style="display:flex;align-items:center;gap:5px;font-size:0.88rem;">
          <input type="checkbox" id="pregnant_check" name="is_pregnant" value="1" {pregnant_checked}>
          Gestante
        </label>
        <div id="gest-fields" style="display:{gest_display};display:flex;gap:8px;">
          <div class="form-group-compact" style="margin-bottom:0;">
            <label>Semanas</label>
            <input type="number" name="gestational_age_weeks" class="form-input-compact"
                   value="{pv('gestational_age_weeks')}" min="0" max="45" style="width:60px;">
          </div>
          <div class="form-group-compact" style="margin-bottom:0;">
            <label>FPP</label>
            <input type="date" name="expected_delivery_date" class="form-input-compact"
                   value="{pv('expected_delivery_date')}">
          </div>
        </div>
      </div>

      <!-- F. Muestra -->
      <div class="form-row-compact" style="align-items:center;">
        <div class="form-group-compact" style="flex:0 0 160px;">
          <label>F. muestra</label>
          <input type="date" id="sample_date_input" name="sample_date" class="form-input-compact" value="{today_str}">
        </div>
        <div style="padding-top:14px;">
          <label style="display:flex;align-items:center;gap:5px;font-size:0.88rem;">
            <input type="checkbox" id="hoy_check" checked onchange="toggleHoy()"> Hoy
          </label>
        </div>
      </div>

      <!-- Solicitante -->
      <div class="form-group-compact">
        <label>Solicitante</label>
        <input type="text" name="requested_by" class="form-input-compact"
               value="{pv('requested_by')}" list="requesters-list"
               placeholder="Seleccione o escriba el medico solicit...">
        <datalist id="requesters-list">{requesters_opts}</datalist>
      </div>

    </div><!-- end registro-form -->

    <!-- RIGHT: Test selector -->
    <div class="test-panel">
      <div class="test-panel-header">
        <span class="test-count-badge">Pruebas seleccionadas: <span id="test-count">0</span></span>
        <button type="button" class="btn btn-secondary btn-sm" onclick="borrarPruebas()">Borrar todas las pruebas</button>
      </div>
      <div class="test-panel-body" id="test-panel-body">
        {tests_html}
      </div>
    </div>

  </div><!-- end registro-grid -->

  <!-- Footer buttons -->
  <div class="module-footer-btns" style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border);">
    <button type="submit" name="_action" value="registro" class="btn btn-primary btn-full">Registrar paciente y pruebas</button>
    <button type="button" class="btn btn-secondary btn-full" onclick="limpiarFormulario()">Registrar nuevo paciente</button>
    <a href="/resultados" class="btn btn-secondary btn-full" style="text-align:center;">Anotar resultado de este paciente</a>
  </div>

</form>

<script>
// Count checked tests
function updateCount(){{
  var n = document.querySelectorAll('input[name="examenes"]:checked').length;
  document.getElementById('test-count').textContent = n;
}}
document.querySelectorAll('input[name="examenes"]').forEach(function(cb){{
  cb.addEventListener('change', updateCount);
}});
updateCount();

function borrarPruebas(){{
  document.querySelectorAll('input[name="examenes"]').forEach(function(cb){{ cb.checked=false; }});
  updateCount();
}}

function limpiarFormulario(){{
  document.getElementById('form-registro').reset();
  document.getElementById('test-count').textContent='0';
  document.getElementById('hid_doc_type').value='DNI';
  document.getElementById('hid_doc_number').value='';
}}

function buscarPaciente(){{
  var dt=document.getElementById('in_doc_type').value;
  var dn=document.getElementById('in_doc_number').value;
  if(!dn){{alert('Ingrese el numero de documento');return;}}
  var f=document.createElement('form');
  f.method='post';f.action='/registro/buscar';
  var i1=document.createElement('input');i1.type='hidden';i1.name='doc_type';i1.value=dt;
  var i2=document.createElement('input');i2.type='hidden';i2.name='doc_number';i2.value=dn;
  f.appendChild(i1);f.appendChild(i2);document.body.appendChild(f);f.submit();
}}

function verHistorial(){{
  var dn=document.getElementById('in_doc_number').value.trim();
  if(!dn){{alert('Ingrese el numero de documento para ver su historial');return;}}
  // Abre en una nueva pestaña para no perder el registro en curso
  window.open('/analisis?tab=historial&doc=' + encodeURIComponent(dn), '_blank');
}}

function toggleProcOtro(){{
  var v=document.getElementById('sel_origin').value;
  document.getElementById('proc_otro_div').style.display=(v==='Otro')?'flex':'none';
}}

document.getElementById('pregnant_check').addEventListener('change', function(){{
  document.getElementById('gest-fields').style.display=this.checked?'flex':'none';
}});

function calcAgeFromBirthDate(){{
  var inp=document.getElementById('birth_date_input');
  var bd=new Date(inp.value);
  if(isNaN(bd.getTime())) return;
  var age=Math.floor((new Date()-bd)/(365.25*24*3600*1000));
  document.getElementById('age_years_input').value=age;
}}
document.getElementById('birth_date_input').addEventListener('change', calcAgeFromBirthDate);
document.getElementById('birth_date_input').addEventListener('input', calcAgeFromBirthDate);
document.getElementById('birth_date_input').addEventListener('paste', function(e){{
  var self=this;
  setTimeout(function(){{
    // Normalize pasted date: try DD/MM/YYYY or DD-MM-YYYY -> YYYY-MM-DD
    var v=self.value.trim();
    var m=v.match(/^(\\d{{1,2}})[\\/-](\\d{{1,2}})[\\/-](\\d{{4}})$/);
    if(m) self.value=m[3]+'-'+m[2].padStart(2,'0')+'-'+m[1].padStart(2,'0');
    calcAgeFromBirthDate();
  }},50);
}});

function toggleHoy(){{
  var chk=document.getElementById('hoy_check');
  var inp=document.getElementById('sample_date_input');
  if(chk.checked){{
    var n=new Date();
    inp.value=n.getFullYear()+'-'+String(n.getMonth()+1).padStart(2,'0')+'-'+String(n.getDate()).padStart(2,'0');
  }}
  inp.disabled=chk.checked;
}}
toggleHoy();
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
    def _resultados_order_options(self, pending, selected_id=None):
        """Build <option> list for the pending orders dropdown."""
        _STATUS_TAGS = {
            "pendiente": "●",
            "parcial":   "◑",
            "completo":  "◉",
            "rechazado": "✕",
        }
        opts = '<option value="">— Seleccione una orden —</option>'
        for row in pending:
            oid, first_name, last_name, date, sample_date, doc_type, doc_number = row[:7]
            order_status = row[7] if len(row) > 7 else "pendiente"
            p_name = f"{first_name or ''} {last_name or ''}".strip() or "-"
            p_doc  = f"{doc_type or ''} {doc_number or ''}".strip() or "-"
            d_disp = _fmt_date(date)
            tag    = _STATUS_TAGS.get(order_status, "")
            label  = f"{tag} #{oid} — {p_name} ({p_doc}) [{d_disp}]"
            sel    = " selected" if oid == selected_id else ""
            opts  += f'<option value="{oid}"{sel} data-status="{order_status}">{html.escape(label)}</option>'
        return opts

    def _resultados_topbar_js(self):
        return """
<script>
function filterOrders() {
  var q = document.getElementById('order-search').value.toLowerCase();
  var sel = document.getElementById('order-select');
  sel.querySelectorAll('option').forEach(function(opt) {
    if (!opt.value) { opt.style.display = ''; return; }
    opt.style.display = opt.text.toLowerCase().includes(q) ? '' : 'none';
  });
}
function updateCargarBtn() {
  var v = document.getElementById('order-select').value;
  document.getElementById('btn-eliminar').style.display = v ? 'inline-flex' : 'none';
}
function cargarOrden() {
  var v = document.getElementById('order-select').value;
  if (v) window.location.href = '/resultados/' + v;
}
function eliminarOrden() {
  var v = document.getElementById('order-select').value;
  if (!v) return;
  if (!confirm('Eliminar la orden #' + v + '? Esta accion no se puede deshacer.')) return;
  fetch('/resultados/' + v + '/eliminar', {method:'POST'})
    .then(function(r){ window.location.href = r.ok ? '/resultados' : '/resultados?err=1'; });
}
</script>"""

    def _handle_resultados_list(self, message="", message_kind="success"):
        user = self._require_login()
        if not user:
            return
        params = _get_query_params(self.path)
        msg_param = params.get("msg", "") or params.get("err", "")
        if msg_param and not message:
            message = html.escape(msg_param)
            message_kind = "error" if params.get("err") else "success"
        order_id_str = params.get("order_id", "")
        if order_id_str and order_id_str.isdigit():
            return self._handle_resultados_form_get(int(order_id_str), message, message_kind)

        db = new_db()
        pending = db.get_pending_orders()
        options_html = self._resultados_order_options(pending)
        pending_count = len(pending)
        alert_html = _alert(message, message_kind) if message else ""

        content = f"""{alert_html}
<div class="module-layout">
  <div class="module-header">
    <div class="top-action-bar">
      <input type="text" id="order-search" class="form-input-compact"
             placeholder="Buscar nombre, doc, #..." style="width:210px" oninput="filterOrders()">
      <select id="order-select" class="order-select" onchange="updateCargarBtn()">
        {options_html}
      </select>
      <button class="btn btn-primary" onclick="cargarOrden()">Cargar</button>
      <span class="muted" style="font-size:0.85rem; white-space:nowrap">
        Pendientes: <strong>{pending_count}</strong>
      </span>
      <button id="btn-eliminar" class="btn btn-danger btn-sm" onclick="eliminarOrden()"
              style="display:none">Eliminar orden</button>
    </div>
  </div>
  <div class="module-body" style="display:flex; align-items:center; justify-content:center;">
    <div style="text-align:center; color:var(--muted);">
      <div style="font-size:3rem; margin-bottom:12px">📋</div>
      <p style="font-size:1.05rem">Seleccione una orden del listado para ingresar resultados</p>
      {'<p style="color:var(--success); font-weight:600">No hay ordenes pendientes</p>' if pending_count == 0 else ''}
    </div>
  </div>
</div>
{self._resultados_topbar_js()}"""
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
        date_disp = _fmt_date(ord_inf.get("date"))

        results = order_details.get("results", [])
        pending_fields = sum(1 for r in results if not r[1])

        # ── Estado actual de la orden ──
        status_row = db.cur.execute(
            "SELECT COALESCE(status,'pendiente'), emitted_at, COALESCE(rejected_reason,'') FROM orders WHERE id=?",
            (order_id,)
        ).fetchone()
        order_status   = status_row[0] if status_row else "pendiente"
        is_emitido     = (order_status == "emitido") or bool(status_row and status_row[1])
        rejected_reason = status_row[2] if status_row else ""

        pending = db.get_pending_orders()
        options_html = self._resultados_order_options(pending, selected_id=order_id)
        pending_count = len(pending)

        form_html = _build_result_form_html(order_id, order_details)
        alert_html = _alert(message, message_kind) if message else ""

        _STATUS_COLORS = {
            "pendiente": "badge-warning",
            "parcial":   "badge-info",
            "completo":  "badge-success",
            "emitido":   "badge-primary",
            "rechazado": "badge-danger",
        }
        status_badge_cls = _STATUS_COLORS.get(order_status, "badge-warning")
        status_badge = f'<span class="badge {status_badge_cls}">{order_status.upper()}</span>'

        pending_badge = (
            f'<span class="badge badge-warning">{pending_fields} sin resultado</span>'
            if pending_fields else
            '<span class="badge badge-success">Todos con resultado</span>'
        )

        content = f"""{alert_html}
<div class="module-layout">
  <div class="module-header">
    <div class="top-action-bar">
      <input type="text" id="order-search" class="form-input-compact"
             placeholder="Buscar nombre, doc, #..." style="width:210px" oninput="filterOrders()">
      <select id="order-select" class="order-select" onchange="updateCargarBtn()">
        {options_html}
      </select>
      <button class="btn btn-primary" onclick="cargarOrden()">Cargar</button>
      <span class="muted" style="font-size:0.85rem; white-space:nowrap">
        Pendientes: <strong>{pending_count}</strong>
      </span>
      <button id="btn-eliminar" class="btn btn-danger btn-sm" onclick="eliminarOrden()"
              style="display:inline-flex">Eliminar orden</button>
    </div>
    <div class="order-info-bar">
      <span><strong>Orden #{order_id}</strong></span>
      <span><strong>Paciente:</strong> {html.escape(patient_name)}</span>
      <span><strong>Doc:</strong> {html.escape(doc)}</span>
      <span><strong>Fecha:</strong> {html.escape(date_disp)}</span>
      {status_badge}
      {pending_badge}
    </div>
  </div>
  {'<div class="alert alert-danger" style="margin:0 0 0 0;border-radius:0;"><strong>MUESTRA RECHAZADA</strong> — ' + html.escape(rejected_reason) + '</div>' if order_status == 'rechazado' and rejected_reason else ''}
  {'<div class="alert alert-info" style="margin:0;border-radius:0;"><strong>Resultados ya emitidos.</strong> Solo lectura — no se puede modificar.</div>' if is_emitido else ''}
  <form id="result-form" method="post" action="/resultados/{order_id}"
        style="display:flex; flex-direction:column; flex:1; min-height:0; overflow:hidden;">
    <div class="module-body" style="padding-right:4px;">
      {form_html}
    </div>
    <div class="module-footer" style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
      {'<button type="button" class="btn btn-primary" onclick="handleFormSubmit()">Guardar Resultados</button>' if not is_emitido else ''}
      {'<button type="button" class="btn btn-danger btn-sm" onclick="showRejectModal()">Rechazar muestra</button>' if not is_emitido else ''}
      <a href="/resultados" class="btn btn-secondary">Cancelar</a>
      <a href="/emitir?order_id={order_id}" class="btn btn-secondary btn-sm" title="Ver esta orden en Emitir Resultados">Ver en Emitir →</a>
      <span style="flex:1"></span>
      <span id="draft-saved" style="font-size:0.8rem;color:var(--muted);display:none">Borrador guardado</span>
    </div>
  </form>
</div>

<!-- Modal: campos vacíos -->
<div id="modal-empty-fields" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:9000;align-items:center;justify-content:center;">
  <div style="background:#fff;border-radius:12px;padding:24px;max-width:500px;width:92%;box-shadow:0 8px 32px rgba(0,0,0,.25);">
    <h3 style="margin:0 0 10px;color:#333;font-size:1.1rem">Campos sin valor</h3>
    <p style="color:#555;margin:0 0 10px">Los siguientes campos están vacíos:</p>
    <ul id="empty-fields-list" style="max-height:180px;overflow-y:auto;color:#444;font-size:0.85rem;padding-left:20px;margin:0 0 14px;"></ul>
    <p style="color:#555;margin:0 0 18px">¿Desea guardar de todos modos?</p>
    <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button class="btn btn-secondary" onclick="document.getElementById('modal-empty-fields').style.display='none'">Cancelar</button>
      <button class="btn btn-primary" onclick="forceSubmit()">Sí, guardar</button>
    </div>
  </div>
</div>

<!-- Modal: rechazar muestra -->
<div id="modal-rechazar" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:9000;align-items:center;justify-content:center;">
  <div style="background:#fff;border-radius:12px;padding:24px;max-width:460px;width:92%;box-shadow:0 8px 32px rgba(0,0,0,.25);">
    <h3 style="margin:0 0 10px;color:#c0392b;font-size:1.1rem">Rechazar muestra</h3>
    <p style="color:#555;margin:0 0 10px">Ingrese el motivo de rechazo:</p>
    <input type="text" id="reject-reason-input" class="form-input" style="width:100%;box-sizing:border-box;margin-bottom:8px"
           placeholder="Ej: muestra hemolizada, volumen insuficiente, mal rotulada...">
    <p style="color:#888;font-size:0.8rem;margin:0 0 16px">Ejemplos: muestra coagulada · cantidad insuficiente · mal rotulada · hemolizada · contenedor roto</p>
    <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button class="btn btn-secondary" onclick="document.getElementById('modal-rechazar').style.display='none'">Cancelar</button>
      <button class="btn btn-danger" onclick="confirmReject()">Confirmar rechazo</button>
    </div>
  </div>
</div>

{self._resultados_topbar_js()}
<script>
var _formDirty = false;
var _isEmitido = {'true' if is_emitido else 'false'};
var _DRAFT_KEY = 'resultados_draft_{order_id}';

function markFormDirty() {{ if (!_isEmitido) {{ _formDirty = true; saveDraft(); }} }}
function saveDraft() {{
  var form = document.getElementById('result-form');
  if (!form) return;
  var fd = new FormData(form);
  var obj = {{}};
  fd.forEach(function(v,k){{ obj[k] = v; }});
  try {{ localStorage.setItem(_DRAFT_KEY, JSON.stringify(obj)); }} catch(e) {{}}
  var ds = document.getElementById('draft-saved');
  if (ds) {{ ds.style.display=''; setTimeout(function(){{ds.style.display='none';}},1500); }}
}}
function clearDraft() {{
  try {{ localStorage.removeItem(_DRAFT_KEY); }} catch(e) {{}}
  _formDirty = false;
}}
function restoreDraft() {{
  if (_isEmitido) return;
  var raw;
  try {{ raw = localStorage.getItem(_DRAFT_KEY); }} catch(e) {{ return; }}
  if (!raw) return;
  var obj;
  try {{ obj = JSON.parse(raw); }} catch(e) {{ return; }}
  var form = document.getElementById('result-form');
  if (!form) return;
  Object.keys(obj).forEach(function(k) {{
    var els = form.querySelectorAll('[name="'+k+'"]');
    els.forEach(function(el) {{
      if (el.type === 'radio') {{ if (el.value === obj[k]) el.checked = true; }}
      else if (el.type === 'hidden') {{ el.value = obj[k]; }}
      else {{ el.value = obj[k]; }}
    }});
  }});
  form.querySelectorAll('.dipstick-opts').forEach(function(cont) {{
    var inp = cont.querySelector('input[type=hidden]');
    if (!inp) return;
    var val = inp.value;
    cont.querySelectorAll('.dip-btn').forEach(function(b) {{
      b.classList.toggle('dip-active', b.dataset.val === val);
    }});
  }});
}}

/* ── Submit con verificación de campos vacíos ── */
function handleFormSubmit() {{
  if (_isEmitido) return;
  var form = document.getElementById('result-form');
  var emptyLabels = [];
  form.querySelectorAll('.test-fieldset').forEach(function(block) {{
    var statusSel = block.querySelector('[name$="_sample_status"]');
    if (statusSel && statusSel.value === 'pendiente') return;
    block.querySelectorAll('.rg-row').forEach(function(row) {{
      if (row.classList.contains('rg-bool-row')) {{
        if (!row.querySelector('input[type=radio]:checked')) {{
          var lbl = row.querySelector('.rg-label');
          if (lbl) emptyLabels.push(lbl.textContent.replace(/\\(.*\\)/g,'').trim());
        }}
        return;
      }}
      var inp = row.querySelector('.rg-input');
      if (inp && !inp.value.trim()) {{
        var lbl = row.querySelector('.rg-label');
        if (lbl) emptyLabels.push(lbl.textContent.replace(/\\(.*\\)/g,'').trim());
      }}
    }});
    block.querySelectorAll('.rg-textarea').forEach(function(ta) {{
      if (!ta.value.trim()) {{
        var pr = ta.closest('.rg-textarea-row');
        var lbl = pr ? pr.querySelector('.rg-label') : null;
        if (lbl) emptyLabels.push(lbl.textContent.replace(/\\(.*\\)/g,'').trim());
      }}
    }});
  }});
  if (emptyLabels.length === 0) {{
    clearDraft();
    form.submit();
    return;
  }}
  var ul = document.getElementById('empty-fields-list');
  ul.innerHTML = emptyLabels.slice(0,30).map(function(f){{
    return '<li>' + f.replace(/[<>&"]/g,'') + '</li>';
  }}).join('');
  if (emptyLabels.length > 30) ul.innerHTML += '<li>... y ' + (emptyLabels.length-30) + ' más</li>';
  document.getElementById('modal-empty-fields').style.display = 'flex';
}}

function forceSubmit() {{
  document.getElementById('modal-empty-fields').style.display = 'none';
  clearDraft();
  document.getElementById('result-form').submit();
}}

/* ── Rechazar muestra ── */
function showRejectModal() {{
  document.getElementById('modal-rechazar').style.display = 'flex';
  setTimeout(function(){{ document.getElementById('reject-reason-input').focus(); }}, 100);
}}
function confirmReject() {{
  var reason = (document.getElementById('reject-reason-input').value || '').trim();
  if (!reason) {{ alert('Debe ingresar el motivo de rechazo.'); return; }}
  fetch('/resultados/{order_id}/rechazar', {{
    method: 'POST',
    headers: {{'Content-Type':'application/x-www-form-urlencoded'}},
    body: 'reason=' + encodeURIComponent(reason)
  }}).then(function(r) {{
    if (r.ok) {{ window.location.href = '/resultados/{order_id}'; }}
    else {{ alert('Error al rechazar la orden.'); }}
  }});
}}

/* ── Readonly si emitido ── */
if (_isEmitido) {{
  document.querySelectorAll('#result-form input, #result-form textarea, #result-form select').forEach(function(el) {{
    el.disabled = true;
  }});
}}

window.addEventListener('DOMContentLoaded', restoreDraft);
document.addEventListener('change', function(e) {{
  if (e.target.closest('#result-form')) markFormDirty();
}});
window.addEventListener('beforeunload', function(e) {{
  if (_formDirty) {{ e.preventDefault(); e.returnValue = ''; }}
}});
</script>"""
        self._respond_html(_base_layout(content, "resultados", user))

    def _handle_resultados_eliminar(self, order_id: int):
        user = self._require_login()
        if not user:
            return
        db = new_db()
        try:
            db.cur.execute(
                "UPDATE orders SET deleted=1, deleted_reason='eliminado desde web' WHERE id=?",
                (order_id,)
            )
            db.conn.commit()
            self.send_response(200)
            self.end_headers()
        except Exception as e:
            self.send_error(500, str(e))

    def _handle_resultados_rechazar(self, order_id: int):
        """POST /resultados/{id}/rechazar — marca la orden como rechazada."""
        user = self._require_login()
        if not user:
            return
        multi_data = _parse_form_multi(self)
        data = {k: (v[0] if v else "") for k, v in multi_data.items()}
        reason = data.get("reason", "").strip()
        if not reason:
            self.send_error(400, "Motivo de rechazo requerido")
            return
        db = new_db()
        try:
            db.reject_order(order_id, reason)
            print(f"[RECHAZAR] orden={order_id} motivo={reason!r}")
            self.send_response(200)
            self.end_headers()
        except Exception as e:
            self.send_error(500, str(e))

    def _handle_resultados_save(self, order_id: int):
        user = self._require_login()
        if not user:
            return
        multi_data = _parse_form_multi(self)
        data = {k: (v[0] if v else "") for k, v in multi_data.items()}

        total_tests = int(data.get("total_tests", 0))
        print(f"[SAVE] orden={order_id} total_tests={total_tests} "
              f"campos={[k for k in data if k.startswith('test_')][:8]}")

        results_dict = _parse_results_from_form(data, multi_data, total_tests)
        print(f"[SAVE] tests parseados={list(results_dict.keys())}")

        if not results_dict:
            print(f"[SAVE] WARN: results_dict vacío para orden {order_id}")
            return self._handle_resultados_form_get(
                order_id, message="No se recibieron datos del formulario.", message_kind="error"
            )

        db = new_db()
        try:
            order_status = db.save_results(order_id, results_dict)
            print(f"[SAVE] OK orden={order_id} status={order_status}")
        except Exception as e:
            print(f"[SAVE] ERROR orden={order_id}: {e}")
            return self._handle_resultados_form_get(
                order_id, message=f"Error al guardar: {e}", message_kind="error"
            )

        _msgs = {
            "completo":  ("Resultados completos. Orden lista para emitir.", "success"),
            "parcial":   ("Resultados guardados. La orden tiene pruebas pendientes.", "info"),
            "pendiente": ("Datos guardados. Complete los resultados.", "info"),
            "emitido":   ("Esta orden ya fue emitida.", "warning"),
            "rechazado": ("Orden marcada como rechazada.", "warning"),
        }
        msg, kind = _msgs.get(order_status, ("Guardado.", "success"))

        # Redirect to emitir pre-selecting the order so user can verify and print
        if order_status in ("completo", "parcial", "rechazado"):
            self._redirect(f"/emitir?order_id={order_id}&msg={msg.replace(' ', '+')}")
        else:
            return self._handle_resultados_form_get(
                order_id, message=msg, message_kind=kind
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
        selected_order_id_str = params.get("order_id", "")
        selected_order_id = int(selected_order_id_str) if selected_order_id_str.isdigit() else None

        db = new_db()
        orders = db.get_completed_orders(include_emitted=include_emitted)

        _STATUS_ICON = {"completo": "✓", "parcial": "◑", "rechazado": "✕", "emitido": "✓✓"}
        _STATUS_BADGE = {
            "completo":  ("badge-success", "COMPLETO"),
            "parcial":   ("badge-info",    "PARCIAL"),
            "rechazado": ("badge-danger",  "RECHAZADO"),
            "emitido":   ("badge-primary", "EMITIDO"),
            "pendiente": ("badge-warning", "PENDIENTE"),
        }

        # Build checkbox table rows
        table_rows = ""
        for row in orders:
            (oid, first_name, last_name, date, sample_date,
             doc_type, doc_number, emitted, emitted_at, status) = row
            p_name = f"{first_name or ''} {last_name or ''}".strip() or "-"
            p_doc  = f"{doc_type or ''} {doc_number or ''}".strip() or "-"
            d_disp = _fmt_date(date)
            icon   = _STATUS_ICON.get(status, "")
            bcls, blbl = _STATUS_BADGE.get(status, ("badge-warning", status.upper()))
            checked = " checked" if (oid == selected_order_id and not emitted) else ""
            disabled = " disabled" if emitted else ""
            row_cls = " emitir-row-emitido" if emitted else ""
            sel_cls = " emitir-row-selected" if oid == selected_order_id else ""
            search_data = f"{oid} {p_name} {p_doc} {d_disp}".lower()
            table_rows += f"""
<tr class="emitir-row{row_cls}{sel_cls}" data-oid="{oid}" data-search="{html.escape(search_data)}"
    onclick="selectRow(this,{oid})">
  <td onclick="event.stopPropagation()" style="width:32px;text-align:center;">
    <input type="checkbox" name="order_ids" value="{oid}"{checked}{disabled}
           onchange="updateBatchBtn()">
  </td>
  <td style="font-weight:600;width:44px">#{oid}</td>
  <td>{html.escape(p_name)}</td>
  <td class="muted" style="font-size:0.82rem">{html.escape(p_doc)}</td>
  <td class="muted" style="font-size:0.82rem;white-space:nowrap">{d_disp}</td>
  <td><span class="badge {bcls}" style="font-size:0.72rem">{icon} {blbl}</span></td>
</tr>"""

        orders_count = len(orders)
        non_emitted_count = sum(1 for r in orders if not r[7])  # r[7] = emitted flag
        toggle_label = "Ocultar emitidos" if include_emitted else "Mostrar emitidos"
        toggle_url   = "/emitir" if include_emitted else "/emitir?include_emitted=1"
        alert_html   = _alert(html.escape(message)) if message else ""

        # Preview panel for selected order
        preview_html = ""
        preview_header = ""
        preview_footer = ""
        order_details = None
        if selected_order_id:
            order_details = db.get_order_details(selected_order_id)
            if order_details:
                pat = order_details["patient"]
                ord_inf = order_details["order"]
                p_name = pat.get("name") or f"{pat.get('first_name','')} {pat.get('last_name','')}".strip()
                p_doc  = f"{pat.get('doc_type','')} {pat.get('doc_number','')}".strip()
                d_disp = _fmt_date(ord_inf.get("date"))
                ord_status = ord_inf.get("status", "pendiente")
                bcls, blbl = _STATUS_BADGE.get(ord_status, ("badge-warning", ord_status.upper()))
                rejected_reason = ord_inf.get("rejected_reason", "")
                emitted_disp = ord_inf.get("emitted_at") or ""
                _sel_emitted = bool(ord_inf.get("emitted_at") or ord_inf.get("emitted"))
                rej_banner = ""
                if ord_status == "rechazado" and rejected_reason:
                    rej_banner = (f'<div class="alert alert-danger" style="margin:4px 0;padding:4px 8px;">'
                                  f'<strong>MUESTRA RECHAZADA</strong> — {html.escape(rejected_reason)}</div>')
                preview_header = f"""
{rej_banner}
<div class="order-info-bar" style="margin:0;border-radius:0;border-top:1px solid var(--border)">
  <span><strong>#{selected_order_id}</strong> {html.escape(p_name)}</span>
  <span class="muted">{html.escape(p_doc)}</span>
  <span class="muted">{d_disp}</span>
  <span class="badge {bcls}">{blbl}</span>
  {'<span class="muted" style="font-size:0.78rem">' + html.escape(_fmt_date(emitted_disp) + (" " + str(emitted_disp)[11:16] if len(str(emitted_disp)) > 10 else "")) + '</span>' if emitted_disp else ''}
</div>"""
                results = order_details.get("results", [])
                if results:
                    trows = ""
                    for r in results:
                        t_name = r[0]; raw = r[1] or ""; ss = r[3] or "recibida"; obs = r[5] or ""
                        disp_val = "—"
                        if raw:
                            disp_val = raw
                            try:
                                d = json.loads(raw)
                                if isinstance(d, dict) and d.get("type") == "structured":
                                    disp_val = "; ".join(f"{k}: {v}" for k, v in d.get("values", {}).items() if v not in ("", None)) or "—"
                                elif isinstance(d, dict):
                                    disp_val = d.get("value", raw)
                            except Exception:
                                pass
                        st_tag = ""
                        if ss not in ("recibida", ""):
                            st_tag = f' <span class="muted">({"sin muestra" if ss=="pendiente" else ss})</span>'
                        obs_tag = f' <em class="muted">Obs: {html.escape(obs)}</em>' if obs else ""
                        trows += (f"<tr><td style='font-size:0.82rem'>{html.escape(t_name)}</td>"
                                  f"<td style='font-size:0.82rem'>{html.escape(str(disp_val))}{st_tag}{obs_tag}</td></tr>")
                    preview_html = f"""<div style="overflow-y:auto;flex:1;min-height:0">
  <table class="data-table" style="font-size:0.82rem">
    <thead><tr><th>Examen</th><th>Resultado</th></tr></thead>
    <tbody>{trows}</tbody>
  </table></div>"""
                else:
                    preview_html = '<p class="muted text-center" style="padding:20px">Sin resultados registrados.</p>'

                _edit_btn = "" if _sel_emitted else (
                    f'<a href="/resultados/{selected_order_id}" class="btn btn-secondary btn-sm">'
                    f'✏ Editar</a> ')
                preview_footer = f"""
<div style="display:flex;gap:8px;align-items:center;padding:8px 12px;
            border-top:1px solid var(--border);flex-shrink:0">
  {_edit_btn}<a href="/emitir/{selected_order_id}/pdf" class="btn btn-primary btn-sm"
    target="_blank">Emitir PDF individual</a>
  <form method="post" action="/emitir/{selected_order_id}/marcar" style="display:inline;">
    <button type="submit" class="btn btn-secondary btn-sm">Marcar emitido</button>
  </form>
</div>"""

        if not preview_html:
            preview_html = """<div style="display:flex;align-items:center;justify-content:center;
  flex:1;color:var(--muted);flex-direction:column;gap:8px;padding:20px">
  <div style="font-size:2.5rem">📄</div>
  <p style="font-size:0.95rem">Haz clic en una fila para ver el detalle</p>
</div>"""

        content = f"""{alert_html}
<form id="batch-form" method="post" action="/emitir/batch">
<div class="module-layout" style="overflow:hidden">
  <div class="module-header">
    <div class="top-action-bar">
      <input type="text" id="emitir-search" class="form-input-compact"
             placeholder="Buscar nombre, doc, #..." style="width:200px" oninput="filterEmitir()">
      <button type="button" class="btn btn-secondary btn-sm" onclick="selectAll(true)">Seleccionar todos</button>
      <button type="button" class="btn btn-secondary btn-sm" onclick="selectAll(false)">Limpiar</button>
      <span class="muted" style="font-size:0.85rem">
        Lista: <strong>{orders_count}</strong>
        &nbsp;·&nbsp; ✓ completo &nbsp; ◑ parcial &nbsp; ✕ rechazado
      </span>
      <a href="{toggle_url}" class="btn btn-secondary btn-sm">{toggle_label}</a>
      <a href="/emitir/exportar_csv" class="btn btn-secondary btn-sm">Exportar CSV</a>
    </div>
  </div>
  <div class="module-body" style="display:flex;gap:0;padding:0;overflow:hidden">
    <!-- LEFT: checklist -->
    <div style="flex:1;min-width:0;overflow-y:auto;border-right:1px solid var(--border)">
      <table class="data-table emitir-checklist" style="font-size:0.83rem">
        <thead>
          <tr>
            <th style="width:32px;text-align:center">
              <input type="checkbox" id="chk-all" title="Seleccionar todos"
                     onchange="selectAll(this.checked)">
            </th>
            <th>#</th><th>Paciente</th><th>Doc</th><th>Fecha</th><th>Estado</th>
          </tr>
        </thead>
        <tbody id="emitir-tbody">
          {table_rows}
        </tbody>
      </table>
    </div>
    <!-- RIGHT: preview -->
    <div id="emitir-preview" style="width:380px;flex-shrink:0;display:flex;
         flex-direction:column;min-height:0;background:var(--surface)">
      {preview_header}
      {preview_html}
      {preview_footer}
    </div>
  </div>
  <div class="module-footer" style="display:flex;gap:10px;align-items:center">
    <button type="submit" id="btn-batch" class="btn btn-primary" disabled
            onclick="return confirmBatch()">
      Emitir seleccionados (<span id="sel-count">0</span>)
    </button>
    <span class="muted" style="font-size:0.82rem" id="batch-hint">
      Marca las órdenes de la lista y haz clic aquí para generar un PDF combinado
    </span>
    <span style="flex:1"></span>
    <span class="muted" style="font-size:0.82rem">
      Pendientes sin emitir: <strong>{non_emitted_count}</strong>
    </span>
  </div>
</div>
</form>
<script>
function updateBatchBtn() {{
  var n = document.querySelectorAll('#emitir-tbody input[type=checkbox]:checked').length;
  document.getElementById('sel-count').textContent = n;
  document.getElementById('btn-batch').disabled = (n === 0);
  document.getElementById('batch-hint').textContent =
    n > 0 ? 'Se generará un PDF con ' + n + ' informe(s)' :
             'Marca las órdenes de la lista y haz clic aquí para generar un PDF combinado';
  // sync header checkbox
  var total = document.querySelectorAll('#emitir-tbody input[type=checkbox]:not(:disabled)').length;
  var hdr = document.getElementById('chk-all');
  hdr.checked = (n > 0 && n === total);
  hdr.indeterminate = (n > 0 && n < total);
}}
function selectAll(val) {{
  document.querySelectorAll('#emitir-tbody input[type=checkbox]:not(:disabled)')
    .forEach(function(cb) {{ cb.checked = val; }});
  updateBatchBtn();
}}
function selectRow(tr, oid) {{
  // Navigate to show preview without losing checkbox state
  // We POST-redirect via GET with order_id param
  var url = '/emitir?order_id=' + oid;
  var ie = new URLSearchParams(window.location.search).get('include_emitted');
  if (ie) url += '&include_emitted=' + ie;
  // Preserve currently checked boxes in session storage
  var checked = [];
  document.querySelectorAll('#emitir-tbody input[type=checkbox]:checked')
    .forEach(function(cb) {{ checked.push(cb.value); }});
  sessionStorage.setItem('emitir_checked', JSON.stringify(checked));
  window.location.href = url;
}}
function filterEmitir() {{
  var q = document.getElementById('emitir-search').value.toLowerCase();
  document.querySelectorAll('#emitir-tbody tr').forEach(function(tr) {{
    var s = (tr.dataset.search || '');
    tr.style.display = s.includes(q) ? '' : 'none';
  }});
}}
function confirmBatch() {{
  var n = document.querySelectorAll('#emitir-tbody input[type=checkbox]:checked').length;
  if (n === 0) return false;
  return confirm('Se emitirán ' + n + ' informe(s) en un solo PDF y quedarán marcados como emitidos. ¿Continuar?');
}}
// Restore checked state from sessionStorage after row-click navigation
(function() {{
  var saved = sessionStorage.getItem('emitir_checked');
  if (saved) {{
    try {{
      var ids = JSON.parse(saved);
      ids.forEach(function(id) {{
        var cb = document.querySelector('#emitir-tbody input[value="' + id + '"]');
        if (cb && !cb.disabled) cb.checked = true;
      }});
    }} catch(e) {{}}
    sessionStorage.removeItem('emitir_checked');
  }}
  updateBatchBtn();
}})();
</script>"""
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

    def _handle_emitir_batch(self):
        """POST /emitir/batch — genera PDF combinado para múltiples órdenes seleccionadas."""
        user = self._require_login()
        if not user:
            return
        multi_data = _parse_form_multi(self)
        order_ids_raw = multi_data.get("order_ids", [])
        order_ids = []
        for x in order_ids_raw:
            x = x.strip()
            if x.isdigit():
                order_ids.append(int(x))

        if not order_ids:
            return self._redirect("/emitir?msg=No+se+seleccionaron+ordenes")

        db = new_db()
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        orders_details = []
        for oid in order_ids:
            details = db.get_order_details(oid)
            if details:
                orders_details.append((oid, details))

        if not orders_details:
            return self._redirect("/emitir?msg=No+se+encontraron+ordenes+validas")

        try:
            pdf_bytes = generate_batch_pdf(
                [d for _, d in orders_details], emitted_at=now_str
            )
        except Exception as e:
            print(f"[BATCH PDF] ERROR: {e}")
            content = _alert(f"Error al generar PDF lote: {html.escape(str(e))}", "error")
            return self._respond_html(_base_layout(content, "emitir", user))

        # Mark as emitted only those not already emitted
        marked = 0
        for oid, details in orders_details:
            if not details.get("order", {}).get("emitted"):
                try:
                    db.mark_order_emitted(oid, now_str)
                    marked += 1
                except Exception:
                    pass

        print(f"[BATCH PDF] {len(orders_details)} ordenes, {marked} marcadas como emitidas")
        date_tag = now_str[:10]
        self._respond_pdf(pdf_bytes, f"lote_{date_tag}_{len(orders_details)}ordenes.pdf")

    def _handle_emitir_exportar_csv(self):
        import csv, io
        user = self._require_login()
        if not user:
            return
        params = _get_query_params(self.path)
        desde = params.get("desde", "")
        hasta = params.get("hasta", "")
        today = datetime.date.today().isoformat()
        start_dt = (desde + " 00:00:00") if desde else (today + " 00:00:00")
        end_dt   = (hasta + " 23:59:59") if hasta else (today + " 23:59:59")
        db = new_db()
        rows = db.get_results_in_range(start_dt, end_dt)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Orden#", "Fecha", "F.Muestra", "Apellidos", "Nombres",
                         "Doc", "Sexo", "Edad(años)", "Examen", "Categoria", "Resultado"])
        for r in rows:
            (ot_id, o_id, o_date, o_sample, p_first, p_last, p_doc_type, p_doc_num,
             p_sex, p_birth, p_hcl, p_origin, p_preg, p_gest_wk, p_edd,
             o_age, o_obs, o_ins, o_fua,
             t_name, t_cat, ot_result, ot_ss, ot_si, ot_obs) = r
            disp_result = ot_result or ""
            try:
                import json as _json
                d = _json.loads(ot_result)
                if isinstance(d, dict) and d.get("type") == "structured":
                    disp_result = "; ".join(
                        f"{k}: {v}" for k, v in d.get("values", {}).items() if v not in ("", None)
                    )
                elif isinstance(d, dict):
                    disp_result = str(d.get("value", ot_result) or "")
            except Exception:
                pass
            writer.writerow([
                o_id, _fmt_date(o_date), _fmt_date(o_sample),
                p_last or "", p_first or "",
                f"{p_doc_type or ''} {p_doc_num or ''}".strip(),
                p_sex or "", o_age or "",
                t_name or "", t_cat or "", disp_result
            ])
        csv_bytes = buf.getvalue().encode("utf-8-sig")
        filename = f"resultados_{today}.csv"
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8-sig")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(csv_bytes)))
        self.end_headers()
        self.wfile.write(csv_bytes)

    # ===========================================================
    # MÓDULO ANÁLISIS — 3 tabs
    # ===========================================================
    def _handle_analisis(self):
        user = self._require_login()
        if not user:
            return
        params  = _get_query_params(self.path)
        tab     = params.get("tab", "estadisticas")
        today   = datetime.date.today().isoformat()
        first_m = datetime.date.today().replace(day=1).isoformat()

        db = new_db()

        # ── Tab links ──────────────────────────────────────────
        def tab_link(name, label):
            cls = "tab-link active" if tab == name else "tab-link"
            return f'<a href="/analisis?tab={name}" class="{cls}">{label}</a>'

        tabs_bar = f"""
<div class="tabs">
  {tab_link("estadisticas", "Estadisticas")}
  {tab_link("pruebas", "Registro de pruebas")}
  {tab_link("historial", "Historial de pacientes")}
</div>"""

        # ── TAB 1: Estadísticas ────────────────────────────────
        if tab == "estadisticas":
            modo  = params.get("modo", "mes")
            mes   = params.get("mes",  str(datetime.date.today().month))
            anio  = params.get("anio", str(datetime.date.today().year))
            desde = params.get("desde", "")
            hasta = params.get("hasta", "")

            start_dt = end_dt = None
            if modo == "rango" and (desde or hasta):
                start_dt = (desde + " 00:00:00") if desde else None
                end_dt   = (hasta + " 23:59:59") if hasta else None
            elif modo == "mes":
                try:
                    import calendar
                    y, m = int(anio), int(mes)
                    last_day = calendar.monthrange(y, m)[1]
                    start_dt = f"{y:04d}-{m:02d}-01 00:00:00"
                    end_dt   = f"{y:04d}-{m:02d}-{last_day:02d} 23:59:59"
                except Exception:
                    pass

            error_msg = ""
            stats = None
            try:
                stats = db.get_statistics(start_datetime=start_dt, end_datetime=end_dt)
            except Exception as e:
                error_msg = str(e)

            # Summary cards
            summary_html = ""
            if stats:
                periodo_label = ""
                if modo == "mes":
                    MESES = ["","Enero","Febrero","Marzo","Abril","Mayo","Junio",
                             "Julio","Agosto","Septiembre","Octubre","Noviembre","Diciembre"]
                    try: periodo_label = f"{MESES[int(mes)]} {anio}"
                    except Exception: periodo_label = f"{mes}/{anio}"
                elif desde or hasta:
                    periodo_label = f"{desde} — {hasta}"
                else:
                    periodo_label = "Todo el tiempo"
                summary_html = f"""
<div style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:14px; align-items:center;">
  <div class="metric-card" style="min-width:120px; padding:10px 16px;">
    <div class="metric-label">Periodo</div>
    <div class="metric-value" style="font-size:1rem">{html.escape(periodo_label)}</div>
  </div>
  <div class="metric-card" style="min-width:100px; padding:10px 16px;">
    <div class="metric-label">Pacientes</div>
    <div class="metric-value">{stats.get('total_patients',0)}</div>
  </div>
  <div class="metric-card" style="min-width:100px; padding:10px 16px;">
    <div class="metric-label">Ordenes</div>
    <div class="metric-value">{stats.get('total_orders',0)}</div>
  </div>
  <div class="metric-card" style="min-width:100px; padding:10px 16px;">
    <div class="metric-label">Pruebas</div>
    <div class="metric-value">{stats.get('total_tests_conducted',0)}</div>
  </div>
</div>"""

            # Detailed table with area rows + per-test sub-rows
            detail_table_html = ""
            if stats:
                detail = stats.get("by_category_detail", {})
                ordered_cats = [c for c in CATEGORY_DISPLAY_ORDER if c in detail]
                ordered_cats += [c for c in detail if c not in CATEGORY_DISPLAY_ORDER]
                rows_html = ""
                for cat in ordered_cats:
                    info = detail[cat]
                    rows_html += f"""
<tr class="stats-area-row">
  <td>{html.escape(cat)}</td>
  <td class="text-center">{info['total']}</td>
</tr>"""
                    for t_name, t_count in info.get("tests", []):
                        rows_html += f"""
<tr class="stats-test-row">
  <td style="padding-left:28px; color:var(--muted);">{html.escape(t_name)}</td>
  <td class="text-center">{t_count}</td>
</tr>"""
                detail_table_html = f"""
<div class="table-wrapper" style="max-height:100%; overflow-y:auto;">
  <table class="data-table">
    <thead><tr><th>Area / Examen</th><th style="width:100px; text-align:center;">Cantidad</th></tr></thead>
    <tbody>{rows_html or '<tr><td colspan="2" class="text-center muted">Sin datos</td></tr>'}</tbody>
  </table>
</div>"""

            # Filter form
            mes_options = "".join(
                f'<option value="{i}" {"selected" if str(i)==mes else ""}>'
                f'{"Ene Feb Mar Abr May Jun Jul Ago Sep Oct Nov Dic".split()[i-1]}</option>'
                for i in range(1, 13)
            )
            filter_form = f"""
<form method="get" action="/analisis" style="display:flex; flex-wrap:wrap; gap:8px; align-items:flex-end; margin-bottom:10px;">
  <input type="hidden" name="tab" value="estadisticas">
  <div>
    <label class="field-label">Modo</label>
    <select name="modo" class="form-select-compact" onchange="this.form.submit()">
      <option value="mes" {"selected" if modo=="mes" else ""}>Por mes</option>
      <option value="rango" {"selected" if modo=="rango" else ""}>Por rango</option>
      <option value="todo" {"selected" if modo=="todo" else ""}>Todo</option>
    </select>
  </div>
  {"" if modo != "mes" else f'''
  <div><label class="field-label">Mes</label>
    <select name="mes" class="form-select-compact">{mes_options}</select></div>
  <div><label class="field-label">Año</label>
    <input type="number" name="anio" class="form-input-compact" value="{html.escape(anio)}" style="width:72px"></div>'''}
  {"" if modo != "rango" else f'''
  <div><label class="field-label">Desde</label>
    <input type="date" name="desde" class="form-input-compact" value="{html.escape(desde)}"></div>
  <div><label class="field-label">Hasta</label>
    <input type="date" name="hasta" class="form-input-compact" value="{html.escape(hasta)}"></div>'''}
  <button type="submit" class="btn btn-primary btn-sm">Consultar</button>
</form>"""

            alert_html = _alert(error_msg, "error") if error_msg else ""
            tab_content = f"""{alert_html}{filter_form}{summary_html}{detail_table_html}"""

        # ── TAB 2: Registro de pruebas ─────────────────────────
        elif tab == "pruebas":
            desde = params.get("desde", first_m)
            hasta = params.get("hasta", today)
            rows_data = []
            error_msg = ""
            if desde or hasta:
                try:
                    start_dt = (desde + " 00:00:00") if desde else None
                    end_dt   = (hasta + " 23:59:59") if hasta else None
                    rows_data = db.get_results_in_range(start_dt, end_dt)
                except Exception as e:
                    error_msg = str(e)

            trows = ""
            for r in rows_data:
                # columns: ot.id, o.id, o.date, o.sample_date, p.first_name, p.last_name,
                #          p.doc_type, p.doc_number, p.sex, [6 patient cols], [4 order cols],
                #          t.name(19), t.category(20), ot.result(21), ss, si, obs
                o_date     = r[2]
                p_first    = r[4]
                p_last     = r[5]
                p_doc_type = r[6]
                p_doc_num  = r[7]
                t_name     = r[19]
                ot_result  = r[21]
                disp = ot_result or "—"
                try:
                    import json as _json
                    d = _json.loads(ot_result)
                    if isinstance(d, dict) and d.get("type") == "structured":
                        disp = "; ".join(
                            f"{k}: {v}" for k, v in d.get("values", {}).items()
                            if v not in ("", None)
                        ) or "—"
                    elif isinstance(d, dict):
                        disp = str(d.get("value", ot_result) or "—")
                except Exception:
                    pass
                p_name = f"{p_last or ''} {p_first or ''}".strip() or "—"
                p_doc  = f"{p_doc_type or ''} {p_doc_num or ''}".strip()
                trows += f"""<tr>
  <td>{_fmt_date(o_date)}</td>
  <td>{html.escape(p_name)}</td>
  <td>{html.escape(p_doc)}</td>
  <td>{html.escape(t_name or "")}</td>
  <td style="max-width:280px; word-break:break-word;">{html.escape(str(disp))}</td>
</tr>"""

            table_html = f"""
<div class="table-wrapper" style="max-height:100%; overflow-y:auto;">
  <table class="data-table">
    <thead><tr><th>Fecha</th><th>Paciente</th><th>Documento</th><th>Examen</th><th>Resultado</th></tr></thead>
    <tbody>{trows or '<tr><td colspan="5" class="text-center muted">Sin datos en el rango seleccionado</td></tr>'}</tbody>
  </table>
</div>"""
            n_rows = len(rows_data)
            alert_html = _alert(error_msg, "error") if error_msg else ""
            tab_content = f"""{alert_html}
<form method="get" action="/analisis" style="display:flex; gap:8px; align-items:flex-end; margin-bottom:10px; flex-wrap:wrap;">
  <input type="hidden" name="tab" value="pruebas">
  <div><label class="field-label">Desde</label>
    <input type="date" name="desde" class="form-input-compact" value="{html.escape(desde)}"></div>
  <div><label class="field-label">Hasta</label>
    <input type="date" name="hasta" class="form-input-compact" value="{html.escape(hasta)}"></div>
  <button type="submit" class="btn btn-primary btn-sm">Consultar</button>
  <a href="/analisis/registro_pdf?desde={html.escape(desde)}&hasta={html.escape(hasta)}"
     class="btn btn-secondary btn-sm" target="_blank">Exportar PDF</a>
  <a href="/emitir/exportar_csv?desde={html.escape(desde)}&hasta={html.escape(hasta)}"
     class="btn btn-secondary btn-sm">Exportar CSV</a>
  <span class="muted" style="font-size:0.82rem;">{n_rows} resultado(s)</span>
</form>
{table_html}"""

        # ── TAB 3: Historial de pacientes ──────────────────────
        else:
            tab = "historial"
            doc_q      = params.get("doc", "").strip()
            apellido_q = params.get("apellido", "").strip()
            sel_order  = params.get("order_id", "")

            history_rows = []
            error_msg    = ""
            if doc_q or apellido_q:
                try:
                    history_rows = db.get_patient_history(
                        doc_number=doc_q or None,
                        last_name=apellido_q or None
                    )
                except Exception as e:
                    error_msg = str(e)

            # Group by order_id — each order stores its own patient snapshot
            # (pueden haber varios pacientes distintos con el mismo apellido)
            orders_map = {}   # {order_id: {info, tests, patient}}
            first_patient_info = {}
            for r in history_rows:
                (o_id, o_date, o_sample, t_id, t_name, ot_result, t_cat,
                 p_first, p_last, p_doc_type, p_doc_num,
                 p_sex, p_birth, p_hcl, p_origin, p_height, p_weight, p_bp,
                 p_preg, p_gest_wk, p_edd,
                 o_age, o_obs, o_req, o_ins, o_fua, o_emitted, o_emitted_at,
                 ot_ss, ot_si, ot_obs_val, ot_pending, ot_id_val,
                 ot_del, ot_del_reason, o_diag) = r
                if o_id not in orders_map:
                    gest_str = "Sí"
                    if p_preg and p_gest_wk:
                        gest_str = f"Sí ({p_gest_wk} sem)"
                    elif not p_preg:
                        gest_str = "No"
                    row_patient = {
                        "name": f"{p_last or ''} {p_first or ''}".strip(),
                        "doc": f"{p_doc_type or ''} {p_doc_num or ''}".strip(),
                        "doc_number": p_doc_num or "",
                        "sex": p_sex or "—", "birth": _fmt_date(p_birth),
                        "hcl": p_hcl or "—", "origin": p_origin or "—",
                        "height": p_height, "weight": p_weight, "bp": p_bp or "—",
                        "gestante": gest_str,
                    }
                    orders_map[o_id] = {
                        "date": _fmt_date(o_date),
                        "sample": _fmt_date(o_sample),
                        "emitted": o_emitted,
                        "emitted_at": o_emitted_at,
                        "requested_by": o_req or "—",
                        "fua": o_fua or "—",
                        "insurance": o_ins or "—",
                        "age": o_age,
                        "observations": o_obs or "",
                        "diagnosis": o_diag or "",
                        "patient": row_patient,
                        "tests": []
                    }
                    if not first_patient_info:
                        first_patient_info = row_patient
                if not ot_del:
                    orders_map[o_id]["tests"].append((t_name, t_cat, ot_result, ot_ss))

            # Left column: order list
            # Detect if search matches multiple distinct patients (show names in list)
            distinct_patients = {oinfo['patient']['doc'] for oinfo in orders_map.values()}
            multi_patient = len(distinct_patients) > 1
            order_list_html = ""
            if orders_map:
                for oid, oinfo in orders_map.items():
                    em_tag = ' <span style="color:#28a745; font-size:0.75rem;">&#10003; Emitida</span>' if oinfo["emitted"] else ""
                    is_sel = str(oid) == sel_order
                    sel_style = "background:#eef2f8; font-weight:700;" if is_sel else ""
                    href = f"/analisis?tab=historial&doc={html.escape(doc_q)}&apellido={html.escape(apellido_q)}&order_id={oid}"
                    n_tests = len(oinfo['tests'])
                    # Show patient name if multiple patients match the search
                    patient_line = ""
                    if multi_patient:
                        patient_line = f'<div style="font-size:0.75rem; color:#444; font-weight:500;">{html.escape(oinfo["patient"]["name"])}</div>'
                    order_list_html += f"""
<div style="padding:6px 8px; border-bottom:1px solid var(--border); {sel_style}">
  <a href="{href}" style="text-decoration:none; display:block; color:inherit;">
    <div style="font-size:0.78rem; color:var(--muted);">{oinfo['date']}{em_tag}</div>
    <div style="font-weight:600; color:var(--primary);">Orden #{oid}</div>
    {patient_line}
    <div style="font-size:0.75rem; color:var(--muted);">{n_tests} prueba(s)</div>
  </a>
</div>"""
            else:
                order_list_html = '<p class="muted text-center" style="padding:16px;">Sin ordenes</p>'

            # Center column: patient clinical summary
            pat_html = ""
            # Per-order data (shown in center column when an order is selected)
            sel_order_info = orders_map.get(int(sel_order)) if sel_order and sel_order.isdigit() and int(sel_order) in orders_map else None
            # Use the patient data of the selected order (so the correct patient
            # is shown when search matches multiple patients with same last name).
            if sel_order_info and sel_order_info.get("patient"):
                patient_info = sel_order_info["patient"]
            else:
                patient_info = first_patient_info
            if patient_info:
                def _r2(label, val):
                    return f'<tr><td class="muted" style="font-size:0.78rem; white-space:nowrap; padding:3px 6px; vertical-align:top;">{label}</td><td style="font-size:0.83rem; padding:3px 6px; word-break:break-word;">{html.escape(str(val))}</td></tr>'
                order_rows = ""
                if sel_order_info:
                    fua_val = sel_order_info['fua'] if sel_order_info['fua'] != '—' else ''
                    # Age for this specific order
                    age_val = sel_order_info.get('age')
                    if age_val is not None:
                        age_display = f"{int(age_val)} años"
                    else:
                        age_display = "—"
                    # Emitido timestamp formatted
                    em_at = sel_order_info.get('emitted_at') or ""
                    em_display = "No emitida"
                    if sel_order_info.get('emitted'):
                        em_display = f"Sí — {_fmt_date(em_at)}"
                        if len(str(em_at)) > 10:
                            em_display += f" {str(em_at)[11:16]}"
                    fua_row = f"""<tr>
  <td class="muted" style="font-size:0.78rem; white-space:nowrap; padding:3px 6px; vertical-align:top;">FUA</td>
  <td style="font-size:0.83rem; padding:3px 6px;">
    <form method="POST" action="/analisis/fua" style="display:flex; align-items:center; gap:4px; margin:0;">
      <input type="hidden" name="order_id" value="{sel_order}">
      <input type="hidden" name="doc" value="{html.escape(doc_q)}">
      <input type="hidden" name="apellido" value="{html.escape(apellido_q)}">
      <input type="text" name="fua_number" value="{html.escape(fua_val)}"
             style="width:100px; padding:2px 4px; font-size:0.82rem; border:1px solid var(--border); border-radius:3px;"
             placeholder="N° FUA">
      <button type="submit" style="padding:2px 8px; font-size:0.75rem; cursor:pointer; background:var(--primary); color:#fff; border:none; border-radius:3px;">Guardar</button>
    </form>
  </td>
</tr>"""
                    order_rows = f"""
<tr><td colspan="2" style="background:#fff3cd; border-left:3px solid #ffc107; font-size:0.73rem; font-weight:700; text-transform:uppercase; color:#856404; padding:5px 6px;">Datos de la orden #{sel_order}</td></tr>
{_r2("F. orden", sel_order_info['date'] or '—')}
{_r2("F. muestra", sel_order_info['sample'] or '—')}
{_r2("Edad en la orden", age_display)}
{_r2("Médico solicitante", sel_order_info['requested_by'])}
{_r2("Seguro", sel_order_info['insurance'])}
{fua_row}
{_r2("Diagnóstico", sel_order_info.get('diagnosis') or '—')}
{_r2("Observaciones", sel_order_info.get('observations') or '—')}
{_r2("Emitida", em_display)}"""
                else:
                    order_rows = f"""
<tr><td colspan="2" style="background:#f8f9fa; border-left:3px solid #dee2e6; font-size:0.73rem; font-weight:600; color:var(--muted); padding:8px 6px; text-align:center; font-style:italic;">← Seleccione una orden de la lista para ver sus datos</td></tr>"""
                pat_html = f"""
<table style="width:100%; border-collapse:collapse;">
  <tr><td colspan="2" style="background:#eef2f8; font-size:0.73rem; font-weight:700; text-transform:uppercase; color:var(--muted); padding:4px 6px;">Datos del paciente</td></tr>
  {_r2("Paciente", patient_info['name'])}
  {_r2("Documento", patient_info['doc'])}
  {_r2("Sexo", patient_info['sex'])}
  {_r2("F. Nac.", patient_info['birth'])}
  {_r2("HCL", patient_info['hcl'])}
  {_r2("Origen", patient_info['origin'])}
  {_r2("Talla", f"{patient_info['height']} cm" if patient_info['height'] else '—')}
  {_r2("Peso", f"{patient_info['weight']} kg" if patient_info['weight'] else '—')}
  {_r2("Presión", patient_info['bp'])}
  {_r2("Gestante (actual)", patient_info['gestante'])}
  {order_rows}
</table>"""
            else:
                pat_html = '<p class="muted text-center" style="padding:16px;">Busque un paciente</p>'

            # Right column: selected order results
            results_html = ""
            if sel_order and sel_order in {str(k) for k in orders_map}:
                oid_sel = int(sel_order)
                oinfo_sel = orders_map[oid_sel]
                tests = oinfo_sel["tests"]
                blocks = ""
                for t_name, t_cat, ot_result, ot_ss in tests:
                    # Parse result into table rows
                    inner = ""
                    rejected = (ot_ss == "rechazada")
                    if rejected:
                        inner = '<span style="color:#dc3545; font-weight:600;">Muestra rechazada</span>'
                    elif ot_result:
                        try:
                            d = json.loads(ot_result)
                            if isinstance(d, dict) and d.get("type") == "structured":
                                vals = {k: v for k, v in d.get("values", {}).items() if v not in ("", None)}
                                if vals:
                                    inner = "<table style='width:100%; border-collapse:collapse;'>"
                                    for k, v in vals.items():
                                        inner += f'<tr><td style="font-size:0.75rem; color:var(--muted); padding:1px 4px; white-space:nowrap;">{html.escape(str(k))}</td><td style="font-size:0.82rem; padding:1px 4px; word-break:break-word;">{html.escape(str(v))}</td></tr>'
                                    inner += "</table>"
                                else:
                                    inner = '<span class="muted">Sin datos</span>'
                            elif isinstance(d, dict):
                                v = d.get("value", "") or d.get("values", {})
                                inner = html.escape(str(v)) if v else '<span class="muted">—</span>'
                        except Exception:
                            inner = html.escape(str(ot_result))
                    else:
                        inner = '<span class="muted">Pendiente</span>'

                    blocks += f"""
<div style="border:1px solid var(--border); border-radius:6px; margin-bottom:6px; overflow:hidden;">
  <div style="background:#eef2f8; padding:4px 8px; font-size:0.8rem; font-weight:700; display:flex; justify-content:space-between;">
    <span>{html.escape(t_name or '')}</span>
    <span style="color:var(--muted); font-weight:400;">{html.escape(t_cat or '')}</span>
  </div>
  <div style="padding:4px 8px;">{inner}</div>
</div>"""

                pdf_link = f'<a href="/emitir/{oid_sel}/pdf" target="_blank" class="btn btn-secondary btn-sm">PDF</a>' if oinfo_sel["emitted"] else f'<a href="/emitir/{oid_sel}/pdf" target="_blank" class="btn btn-primary btn-sm">Generar PDF</a>'
                results_html = f"""
<div style="display:flex; gap:8px; align-items:center; margin-bottom:8px; flex-wrap:wrap;">
  <span style="font-weight:700; color:var(--primary);">Orden #{oid_sel}</span>
  <span class="muted" style="font-size:0.8rem;">{oinfo_sel['date']}</span>
  {pdf_link}
  <a href="/resultados?order_id={oid_sel}" class="btn btn-secondary btn-sm">Anotar Resultados</a>
</div>
{blocks or '<p class="muted text-center">Sin resultados</p>'}"""
            elif orders_map:
                results_html = '<p class="muted text-center" style="padding:16px;">Seleccione una orden de la lista</p>'
            else:
                results_html = '<p class="muted text-center" style="padding:16px;">—</p>'

            alert_html = _alert(error_msg, "error") if error_msg else ""
            tab_content = f"""{alert_html}
<form method="get" action="/analisis" style="display:flex; gap:8px; align-items:flex-end; margin-bottom:10px; flex-wrap:wrap;">
  <input type="hidden" name="tab" value="historial">
  <div><label class="field-label">N documento</label>
    <input type="text" name="doc" class="form-input-compact" value="{html.escape(doc_q)}"
           placeholder="DNI/CUI..." style="width:130px"></div>
  <div><label class="field-label">Apellidos</label>
    <input type="text" name="apellido" class="form-input-compact" value="{html.escape(apellido_q)}"
           placeholder="Apellidos..." style="width:150px"></div>
  <button type="submit" class="btn btn-primary btn-sm">Buscar</button>
</form>
<div class="historial-grid" style="flex:1; min-height:0;">
  <div class="historial-col" style="overflow-y:auto;">
    <div style="font-size:0.75rem; font-weight:700; text-transform:uppercase; color:var(--muted);
                padding:4px 8px; background:var(--bg-alt); border-bottom:1px solid var(--border);">
      Historial de ordenes
    </div>
    {order_list_html}
  </div>
  <div class="historial-col" style="overflow-y:auto;">
    <div style="font-size:0.75rem; font-weight:700; text-transform:uppercase; color:var(--muted);
                padding:4px 8px; background:var(--bg-alt); border-bottom:1px solid var(--border);">
      Resumen clinico
    </div>
    <div style="padding:8px;">{pat_html}</div>
  </div>
  <div class="historial-col" style="overflow-y:auto;">
    <div style="font-size:0.75rem; font-weight:700; text-transform:uppercase; color:var(--muted);
                padding:4px 8px; background:var(--bg-alt); border-bottom:1px solid var(--border);">
      Resultados de la orden
    </div>
    <div style="padding:8px;">{results_html}</div>
  </div>
</div>"""

        content = f"""
<div class="module-layout">
  <div class="module-header">
    {tabs_bar}
  </div>
  <div class="module-body" style="display:flex; flex-direction:column; padding-top:4px;">
    {tab_content}
  </div>
</div>"""
        self._respond_html(_base_layout(content, "analisis", user))

    def _handle_analisis_fua_update(self):
        """POST /analisis/fua — actualiza el FUA de una orden existente."""
        user = self._require_login()
        if not user:
            return
        data = _parse_form_body(self)
        order_id = data.get("order_id", "").strip()
        fua_number = data.get("fua_number", "").strip()
        doc_q = data.get("doc", "").strip()
        apellido_q = data.get("apellido", "").strip()
        if not order_id:
            self.send_error(400, "Falta order_id")
            return
        db = new_db()
        db.update_order_fua(int(order_id), fua_number)
        # Redirect back to historial with the same search and selected order
        qs = f"tab=historial&order_id={order_id}"
        if doc_q:
            qs += f"&doc={doc_q}"
        if apellido_q:
            qs += f"&apellido={apellido_q}"
        self._redirect(f"/analisis?{qs}")

    def _handle_analisis_registro_pdf(self):
        """Genera PDF de registro de pruebas para un rango de fechas."""
        user = self._require_login()
        if not user:
            return
        params  = _get_query_params(self.path)
        today   = datetime.date.today().isoformat()
        desde   = params.get("desde", today)
        hasta   = params.get("hasta", today)
        db = new_db()
        try:
            start_dt = (desde + " 00:00:00") if desde else None
            end_dt   = (hasta + " 23:59:59") if hasta else None
            rows = db.get_results_in_range(start_dt, end_dt)
        except Exception as e:
            self.send_error(500, str(e))
            return
        from pdf_generator import generate_registro_pdf
        try:
            pdf_bytes = generate_registro_pdf(rows, desde, hasta)
        except Exception as e:
            self.send_error(500, f"Error al generar PDF: {e}")
            return
        fname = f"registro_{desde}_{hasta}.pdf"
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(pdf_bytes)))
        self.end_headers()
        self.wfile.write(pdf_bytes)

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
    url = f"http://127.0.0.1:{port}/login"
    print(f"[OK] Servidor iniciado en: {url}")
    print("   Abre esa URL en Chrome o Brave.")
    print("   Presiona Ctrl+C para detener.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")


if __name__ == "__main__":
    run()

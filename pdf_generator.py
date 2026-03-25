# pdf_generator.py
# Generador de PDF para informes de laboratorio (sin dependencias Qt)
import datetime
import json
import os

from fpdf import FPDF

from test_definitions import TEST_TEMPLATES, default_sample_type_for_test

LAB_TITLE = "Laboratorio P.S. Iñapari - 002789"


# ---------------------------------------------------------------------------
# Helpers de texto / fecha
# ---------------------------------------------------------------------------

def _ensure_latin1(text) -> str:
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    replacements = {'\u2013': '-', '\u2014': '-', '\u2018': "'",
                    '\u2019': "'", '\u201c': '"', '\u201d': '"'}
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    try:
        text.encode('latin-1')
        return text
    except UnicodeEncodeError:
        return text.encode('latin-1', 'replace').decode('latin-1')


def _format_date_display(value, placeholder="—") -> str:
    if value in (None, ""):
        return placeholder
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.datetime.strptime(str(value), fmt)
            return parsed.strftime("%d/%m/%Y")
        except (ValueError, TypeError):
            continue
    try:
        parsed = datetime.datetime.fromisoformat(str(value))
        return parsed.strftime("%d/%m/%Y")
    except Exception:
        return str(value)


def _format_datetime_display(value, placeholder="—") -> str:
    if value in (None, ""):
        return placeholder
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.datetime.strptime(str(value), fmt)
            return parsed.strftime("%d/%m/%Y %H:%M")
        except (ValueError, TypeError):
            continue
    try:
        parsed = datetime.datetime.fromisoformat(str(value))
        return parsed.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return str(value)


def _format_age_text(patient_info: dict, order_info: dict) -> str:
    age_value = order_info.get('age_years')
    if age_value is not None:
        try:
            return f"{int(float(age_value))} años"
        except (TypeError, ValueError):
            pass
    birth_date = patient_info.get('birth_date')
    order_date = order_info.get('date')
    if not birth_date:
        return "-"
    try:
        birth_dt = datetime.datetime.strptime(str(birth_date), "%Y-%m-%d")
        if order_date:
            try:
                ref_dt = datetime.datetime.strptime(str(order_date), "%Y-%m-%d %H:%M:%S")
            except Exception:
                ref_dt = datetime.datetime.now()
        else:
            ref_dt = datetime.datetime.now()
        days = (ref_dt.date() - birth_dt.date()).days
        if days < 0:
            return "-"
        return f"{int(days / 365.25)} años"
    except Exception:
        return "-"


def _format_sample_status_text(status_value, note, pending_since=None) -> str:
    value = (status_value or "recibida").strip().lower()
    if value == "recibida":
        return ""
    label = "Pendiente" if value == "pendiente" else "Rechazada"
    date_suffix = ""
    if value == "pendiente" and pending_since:
        display = _format_datetime_display(pending_since, "")
        if display:
            date_suffix = f" (desde {display})"
    base = f"{label}{date_suffix}"
    return f"{base} - {note}" if note else base


def _parse_stored_result(raw_result) -> dict:
    if isinstance(raw_result, dict):
        return raw_result
    if raw_result in (None, ""):
        return {"type": "text", "value": ""}
    try:
        data = json.loads(raw_result)
    except (TypeError, json.JSONDecodeError):
        return {"type": "text", "value": raw_result}
    if isinstance(data, dict) and data.get("type") == "structured":
        return data
    return {"type": "text", "value": raw_result if raw_result is not None else ""}


def _is_blank_result(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    return False


def _extract_result_structure(test_name: str, raw_result, context=None) -> dict:
    parsed = _parse_stored_result(raw_result)
    template_key = parsed.get("template") if isinstance(parsed, dict) else None
    template = TEST_TEMPLATES.get(template_key) if template_key else None
    if template is None:
        template = TEST_TEMPLATES.get(test_name)

    if parsed.get("type") == "structured" and template:
        values = parsed.get("values", {})
        items = []
        pending_section = None
        for field_def in template.get("fields", []):
            if field_def.get("type") == "section":
                pending_section = field_def.get("label", "") or None
                continue
            key = field_def.get("key")
            if not key:
                continue
            value = values.get(key, "")
            if isinstance(value, str):
                stripped = value.strip()
                if stripped == "":
                    continue
                display_value = " ".join(value.split())
            else:
                if _is_blank_result(value):
                    continue
                display_value = value
            unit = field_def.get("unit")
            field_type = field_def.get("type")
            if unit and field_type not in ("bool", "text_area", "choice"):
                display_value = (f"{display_value} {unit}"
                                 if not str(display_value).endswith(unit)
                                 else display_value)
            if pending_section:
                items.append({"type": "section", "label": pending_section})
                pending_section = None
            items.append({
                "type": "value",
                "key": key,
                "label": field_def.get("label", key),
                "value": display_value,
                "reference": field_def.get("reference") or "-"
            })
        return {"type": "structured", "items": items}

    text_value = parsed.get("value", raw_result or "")
    if isinstance(text_value, str):
        text_value = text_value.strip()
        if text_value == "":
            return {"type": "text", "value": ""}
    elif _is_blank_result(text_value):
        return {"type": "text", "value": ""}
    return {"type": "text", "value": text_value}


# ---------------------------------------------------------------------------
# Renderizado PDF
# ---------------------------------------------------------------------------

def _render_order_pdf(pdf: FPDF, info: dict, emission_display: str,
                       print_display: str = None, is_copy: bool = False):
    """Renderiza una orden en el PDF dado. Idéntico en lógica a main_window._render_order_pdf."""
    pat = info["patient"]
    ord_inf = info["order"]
    results = info["results"]

    doc_text = " ".join([p for p in (pat.get('doc_type'), pat.get('doc_number')) if p]) or "-"
    patient_name = (pat.get('name') or '-').upper()
    age_text = _format_age_text(pat, ord_inf)
    sex_text = (pat.get('sex') or '-').upper()
    hcl_text = (pat.get('hcl') or '-').upper()
    origin_text = (pat.get('origin') or '-').upper()
    requester_text = (ord_inf.get('requested_by') or '-').upper()

    header_image_path = os.path.join("img", "img.png")
    pregnancy_flag = pat.get('is_pregnant')
    gest_weeks = pat.get('gestational_age_weeks')
    due_raw = pat.get('expected_delivery_date')
    due_display = _format_date_display(due_raw, '-') if due_raw else '-'

    pregnancy_text = None
    if pregnancy_flag or due_raw or gest_weeks not in (None, ''):
        if pregnancy_flag:
            weeks_text = ''
            if gest_weeks not in (None, '', 0):
                try:
                    weeks_text = f"{int(gest_weeks)} sem"
                except (TypeError, ValueError):
                    pass
            pregnancy_text = 'Sí'
            if weeks_text:
                pregnancy_text = f"{pregnancy_text} ({weeks_text})"
        else:
            pregnancy_text = 'No'

    sample_date_display = _format_date_display(ord_inf.get('sample_date'), '-')
    if not print_display:
        print_display = emission_display
    insurance_display = (ord_inf.get('insurance_type') or 'SIS').strip().upper() or 'SIS'

    info_pairs = [
        (("Paciente", patient_name), ("Edad", age_text)),
        (("Documento", doc_text.upper()), ("Sexo", sex_text)),
        (("Seguro", insurance_display), ("Historia clínica", hcl_text)),
        (("Procedencia", origin_text), ("Fecha del informe", emission_display)),
        (("Solicitante", requester_text), ("Fecha de toma de muestra", sample_date_display)),
    ]
    if pregnancy_text:
        info_pairs.append((("Gestante", pregnancy_text), ("FUM", due_display)))

    # --- inner helpers ---

    def wrap_text(text, max_width):
        if max_width <= 0:
            return [str(text)]
        if text in (None, ""):
            text = "-"
        text = _ensure_latin1(str(text)).replace('\r', ' ')
        segments = [p.strip() for p in text.split('\n') if p.strip()]
        if not segments:
            segments = [text.strip() or "-"]
        lines = []
        for segment in segments:
            words = segment.split()
            if not words:
                lines.append("-")
                continue
            current = words[0]
            for word in words[1:]:
                candidate = f"{current} {word}"
                if pdf.get_string_width(candidate) <= max(max_width, 1):
                    current = candidate
                else:
                    lines.append(current)
                    current = word
            lines.append(current)
        return lines or ["-"]

    def normalize_styled_text(text):
        if text in (None, ""):
            return "-", False
        if not isinstance(text, str):
            return text, False
        stripped = text.strip()
        if len(stripped) >= 2 and stripped[0] in {"*", "_"} and stripped[-1] == stripped[0]:
            inner = stripped[1:-1].strip()
            if inner:
                return inner, True
        return text, False

    def ensure_space(required_height):
        if pdf.get_y() + required_height > pdf.h - pdf.b_margin:
            pdf.add_page()
            draw_page_header()
            return True
        return False

    def draw_patient_info():
        col_width = (pdf.w - pdf.l_margin - pdf.r_margin) / 2

        def wrap_value_lines(text, width):
            safe_value = str(text) if text not in (None, "") else "-"
            safe_value = _ensure_latin1(safe_value)
            segments = [p.strip() for p in safe_value.split('\n') if p.strip()]
            if not segments:
                segments = [safe_value.strip() or "-"]
            lines = []
            for segment in segments:
                words = segment.split()
                if not words:
                    lines.append("-")
                    continue
                current = words[0]
                for word in words[1:]:
                    candidate = f"{current} {word}"
                    if pdf.get_string_width(candidate) <= max(width, 1):
                        current = candidate
                    else:
                        lines.append(current)
                        current = word
                lines.append(current)
            return lines or ["-"]

        def render_pair(label, value, x_start, width, start_y):
            pdf.set_xy(x_start, start_y)
            pdf.set_font("Arial", 'B', 7.2)
            pdf.cell(width, 3.2, _ensure_latin1(f"{label.upper()}:"), border=0)
            pdf.set_font("Arial", '', 7.2)
            current_y = start_y + 3.2
            value_lines = wrap_value_lines(value, width - 1.2)
            for line in value_lines:
                pdf.set_xy(x_start, current_y)
                pdf.cell(width, 3.0, line, border=0)
                current_y += 3.0
            return current_y

        pdf.set_font("Arial", 'B', 8.8)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, _ensure_latin1("Datos del paciente"), ln=1)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
        for left, right in info_pairs:
            start_y = pdf.get_y()
            left_end = render_pair(left[0], left[1], pdf.l_margin, col_width, start_y)
            right_end = render_pair(right[0], right[1], pdf.l_margin + col_width, col_width, start_y)
            pdf.set_y(max(left_end, right_end) + 1.2)

    def draw_page_header():
        top_y = max(5, pdf.t_margin - 6)
        header_drawn = False
        if os.path.exists(header_image_path):
            try:
                header_width = pdf.w - pdf.l_margin - pdf.r_margin
                pdf.image(header_image_path, x=pdf.l_margin, y=top_y, w=header_width, h=27)
                pdf.set_y(top_y + 27 + 2)
                header_drawn = True
            except Exception:
                header_drawn = False
        if not header_drawn:
            pdf.set_y(pdf.t_margin)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 6, _ensure_latin1(LAB_TITLE), ln=1, align='C')
            pdf.ln(2)
        draw_patient_info()
        pdf.ln(1.0)
        if is_copy:
            copy_note = (f"Copia reimpresa el {print_display}"
                         if print_display else "Copia reimpresa")
            pdf.set_font("Arial", 'B', 8.5)
            pdf.set_text_color(110, 110, 110)
            pdf.cell(0, 4, _ensure_latin1(copy_note), ln=1, align='R')
            pdf.set_text_color(0, 0, 0)
            pdf.ln(0.5)

    table_total_width = pdf.w - pdf.l_margin - pdf.r_margin
    column_widths = [table_total_width * 0.38, table_total_width * 0.27,
                     table_total_width * 0.35]

    def render_table_header(widths, on_new_page=None):
        header_height = 5.6
        if ensure_space(header_height) and on_new_page:
            on_new_page()
        pdf.set_font("Arial", 'B', 7.2)
        x_start = pdf.l_margin
        pdf.set_x(x_start)
        headers = ["Parámetro", "Resultado", "Valores de referencia"]
        for idx, title in enumerate(headers):
            if idx == 2:
                pdf.set_fill_color(220, 220, 220)
                pdf.set_text_color(50, 50, 50)
            else:
                pdf.set_fill_color(46, 117, 182)
                pdf.set_text_color(255, 255, 255)
            pdf.cell(widths[idx], header_height, _ensure_latin1(title),
                     border=1, align='C', fill=True)
        pdf.ln(header_height)
        pdf.set_text_color(0, 0, 0)

    def render_table_row(texts, widths, on_new_page):
        line_height = 3.1
        padding_x = 1.3
        padding_y = 0.8
        pdf.set_font("Arial", '', 6.8)
        lines_by_cell = []
        max_lines = 1
        for idx, text in enumerate(texts):
            available = max(widths[idx] - 2 * padding_x, 1)
            normalized, is_italic = normalize_styled_text(text)
            lines = wrap_text(normalized, available)
            lines_by_cell.append((lines, is_italic))
            if len(lines) > max_lines:
                max_lines = len(lines)
        row_height = max_lines * line_height + 2 * padding_y
        if ensure_space(row_height):
            on_new_page()
            render_table_header(widths, on_new_page)
        x_start = pdf.l_margin
        y_start = pdf.get_y()
        pdf.set_draw_color(210, 215, 226)
        pdf.set_line_width(0.2)
        for idx, (lines, is_italic) in enumerate(lines_by_cell):
            cell_width = widths[idx]
            x_pos = x_start + sum(widths[:idx])
            if idx == 2:
                pdf.set_fill_color(245, 245, 245)
                pdf.set_text_color(70, 70, 70)
            else:
                pdf.set_fill_color(255, 255, 255)
                pdf.set_text_color(0, 0, 0)
            pdf.rect(x_pos, y_start, cell_width, row_height)
            text_y = y_start + padding_y
            for line in lines:
                line = _ensure_latin1(line)
                pdf.set_xy(x_pos + padding_x, text_y)
                pdf.set_font("Arial", 'I' if is_italic else '', 6.8)
                pdf.cell(cell_width - 2 * padding_x, line_height, line, border=0)
                text_y += line_height
        pdf.set_text_color(0, 0, 0)
        pdf.set_xy(pdf.l_margin, y_start + row_height)

    def render_section_row(label, total_width, widths, on_new_page):
        section_height = 4.2
        if ensure_space(section_height + 1):
            on_new_page()
            render_table_header(widths, on_new_page)
        pdf.set_font("Arial", 'B', 6.8)
        pdf.set_fill_color(242, 246, 253)
        pdf.set_text_color(47, 84, 150)
        pdf.cell(total_width, section_height, _ensure_latin1(label),
                 border=1, ln=1, align='L', fill=True)
        pdf.set_text_color(0, 0, 0)

    def draw_test_header(title):
        ensure_space(9)
        pdf.set_font("Arial", 'B', 8.2)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(46, 117, 182)
        pdf.cell(0, 6, _ensure_latin1(title.upper()), ln=1, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1.2)

    # Draw header on first page
    draw_page_header()

    # Render each test result
    for row in results:
        # row tuple: (test_name, raw_result, _, sample_status, sample_issue,
        #              observation, sample_type, _, pending_since)
        test_name = row[0]
        raw_result = row[1]
        sample_status = row[3]
        sample_issue = row[4]
        observation = row[5]
        sample_type = row[6]
        pending_since = row[8] if len(row) > 8 else None

        structure = _extract_result_structure(test_name, raw_result)

        # Skip empty results
        if structure.get("type") == "structured":
            if not any(item.get("type") == "value" for item in structure.get("items", [])):
                continue
        else:
            value_text = structure.get("value", "")
            if _is_blank_result(value_text):
                continue

        status_text = _format_sample_status_text(sample_status, sample_issue, pending_since)
        observation_text = observation or ""

        draw_test_header(test_name)

        # Sample type line
        sample_text = (sample_type or "").strip() if isinstance(sample_type, str) else ""
        if not sample_text:
            sample_text = default_sample_type_for_test(test_name)
        ensure_space(4.8)
        pdf.set_font("Arial", 'B', 6.9)
        pdf.set_text_color(67, 91, 114)
        pdf.cell(0, 3.8, _ensure_latin1(f"MUESTRA: {sample_text}"), ln=1)
        pdf.set_text_color(0, 0, 0)

        def on_new_page():
            draw_test_header(test_name)
            pdf.set_font("Arial", 'B', 6.9)
            pdf.set_text_color(67, 91, 114)
            pdf.cell(0, 3.8, _ensure_latin1(f"MUESTRA: {sample_text}"), ln=1)
            pdf.set_text_color(0, 0, 0)

        if structure.get("type") == "structured":
            render_table_header(column_widths, on_new_page)
            for item in structure.get("items", []):
                if item.get("type") == "section":
                    render_section_row(item.get("label", ""), sum(column_widths),
                                       column_widths, on_new_page)
                    continue
                row_texts = [
                    item.get('label', ''),
                    item.get('value', '-'),
                    item.get('reference') or '-'
                ]
                render_table_row(row_texts, column_widths, on_new_page)
        else:
            text_value = structure.get("value", "")
            ensure_space(6)
            normalized_text, is_italic = normalize_styled_text(text_value)
            pdf.set_font("Arial", 'I' if is_italic else '', 7)
            pdf.multi_cell(0, 3.8, _ensure_latin1(normalized_text))

        if status_text:
            ensure_space(5)
            pdf.set_font("Arial", 'I', 6.6)
            pdf.set_text_color(166, 38, 38)
            pdf.multi_cell(0, 3.8, _ensure_latin1(f"Estado de muestra: {status_text}"))
            pdf.set_text_color(0, 0, 0)

        if observation_text:
            ensure_space(5)
            normalized_obs, is_obs_italic = normalize_styled_text(observation_text)
            pdf.set_font("Arial", 'I' if is_obs_italic else '', 6.6)
            pdf.multi_cell(0, 3.8, _ensure_latin1(f"Observación: {normalized_obs}"))

        pdf.ln(2)

    # General observations
    if ord_inf.get('observations') and str(ord_inf['observations']).strip().upper() not in {"", "N/A"}:
        ensure_space(8)
        pdf.set_font("Arial", 'B', 7.4)
        pdf.cell(0, 4.2, "Observaciones generales", ln=1)
        pdf.set_font("Arial", '', 6.9)
        pdf.multi_cell(0, 3.6, _ensure_latin1(ord_inf['observations']))
        pdf.ln(1.5)


def generate_order_pdf(order_details: dict, emitted_at: str) -> bytes:
    """Genera el PDF de una orden y retorna los bytes.

    Args:
        order_details: dict retornado por db.get_order_details()
        emitted_at: timestamp de emisión (ej. '2025-03-25 14:30:00')

    Returns:
        bytes del PDF listo para enviar como respuesta HTTP
    """
    try:
        emission_dt = datetime.datetime.strptime(emitted_at, "%Y-%m-%d %H:%M:%S")
        emission_display = emission_dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        emission_display = emitted_at or datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    existing_emitted_at = order_details.get("order", {}).get("emitted_at")
    is_copy = bool(existing_emitted_at)
    print_display = datetime.datetime.now().strftime("%d/%m/%Y %H:%M") if is_copy else emission_display
    if is_copy and existing_emitted_at:
        try:
            orig_dt = datetime.datetime.strptime(existing_emitted_at, "%Y-%m-%d %H:%M:%S")
            emission_display = orig_dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            pass

    pdf = FPDF('P', 'mm', 'A4')
    pdf.set_margins(10, 8, 10)
    pdf.set_auto_page_break(True, margin=10)
    pdf.add_page()

    _render_order_pdf(pdf, order_details, emission_display,
                      print_display=print_display, is_copy=is_copy)

    raw = pdf.output(dest='S')
    if isinstance(raw, str):
        return raw.encode('latin-1')
    return bytes(raw)

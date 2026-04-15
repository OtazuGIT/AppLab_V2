# pdf_generator.py
# Generador de PDF para informes de laboratorio (sin dependencias Qt)
import datetime
import json
import os
import re
import unicodedata

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


# ---------------------------------------------------------------------------
# Filtrado de valores de referencia por contexto (edad/sexo/embarazo)
# Portado de main_window.py líneas 4279–4454 sin dependencias Qt
# ---------------------------------------------------------------------------

def _normalize_text_for_ref(text) -> str:
    if not isinstance(text, str):
        text = str(text or "")
    normalized = unicodedata.normalize("NFD", text.lower())
    return "".join(ch for ch in normalized if unicodedata.category(ch) != 'Mn')


def _normalize_bool_for_ref(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "si", "sí")
    return False


def _split_reference_segments(reference_text: str) -> list:
    segments = []
    for raw_line in str(reference_text).split('\n'):
        for part in raw_line.split('|'):
            cleaned = part.strip()
            if cleaned:
                segments.append(cleaned)
    return segments or [str(reference_text).strip()]


def _assign_age_range_groups(groups: set, start_age: float, end_age: float):
    if end_age < 0 or start_age < 0:
        return
    if end_age >= 18 and start_age >= 18:
        groups.add('adult')
    elif end_age < 18:
        if end_age <= 1:
            groups.add('newborn')
        groups.add('child')
    else:
        groups.update({'child', 'adult'})


def _classify_reference_segment(segment: str) -> dict:
    normalized = _normalize_text_for_ref(segment)
    groups = set()
    sexes = set()
    ranges = []
    if any(kw in normalized for kw in ["rn", "recien nacido", "neon", "lactant"]):
        groups.add('newborn')
    if any(kw in normalized for kw in ["nino", "ninos", "infantil", "pediatr", "menor", "adolesc"]):
        groups.add('child')
    if "mes" in normalized:
        groups.add('child')
    if any(kw in normalized for kw in ["adulto", "adultos", "mayor", "ancian", "geriatr"]):
        groups.add('adult')
    if any(kw in normalized for kw in ["mujer", "mujeres", "femen"]):
        sexes.add('female')
        groups.add('adult')
    if any(kw in normalized for kw in ["hombre", "hombres", "varon", "varones", "mascul"]):
        sexes.add('male')
        groups.add('adult')
    if "gestant" in normalized or "embaraz" in normalized:
        sexes.add('female')
        groups.add('adult')
        groups.add('pregnant')
    for match in re.finditer(r'(\d+)\s*[-\u2013]\s*(\d+)\s*(?:anos|ano|a)', normalized):
        start = int(match.group(1))
        end = int(match.group(2))
        _assign_age_range_groups(groups, start, end)
        ranges.append((start, end))
    for match in re.finditer(r'(>=|<=|>|<)?\s*(\d+)\s*(?:anos|ano|a)', normalized):
        operator = match.group(1) or ""
        age = int(match.group(2))
        _assign_age_range_groups(groups, age, age)
        if operator == '>':
            ranges.append((age + 0.001, float('inf')))
        elif operator == '>=':
            ranges.append((age, float('inf')))
        elif operator == '<':
            ranges.append((float('-inf'), age - 0.001))
        elif operator == '<=':
            ranges.append((float('-inf'), age))
        else:
            ranges.append((age, age))
    for match in re.finditer(r'(\d+)\s*(?:mes|meses)', normalized):
        months = int(match.group(1))
        groups.add('child')
        if months <= 1:
            groups.add('newborn')
        ranges.append((0, max(months / 12, 0)))
    return {"groups": groups, "sexes": sexes, "ranges": ranges}


def _age_in_range(age_value: float, start: float, end: float) -> bool:
    if start is None and end is None:
        return True
    if start is None:
        return age_value <= end
    if end is None:
        return age_value >= start
    return start <= age_value <= end


def _segment_matches_sex(sexes: set, normalized_sex: str) -> bool:
    if not sexes:
        return True
    if not normalized_sex:
        return True
    if any(kw in normalized_sex for kw in ["femen", "mujer"]):
        return 'female' in sexes
    if any(kw in normalized_sex for kw in ["mascul", "hombre", "varon"]):
        return 'male' in sexes
    return True


def _segment_matches_context(classification: dict, age_value, sex: str, is_pregnant: bool) -> bool:
    groups = classification.get('groups', set())
    sexes = classification.get('sexes', set())
    ranges = classification.get('ranges', [])
    if age_value is not None and ranges:
        if not any(_age_in_range(age_value, s, e) for s, e in ranges):
            return False
    if age_value is None:
        return _segment_matches_sex(sexes, sex)
    target_groups = set()
    if age_value <= 0:
        target_groups.add('newborn')
    if age_value < 18:
        target_groups.add('child')
    if age_value >= 18:
        target_groups.add('adult')
    if 'pregnant' in groups and not is_pregnant:
        return False
    if groups and not groups.intersection(target_groups):
        return False
    return _segment_matches_sex(sexes, sex)


def _segment_matches_group_only(classification: dict, age_value, is_pregnant: bool) -> bool:
    groups = classification.get('groups', set())
    if not groups:
        return False
    target_groups = set()
    if age_value is None:
        target_groups.update({'child', 'adult', 'newborn'})
    else:
        if age_value <= 0:
            target_groups.add('newborn')
        if age_value < 18:
            target_groups.add('child')
        if age_value >= 18:
            target_groups.add('adult')
    if 'pregnant' in groups and not is_pregnant:
        return False
    non_preg = {g for g in groups if g != 'pregnant'}
    if non_preg and not non_preg.intersection(target_groups):
        return False
    return True


def _filter_reference_for_context(reference: str, context) -> str:
    """Filtra cadena de referencia multigrupo para devolver solo el segmento
    que corresponde al paciente (edad/sexo/embarazo). Ej: una mujer adulta
    con Hb solo ve '12.0-16.0 g/dL' en lugar de todos los grupos.

    context = {"patient": {"sex": ..., "is_pregnant": ...},
               "order":   {"age_years": ...}}
    """
    if not reference or reference == "-" or not isinstance(reference, str):
        return reference
    if not context:
        return reference
    patient_info = context.get("patient", {}) if isinstance(context, dict) else {}
    order_info = context.get("order", {}) if isinstance(context, dict) else {}

    # Age
    age_value = None
    raw_age = order_info.get("age_years")
    if raw_age is not None:
        try:
            age_value = float(raw_age)
        except (TypeError, ValueError):
            pass
    if age_value is None:
        birth = patient_info.get("birth_date")
        if birth:
            try:
                bd = datetime.datetime.strptime(str(birth), "%Y-%m-%d")
                age_value = (datetime.datetime.now() - bd).days / 365.25
            except (ValueError, TypeError):
                pass

    sex = _normalize_text_for_ref(patient_info.get("sex") or "")
    is_pregnant = _normalize_bool_for_ref(patient_info.get("is_pregnant"))

    segments = _split_reference_segments(reference)
    applicable = []
    sex_only = []
    group_only = []
    general = []
    for seg in segments:
        cls = _classify_reference_segment(seg)
        if _segment_matches_context(cls, age_value, sex, is_pregnant):
            applicable.append(seg.strip())
            continue
        if _segment_matches_sex(cls.get('sexes', set()), sex):
            sex_only.append(seg.strip())
        if _segment_matches_group_only(cls, age_value, is_pregnant):
            group_only.append(seg.strip())
        if not cls['groups'] and not cls['sexes']:
            general.append(seg.strip())
    if applicable:
        return applicable[0]
    if sex_only:
        return sex_only[0]
    if group_only:
        return group_only[0]
    if general:
        return general[0]
    return segments[0].strip() if segments else reference


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
                "reference": _filter_reference_for_context(field_def.get("reference") or "-", context)
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

    # Context for reference value filtering by patient age/sex/pregnancy
    _ref_context = {"patient": pat, "order": ord_inf}

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
            pdf.set_font("Arial", 'B', 7.0)
            pdf.cell(width, 2.8, _ensure_latin1(f"{label.upper()}:"), border=0)
            pdf.set_font("Arial", '', 7.0)
            current_y = start_y + 2.8
            value_lines = wrap_value_lines(value, width - 1.2)
            for line in value_lines:
                pdf.set_xy(x_start, current_y)
                pdf.cell(width, 2.6, line, border=0)
                current_y += 2.6
            return current_y

        pdf.set_font("Arial", 'B', 8.8)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, _ensure_latin1("Datos del paciente"), ln=1)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(0.3)
        for left, right in info_pairs:
            start_y = pdf.get_y()
            left_end = render_pair(left[0], left[1], pdf.l_margin, col_width, start_y)
            right_end = render_pair(right[0], right[1], pdf.l_margin + col_width, col_width, start_y)
            pdf.set_y(max(left_end, right_end) + 0.5)

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
        pdf.ln(0.3)
        if is_copy:
            copy_note = (f"Copia reimpresa el {print_display}"
                         if print_display else "Copia reimpresa")
            pdf.set_font("Arial", 'B', 8.5)
            pdf.set_text_color(110, 110, 110)
            pdf.cell(0, 4, _ensure_latin1(copy_note), ln=1, align='R')
            pdf.set_text_color(0, 0, 0)
            pdf.ln(0.5)

    table_total_width = pdf.w - pdf.l_margin - pdf.r_margin
    column_widths = [table_total_width * 0.40, table_total_width * 0.30,
                     table_total_width * 0.30]

    def render_table_header(widths, on_new_page=None):
        header_height = 4.5
        if ensure_space(header_height) and on_new_page:
            on_new_page()
        pdf.set_font("Arial", 'B', 7.0)
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
        line_height = 2.7
        padding_x = 1.3
        padding_y = 0.5
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
        section_height = 3.4
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
        ensure_space(7)
        pdf.set_font("Arial", 'B', 8.2)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(46, 117, 182)
        pdf.cell(0, 5, _ensure_latin1(title.upper()), ln=1, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(0.6)

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

        structure = _extract_result_structure(test_name, raw_result, _ref_context)

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
        ensure_space(4.0)
        pdf.set_font("Arial", 'B', 6.9)
        pdf.set_text_color(67, 91, 114)
        pdf.cell(0, 3.0, _ensure_latin1(f"MUESTRA: {sample_text}"), ln=1)
        pdf.set_text_color(0, 0, 0)

        def on_new_page():
            draw_test_header(test_name)
            pdf.set_font("Arial", 'B', 6.9)
            pdf.set_text_color(67, 91, 114)
            pdf.cell(0, 3.0, _ensure_latin1(f"MUESTRA: {sample_text}"), ln=1)
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
            ensure_space(5)
            normalized_text, is_italic = normalize_styled_text(text_value)
            pdf.set_font("Arial", 'I' if is_italic else '', 7)
            pdf.multi_cell(0, 3.2, _ensure_latin1(normalized_text))

        if status_text:
            ensure_space(4)
            pdf.set_font("Arial", 'I', 6.6)
            pdf.set_text_color(166, 38, 38)
            pdf.multi_cell(0, 3.2, _ensure_latin1(f"Estado de muestra: {status_text}"))
            pdf.set_text_color(0, 0, 0)

        if observation_text:
            ensure_space(4)
            normalized_obs, is_obs_italic = normalize_styled_text(observation_text)
            pdf.set_font("Arial", 'I' if is_obs_italic else '', 6.6)
            pdf.multi_cell(0, 3.2, _ensure_latin1(f"Observación: {normalized_obs}"))

        pdf.ln(0.8)

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
    pdf.set_margins(7, 6, 7)
    pdf.set_auto_page_break(True, margin=8)
    pdf.add_page()

    _render_order_pdf(pdf, order_details, emission_display,
                      print_display=print_display, is_copy=is_copy)

    raw = pdf.output(dest='S')
    if isinstance(raw, str):
        return raw.encode('latin-1')
    return bytes(raw)


def generate_batch_pdf(orders_details_list: list, emitted_at: str) -> bytes:
    """Genera un PDF combinado para múltiples órdenes (una por página).

    Args:
        orders_details_list: lista de dicts retornados por db.get_order_details()
        emitted_at: timestamp de emisión compartido

    Returns:
        bytes del PDF listo para enviar como respuesta HTTP
    """
    try:
        emission_dt = datetime.datetime.strptime(emitted_at, "%Y-%m-%d %H:%M:%S")
        emission_display = emission_dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        emission_display = emitted_at or datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    pdf = FPDF('P', 'mm', 'A4')
    pdf.set_margins(7, 6, 7)
    pdf.set_auto_page_break(True, margin=8)

    for order_details in orders_details_list:
        pdf.add_page()
        existing_emitted_at = order_details.get("order", {}).get("emitted_at")
        is_copy = bool(existing_emitted_at)
        print_display = datetime.datetime.now().strftime("%d/%m/%Y %H:%M") if is_copy else emission_display
        _emission = emission_display
        if is_copy and existing_emitted_at:
            try:
                orig_dt = datetime.datetime.strptime(existing_emitted_at, "%Y-%m-%d %H:%M:%S")
                _emission = orig_dt.strftime("%d/%m/%Y %H:%M")
            except Exception:
                pass
        _render_order_pdf(pdf, order_details, _emission,
                          print_display=print_display, is_copy=is_copy)

    raw = pdf.output(dest='S')
    if isinstance(raw, str):
        return raw.encode('latin-1')
    return bytes(raw)


def generate_registro_pdf(rows, desde: str, hasta: str) -> bytes:
    """Genera un PDF con el registro de pruebas para el rango dado.
    rows: output of db.get_results_in_range()
    """
    pdf = FPDF('L', 'mm', 'A4')   # Landscape for wider table
    pdf.set_margins(8, 8, 8)
    pdf.set_auto_page_break(True, margin=10)
    pdf.add_page()

    # Header
    pdf.set_font("Arial", "B", 13)
    pdf.cell(0, 7, _ensure_latin1(LAB_TITLE), ln=True, align="C")
    pdf.set_font("Arial", "B", 10)
    periodo = f"Registro de pruebas: {desde} al {hasta}"
    pdf.cell(0, 6, _ensure_latin1(periodo), ln=True, align="C")
    pdf.set_font("Arial", "", 8)
    generated = f"Generado: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}"
    pdf.cell(0, 5, _ensure_latin1(generated), ln=True, align="C")
    pdf.ln(3)

    # Table header  — landscape A4 = 277mm usable
    COL_W = [20, 60, 30, 12, 50, 105]   # Fecha|Paciente|Documento|Edad|Examen|Resultado
    HEADERS = ["Fecha", "Paciente", "Documento", "Edad", "Examen", "Resultado"]
    pdf.set_fill_color(46, 134, 222)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 7)
    for h, w in zip(HEADERS, COL_W):
        pdf.cell(w, 6, _ensure_latin1(h), border=1, align="C", fill=True)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    # Rows
    fill = False
    pdf.set_font("Arial", "", 7)
    for r in rows:
        o_date   = str(r[2] or "")[:10]
        p_first  = r[4] or ""
        p_last   = r[5] or ""
        p_doc_t  = r[6] or ""
        p_doc_n  = r[7] or ""
        o_age    = str(r[15]) if r[15] is not None else "—"
        t_name   = r[19] or ""
        ot_res   = r[21] or ""

        # Parse result
        disp = ot_res
        try:
            d = json.loads(ot_res)
            if isinstance(d, dict) and d.get("type") == "structured":
                vals = [(k, v) for k, v in d.get("values", {}).items() if v not in ("", None)]
                disp = " | ".join(f"{k}: {v}" for k, v in vals) if vals else "—"
            elif isinstance(d, dict):
                v = d.get("value", ot_res)
                disp = str(v) if v else "—"
        except Exception:
            pass

        p_name = f"{p_last} {p_first}".strip()

        row_vals = [o_date, p_name, f"{p_doc_t} {p_doc_n}".strip(), o_age, t_name, disp]
        pdf.set_fill_color(248, 251, 255) if fill else pdf.set_fill_color(255, 255, 255)
        # Multi-line cell hack: use the last column as a multi-line cell
        # Calculate row height by splitting result text
        result_text = _ensure_latin1(str(disp))
        for val, w in zip(row_vals[:-1], COL_W[:-1]):
            pdf.cell(w, 5, _ensure_latin1(str(val))[:30], border="LTB", fill=True)
        # Last cell (result) — truncate to fit
        pdf.cell(COL_W[-1], 5, result_text[:80], border="RTB", fill=True)
        pdf.ln()
        fill = not fill

    pdf.ln(3)
    pdf.set_font("Arial", "I", 7)
    pdf.cell(0, 4, _ensure_latin1(f"Total: {len(rows)} resultado(s)"), ln=True)

    raw = pdf.output(dest='S')
    if isinstance(raw, str):
        return raw.encode('latin-1')
    return bytes(raw)

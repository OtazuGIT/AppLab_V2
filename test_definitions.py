# test_definitions.py
# Definiciones de plantillas de exámenes extraídas de main_window.py (sin dependencias Qt)
import copy

CATEGORY_DISPLAY_ORDER = [
    "HEMATOLOGÍA",
    "BIOQUÍMICA",
    "INMUNOLOGÍA",
    "PRUEBAS RÁPIDAS",
    "PARASITOLOGÍA",
    "MICROBIOLOGÍA",
    "MICROSCOPÍA",
    "LABORATORIO REFERENCIAL",
    "OTROS",
    "TOMA DE MUESTRA"
]

SAMPLE_TYPE_DEFAULTS = {
    "examen completo de orina": "Orina de chorro medio",
    "examen general de orina": "Orina de chorro medio",
    "sedimento urinario": "Orina de chorro medio",
    "urocultivo": "Orina de chorro medio",
    "secrecion vaginal": "Secreción vaginal",
    "secrecion (otros sitios)": "Secreción"
}

# ---------------------------------------------------------------------------
# Campos base reutilizables
# ---------------------------------------------------------------------------

HEMOGRAM_BASE_FIELDS = [
    {"key": "hematocrito", "label": "Hematocrito (Hto)", "unit": "%",
     "reference": "RN: 44-65 %\nNiños 1-10 a: 35-45 %\nHombres adultos: 40-54 %\nMujeres adultas: 36-47 %\nGestantes (2°-3° trim): 33-43 %",
     "placeholder": "Ej. 42.5"},
    {"key": "hemoglobina", "label": "Hemoglobina (Hb)", "unit": "g/dL",
     "reference": "RN: 14.0-24.0 g/dL\n1-12 meses: 10.0-12.5 g/dL\nNiños 1-12 años: 11.5-15.5 g/dL\nMujeres adultas: 12.0-16.0 g/dL\nHombres adultos: 13.5-17.5 g/dL\nGestantes (2°-3° trim): ≥11.0 g/dL",
     "placeholder": "Ej. 14.1"},
    {"key": "leucocitos", "label": "Leucocitos", "unit": "/µL",
     "reference": "RN: 9 000-30 000 /µL\n1-12 meses: 6 000-17 500 /µL\nNiños 1-6 años: 5 000-15 500 /µL\nNiños 6-18 años: 4 500-13 500 /µL\nAdultos: 4 500-11 000 /µL",
     "placeholder": "Ej. 7 500"},
    {"key": "eritrocitos", "label": "Recuento de hematíes (RBC)", "unit": "millones/µL",
     "reference": "RN: 4.1-6.1 millones/µL\nNiños 1-10 años: 3.9-5.3 millones/µL\nHombres adultos: 4.5-6.0 millones/µL\nMujeres adultas: 4.0-5.4 millones/µL",
     "placeholder": "Ej. 4.8"},
    {"key": "plaquetas", "label": "Plaquetas", "unit": "/µL",
     "reference": "RN: 150 000-450 000 /µL\nNiños: 150 000-450 000 /µL\nAdultos: 150 000-400 000 /µL",
     "placeholder": "Ej. 250 000"},
    {"key": "segmentados", "label": "Segmentados", "unit": "%",
     "reference": "Adultos: 40-75 %\nNiños 1-6 años: 30-60 %"},
    {"key": "abastonados", "label": "Abastonados", "unit": "%", "reference": "0-6 %", "optional": True},
    {"key": "linfocitos", "label": "Linfocitos", "unit": "%",
     "reference": "RN: 22-35 %\nNiños 1-6 años: 40-65 %\nAdultos: 20-45 %"},
    {"key": "monocitos", "label": "Monocitos", "unit": "%", "reference": "2-10 %"},
    {"key": "eosinofilos", "label": "Eosinófilos", "unit": "%", "reference": "0-6 %"},
    {"key": "basofilos", "label": "Basófilos", "unit": "%", "reference": "0-2 %", "optional": True},
    {"key": "mielocitos", "label": "Mielocitos", "unit": "%", "optional": True},
    {"key": "metamielocitos", "label": "Metamielocitos", "unit": "%", "optional": True},
    {"key": "otras_celulas", "label": "Otras anormalidades", "optional": True,
     "placeholder": "Ej. Células en banda"},
    {"key": "observaciones", "label": "Observaciones microscópicas", "type": "text_area",
     "optional": True, "placeholder": "Describe hallazgos morfológicos"}
]

_DIPSTICK_OPTS = ["Negativo", "Trazas", "+", "++", "+++", "++++"]
_UROBILINOGENO_OPTS = ["Normal (0.1-1.0 mg/dL)", "2.0 mg/dL", "4.0 mg/dL", "8.0 mg/dL"]

URINE_BASE_FIELDS = [
    {"type": "section", "label": "Examen físico"},
    {"key": "color",   "label": "Color",   "reference": "Amarillo pajizo; RN: incoloro a amarillo claro",
     "type": "choice", "choices": ["Amarillo pajizo", "Amarillo claro", "Amarillo oscuro", "Anaranjado", "Rojo / hematúrico", "Marrón", "Turbio / lechoso", "Incoloro"]},
    {"key": "aspecto", "label": "Aspecto", "reference": "Transparente; leve turbidez fisiológica en gestantes",
     "type": "choice", "choices": ["Transparente", "Ligeramente turbio", "Turbio", "Muy turbio / lechoso"]},
    {"key": "olor",    "label": "Olor",    "reference": "Aromático suave", "optional": True},
    {"type": "section", "label": "Examen químico (tira reactiva)"},
    {"key": "densidad",          "label": "Densidad",       "reference": "RN: 1.002-1.012 | Niños: 1.005-1.015 | Adultos: 1.005-1.030", "placeholder": "Ej. 1.020"},
    {"key": "ph",                "label": "pH",             "reference": "RN: 5.0-7.0 | Niños/Adultos: 5.0-7.5", "placeholder": "Ej. 6.0"},
    {"key": "urobilinogeno",     "label": "Urobilinógeno",  "reference": "Normal: 0.1-1.0 mg/dL",
     "type": "choice", "choices": _UROBILINOGENO_OPTS},
    {"key": "bilirrubina",       "label": "Bilirrubina",    "reference": "Negativo",          "type": "dipstick"},
    {"key": "proteinas",         "label": "Proteínas",      "reference": "Negativo (<15 mg/dL)", "type": "dipstick"},
    {"key": "nitritos",          "label": "Nitritos",       "reference": "Negativo",
     "type": "bool", "positive_text": "Positivo", "negative_text": "Negativo"},
    {"key": "glucosa",           "label": "Glucosa",        "reference": "Negativo",          "type": "dipstick"},
    {"key": "cetonas",           "label": "Cetonas",        "reference": "Negativo",          "type": "dipstick"},
    {"key": "leucocitos_quimico","label": "Leucocitos",     "reference": "Negativo",          "type": "dipstick"},
    {"key": "acido_ascorbico",   "label": "Ácido ascórbico","reference": "Negativo",          "type": "dipstick", "optional": True},
    {"key": "sangre",            "label": "Sangre",         "reference": "Negativo",          "type": "dipstick"},
    {"type": "section", "label": "Sedimento urinario"},
    {"key": "celulas_epiteliales","label": "Células epiteliales/c", "reference": "0-5 /campo"},
    {"key": "leucocitos_campo",  "label": "Leucocitos/c",   "reference": "0-5 /campo (mujeres hasta 10)"},
    {"key": "hematies_campo",    "label": "Hematíes/c",     "reference": "0-2 /campo"},
    {"key": "cristales",         "label": "Cristales/c",    "reference": "No se observan", "optional": True,
     "quick_negative": "-"},
    {"key": "cilindros",         "label": "Cilindros/c",    "reference": "0-2 cilindros hialinos/campo"},
    {"key": "otros_hallazgos",   "label": "Otros hallazgos","type": "text_area", "optional": True,
     "quick_negative": "-"}
]

_COPRO_CONSISTENCIA = ["Formada", "Blanda", "Semilíquida", "Líquida", "Mucosa", "Pastosa"]
_COPRO_COLOR = ["Pardo amarillento", "Amarillo", "Verde", "Negro", "Rojo / sanguinolento", "Blanquecino / acólico"]

COPRO_DIRECT_FIELDS = [
    {"type": "section", "label": "Evaluación macroscópica"},
    {"key": "consistencia", "label": "Consistencia", "reference": "Formada; lactantes semiformada",
     "type": "choice", "choices": _COPRO_CONSISTENCIA},
    {"key": "color", "label": "Color", "reference": "Pardo amarillento", "optional": True,
     "type": "choice", "choices": _COPRO_COLOR},
    {"key": "moco", "label": "Moco", "type": "choice",
     "choices": ["Ausente", "Escaso", "Moderado", "Abundante"], "reference": "Ausente o escaso"},
    {"key": "sangre_macro", "label": "Sangre macroscópica", "type": "choice",
     "choices": ["Ausente", "Presente"], "reference": "Ausente", "optional": True},
    {"type": "section", "label": "Evaluación microscópica"},
    {"key": "leucocitos", "label": "Leucocitos/c", "reference": "0-2 /campo"},
    {"key": "hematies", "label": "Hematíes/c", "reference": "0-1 /campo"},
    {"key": "parasitos", "label": "Parásitos / quistes / huevos", "type": "text_area",
     "reference": "No se observan", "optional": True,
     "quick_negative": "No se observan parásitos, quistes ni huevos",
     "placeholder": "Ej. Quistes de Giardia lamblia, huevos de Ascaris lumbricoides"},
    {"key": "levaduras",  "label": "Levaduras",  "reference": "Ausentes o escasas", "optional": True,
     "quick_negative": "Ausentes"},
    {"key": "grasas",     "label": "Grasas",     "reference": "Ausentes", "optional": True,
     "quick_negative": "Ausentes"},
    {"key": "reaccion_inflamatoria", "label": "Reacción inflamatoria", "optional": True},
    {"key": "metodo", "label": "Método", "type": "choice",
     "choices": ["Directo", "Concentrado", "Serial"], "reference": "Registrar técnica aplicada"},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

COPRO_CONCENT_FIELDS = [
    {"type": "section", "label": "Procedimiento"},
    {"key": "metodo", "label": "Método", "type": "choice",
     "choices": ["Concentración", "Flotación", "Sedimentación"], "reference": "Indique técnica aplicada"},
    {"type": "section", "label": "Hallazgos"},
    {"key": "parasitos", "label": "Parásitos observados", "type": "text_area",
     "reference": "No se observan", "optional": True},
    {"key": "quistes", "label": "Quistes / huevos", "reference": "No se observan", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

GRAM_FIELDS = [
    {"type": "section", "label": "Examen directo"},
    {"key": "directo_celulas", "label": "Células/c", "reference": "Escasas células epiteliales", "optional": True},
    {"key": "directo_leucocitos", "label": "Leucocitos/c", "reference": "0-10 /campo"},
    {"key": "directo_hematies", "label": "Hematíes/c", "reference": "0-1 /campo", "optional": True},
    {"key": "directo_germenes", "label": "Gérmenes", "reference": "Flora bacteriana escasa", "optional": True},
    {"type": "section", "label": "Coloración de Gram"},
    {"key": "gram_celulas", "label": "Células/c", "reference": "Escasas células epiteliales", "optional": True},
    {"key": "gram_leucocitos", "label": "Leucocitos/c", "reference": "0-10 /campo"},
    {"key": "gram_bacilos_doderlein", "label": "Bacilos de Döderlein", "reference": "Abundantes"},
    {"key": "gram_bacterias", "label": "Bacterias", "reference": "Flora mixta escasa", "optional": True},
    {"key": "gram_celulas_clue", "label": "Células clue", "reference": "Ausentes", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

REACTION_FIELDS = [
    {"key": "leucocitos_pmn", "label": "Leucocitos PMN/c", "reference": "0-1 /campo"},
    {"key": "leucocitos_mmn", "label": "Leucocitos MMN/c", "reference": "0-1 /campo"},
    {"key": "moco", "label": "Moco", "type": "choice",
     "choices": ["Ausente", "Escaso", "Moderado", "Abundante"], "reference": "Ausente o escaso", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

SEDIMENTO_FIELDS = [
    {"key": "celulas_epiteliales", "label": "Células epiteliales/c", "reference": "0-5 /campo"},
    {"key": "leucocitos_campo", "label": "Leucocitos/c", "reference": "0-5 /campo"},
    {"key": "hematies_campo", "label": "Hematíes/c", "reference": "0-2 /campo"},
    {"key": "bacterias", "label": "Bacterias", "reference": "Ausentes o escasas", "optional": True},
    {"key": "cristales", "label": "Cristales", "reference": "No se observan", "optional": True},
    {"key": "cilindros", "label": "Cilindros", "reference": "0-2 hialinos/campo", "optional": True},
    {"key": "otros_hallazgos", "label": "Otros hallazgos", "type": "text_area", "optional": True}
]

SECRECION_VAGINAL_FIELDS = [
    {"type": "section", "label": "Evaluación clínica"},
    {"key": "ph", "label": "pH vaginal", "reference": "Mujer fértil: 3.8-4.5 | Postmenopáusica: hasta 5.0",
     "placeholder": "Ej. 4.2"},
    {"key": "aspecto", "label": "Aspecto", "reference": "Homogéneo, blanco lechoso", "optional": True},
    {"key": "olor", "label": "Olor", "reference": "Sin olor fétido", "optional": True},
    {"type": "section", "label": "Test de aminas"},
    {"key": "test_aminas", "label": "Test de aminas", "type": "bool",
     "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
    {"type": "section", "label": "Observación en fresco"},
    {"key": "celulas_epiteliales", "label": "Células epiteliales/campo", "reference": "Escasas", "optional": True},
    {"key": "leucocitos", "label": "Leucocitos/campo", "reference": "<10/campo de gran aumento"},
    {"key": "hematies", "label": "Hematíes/campo", "reference": "0-1/campo", "optional": True},
    {"key": "trichomonas", "label": "Trichomonas vaginalis", "reference": "No se observan", "optional": True,
     "quick_negative": "No se observan"},
    {"key": "levaduras", "label": "Levaduras / blastosporas", "reference": "No se observan", "optional": True,
     "quick_negative": "No se observan"},
    {"key": "otros_fresco", "label": "Otros hallazgos (fresco)", "optional": True},
    {"type": "section", "label": "Coloración de Gram"},
    {"key": "puntaje_nugent", "label": "Puntaje de Nugent",
     "reference": "0-3 flora normal | 4-6 flora intermedia | 7-10 vaginosis"},
    {"key": "celulas_clue", "label": "Células clue", "reference": "Ausentes"},
    {"key": "bacilos_doderlein", "label": "Bacilos de Döderlein", "reference": "Abundantes"},
    {"key": "cocos_gram", "label": "Cocos / bacterias Gram variables", "optional": True},
    {"key": "leucocitos_gram", "label": "Leucocitos/campo (Gram)", "reference": "0-5/campo", "optional": True},
    {"key": "otros_gram", "label": "Otros gérmenes (Gram)", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

SECRECION_GENERAL_FIELDS = [
    {"type": "section", "label": "Datos de la muestra"},
    {"key": "tipo_secrecion", "label": "Tipo de secreción", "type": "choice",
     "choices": ["Cervical", "Uretral", "Ocular", "Nasofaríngea", "Otorrinolaringológica", "Rectal", "Cutánea", "Otra"]},
    {"key": "aspecto", "label": "Aspecto", "reference": "Transparente o mucoso", "optional": True},
    {"key": "olor", "label": "Olor", "reference": "Sin olor fétido", "optional": True},
    {"type": "section", "label": "Examen directo"},
    {"key": "celulas", "label": "Células epiteliales/campo", "reference": "Escasas", "optional": True},
    {"key": "leucocitos", "label": "Leucocitos/campo", "reference": "<5/campo en secreciones no purulentas"},
    {"key": "eritrocitos", "label": "Hematíes/campo", "reference": "0-1 /campo", "optional": True},
    {"key": "flora", "label": "Flora bacteriana", "reference": "Flora mixta escasa", "optional": True},
    {"key": "levaduras", "label": "Levaduras", "reference": "No se observan", "optional": True},
    {"key": "parasitos", "label": "Parásitos", "reference": "No se observan", "optional": True},
    {"type": "section", "label": "Gram (si aplica)"},
    {"key": "gram_leucocitos", "label": "Leucocitos/campo", "reference": "0-5/campo", "optional": True},
    {"key": "gram_microorganismos", "label": "Microorganismos observados", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

CONST_CORPUSCULAR_FIELDS = [
    {"key": "vcm", "label": "VCM", "unit": "fL",
     "reference": "RN: 95-120 | Niños: 70-86 | Adultos: 80-96", "placeholder": "Ej. 88"},
    {"key": "hcm", "label": "HCM", "unit": "pg",
     "reference": "RN: 31-37 | Niños: 24-32 | Adultos: 27-33", "placeholder": "Ej. 29"},
    {"key": "chcm", "label": "CHCM", "unit": "g/dL",
     "reference": "Niños y adultos: 32-36 g/dL", "placeholder": "Ej. 33"},
    {"key": "rdw", "label": "RDW", "unit": "%",
     "reference": "11.5-14.5 %", "placeholder": "Ej. 13.2"}
]

TOLERANCIA_GLUCO_FIELDS = [
    {"key": "glucosa_ayunas", "label": "Glucosa en ayunas", "unit": "mg/dL",
     "reference": "Normal <100 mg/dL | Gestante <95 mg/dL", "placeholder": "Ej. 92"},
    {"key": "glucosa_60", "label": "Glucosa 60 min", "unit": "mg/dL",
     "reference": "Normal <180 mg/dL", "placeholder": "Ej. 155"},
    {"key": "glucosa_120", "label": "Glucosa 120 min", "unit": "mg/dL",
     "reference": "Normal <140 mg/dL | Gestante <153 mg/dL", "placeholder": "Ej. 132"},
    {"key": "glucosa_180", "label": "Glucosa 180 min", "unit": "mg/dL",
     "reference": "<140 mg/dL", "optional": True, "placeholder": "Ej. 124"}
]

GASES_ARTERIALES_FIELDS = [
    {"key": "ph", "label": "pH", "reference": "RN: 7.30-7.40 | Adultos: 7.35-7.45", "placeholder": "Ej. 7.39"},
    {"key": "pco2", "label": "pCO₂", "unit": "mmHg",
     "reference": "RN: 27-40 | Adultos: 35-45", "placeholder": "Ej. 40"},
    {"key": "po2", "label": "pO₂", "unit": "mmHg",
     "reference": "RN: 50-70 | Adultos: 80-100", "placeholder": "Ej. 92"},
    {"key": "hco3", "label": "HCO₃⁻", "unit": "mmol/L",
     "reference": "RN: 20-26 | Adultos: 22-26", "placeholder": "Ej. 24"},
    {"key": "exceso_base", "label": "Exceso de bases", "unit": "mmol/L",
     "reference": "-2 a +2", "placeholder": "Ej. -1"},
    {"key": "saturacion", "label": "SatO₂", "unit": "%",
     "reference": "RN: 90-95 % | Adultos: 95-100 %", "placeholder": "Ej. 97"},
    {"key": "lactato", "label": "Lactato", "unit": "mmol/L",
     "reference": "0.5-1.6 mmol/L", "optional": True, "placeholder": "Ej. 1.1"}
]

UROCULTIVO_FIELDS = [
    {"key": "recuento", "label": "Recuento bacteriano", "unit": "UFC/mL",
     "reference": "<10^5 UFC/mL: sin significancia clínica"},
    {"key": "microorganismo", "label": "Microorganismo aislado",
     "reference": "Sin desarrollo significativo", "optional": True},
    {"key": "interpretacion", "label": "Interpretación", "type": "text_area",
     "optional": True, "placeholder": "Sensibilidad recomendada"}
]

COPROCULTIVO_FIELDS = [
    {"key": "microorganismos", "label": "Microorganismos aislados",
     "reference": "No se aíslan patógenos entéricos", "optional": True},
    {"key": "resultado", "label": "Resultado",
     "reference": "Flora intestinal normal", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

EXAMEN_HONGOS_FIELDS = [
    {"type": "section", "label": "Examen directo con KOH"},
    {"key": "hifas", "label": "Hifas", "reference": "No se observan", "optional": True},
    {"key": "levaduras", "label": "Levaduras / blastosporas", "reference": "No se observan", "optional": True},
    {"key": "artroconidios", "label": "Artroconidios", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

CONTENIDO_GASTRICO_FIELDS = [
    {"key": "volumen", "label": "Volumen residual", "unit": "mL",
     "reference": "<20 mL", "placeholder": "Ej. 12"},
    {"key": "ph", "label": "pH", "reference": "1.0-4.0", "placeholder": "Ej. 2.5"},
    {"key": "aspecto", "label": "Aspecto",
     "reference": "Translúcido o ligeramente verdoso", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

GRUPO_RH_FIELDS = [
    {"key": "grupo_abo", "label": "Grupo ABO", "type": "choice",
     "choices": ["O", "A", "B", "AB"], "reference": "Reportar fenotipo ABO"},
    {"key": "factor_rh", "label": "Factor Rh", "type": "choice",
     "choices": ["Positivo", "Negativo"], "reference": "Factor Rh(D)"},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

WIDAL_FIELDS = [
    {"key": "antigeno_o", "label": "Antígeno O", "reference": "Negativo: <1:80"},
    {"key": "antigeno_h", "label": "Antígeno H", "reference": "Negativo: <1:160"},
    {"key": "antigeno_ah", "label": "Antígeno AH", "reference": "Negativo: <1:80", "optional": True},
    {"key": "antigeno_bh", "label": "Antígeno BH", "reference": "Negativo: <1:80", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]


# ---------------------------------------------------------------------------
# Funciones constructoras de plantillas
# ---------------------------------------------------------------------------

def build_bool_observation_template(positive_text="Positivo", negative_text="Negativo",
                                     reference_text="Negativo"):
    return {
        "fields": [
            {"key": "resultado", "label": "Resultado", "type": "bool",
             "positive_text": positive_text, "negative_text": negative_text,
             "reference": reference_text},
            {"key": "observaciones", "label": "Observaciones", "type": "text_area",
             "optional": True, "placeholder": "Observaciones (opcional)"}
        ]
    }


def build_parasitologico_seriado_template(sample_count=3):
    _CONS = ["Formada", "Blanda", "Semilíquida", "Líquida", "Mucosa", "Pastosa"]
    _COL  = ["Pardo amarillento", "Amarillo", "Verde", "Negro", "Rojo / sanguinolento", "Blanquecino"]
    fields = []
    for idx in range(1, sample_count + 1):
        fields.append({"type": "section", "label": f"Muestra {idx}"})
        fields.append({"key": f"consistencia_{idx}", "label": "Consistencia", "type": "choice",
                        "choices": _CONS, "optional": True})
        fields.append({"key": f"color_{idx}",        "label": "Color",         "type": "choice",
                        "choices": _COL, "optional": True})
        fields.append({"key": f"hallazgos_{idx}",    "label": "Hallazgos parasitológicos",
                        "type": "text_area", "optional": True,
                        "quick_negative": "No se observan parásitos ni huevos",
                        "placeholder": "Ej. Quistes de Giardia lamblia, huevos de Ascaris"})
    fields.append({"key": "observaciones", "label": "Observaciones generales",
                    "type": "text_area", "optional": True})
    return {"fields": fields}


def build_multi_sample_bool_template(sample_count=3, positive_text="Positivo",
                                      negative_text="Negativo", reference_text="Negativo",
                                      sample_label_prefix="Muestra"):
    fields = []
    for idx in range(1, sample_count + 1):
        fields.append({"type": "section", "label": f"{sample_label_prefix} {idx}"})
        fields.append({
            "key": f"muestra_{idx}",
            "label": f"Resultado {sample_label_prefix.lower()} {idx}",
            "type": "bool",
            "positive_text": positive_text,
            "negative_text": negative_text,
            "reference": reference_text,
        })
    fields.append({"key": "observaciones", "label": "Observaciones", "type": "text_area",
                   "optional": True, "placeholder": "Observaciones generales"})
    return {"fields": fields}


def build_single_value_template(key, label, unit=None, reference=None, placeholder=None,
                                 helper=None, optional=False, field_type="line", choices=None):
    field = {"key": key, "label": label}
    if unit:
        field["unit"] = unit
    if reference:
        field["reference"] = reference
    if placeholder:
        field["placeholder"] = placeholder
    if helper:
        field["helper"] = helper
    if optional:
        field["optional"] = True
    if field_type != "line":
        field["type"] = field_type
    if choices:
        field["choices"] = choices
    return {"fields": [field]}


def build_sample_tracking_template(reference_note):
    return {
        "fields": [
            {"key": "fecha_toma", "label": "Fecha de toma",
             "placeholder": "DD/MM/AAAA", "reference": "Coincide con el registro de 'F. muestra'"},
            {"key": "hora_toma", "label": "Hora de toma/envío",
             "placeholder": "HH:MM", "reference": "Registrar hora oficial de la toma"},
            {"key": "destino", "label": "Destino / referencia",
             "optional": True, "placeholder": "Ej. Laboratorio de referencia"},
            {"key": "observaciones", "label": "Observaciones", "type": "text_area",
             "optional": True, "reference": reference_note}
        ]
    }


# ---------------------------------------------------------------------------
# TEST_TEMPLATES principal
# ---------------------------------------------------------------------------

TEST_TEMPLATES = {
    "Hemograma manual": {
        "fields": copy.deepcopy(HEMOGRAM_BASE_FIELDS),
        "auto_calculations": [{"source": "hematocrito", "target": "hemoglobina",
                                "operation": "divide", "operand": 3.03, "decimals": 2,
                                "description": "Hb = Hto / 3.03 (cálculo automático)"}]
    },
    "Hemograma automatizado": {
        "fields": copy.deepcopy(HEMOGRAM_BASE_FIELDS),
        "auto_calculations": [{"source": "hematocrito", "target": "hemoglobina",
                                "operation": "divide", "operand": 3.03, "decimals": 2,
                                "description": "Hb = Hto / 3.03 (cálculo automático)"}]
    },
    "Examen completo de orina": {"fields": copy.deepcopy(URINE_BASE_FIELDS)},
    "Sedimento urinario": {"fields": copy.deepcopy(SEDIMENTO_FIELDS)},
    "Examen coprológico (directo)": {"fields": copy.deepcopy(COPRO_DIRECT_FIELDS)},
    "Examen coprológico (concentración)": {"fields": copy.deepcopy(COPRO_CONCENT_FIELDS)},
    "Coloración de Gram": {"fields": copy.deepcopy(GRAM_FIELDS)},
    "Reacción inflamatoria": {"fields": copy.deepcopy(REACTION_FIELDS)},
    "Test de aminas": {
        "fields": [
            {"key": "resultado", "label": "Resultado", "type": "bool",
             "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
            {"key": "olor_caracteristico", "label": "Olor característico", "optional": True},
            {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
        ]
    },
    "Test de Helecho": {
        "fields": [
            {"key": "resultado", "label": "Resultado", "type": "bool",
             "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Patrón negativo"},
            {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
        ]
    },
    "Secreción vaginal": {"fields": copy.deepcopy(SECRECION_VAGINAL_FIELDS)},
    "Secreción (otros sitios)": {"fields": copy.deepcopy(SECRECION_GENERAL_FIELDS)},
    "Constantes corpusculares": {"fields": copy.deepcopy(CONST_CORPUSCULAR_FIELDS)},
    "Tolerancia a la glucosa": {"fields": copy.deepcopy(TOLERANCIA_GLUCO_FIELDS)},
    "Gases arteriales": {"fields": copy.deepcopy(GASES_ARTERIALES_FIELDS)},
    "Urocultivo": {"fields": copy.deepcopy(UROCULTIVO_FIELDS)},
    "Coprocultivo": {"fields": copy.deepcopy(COPROCULTIVO_FIELDS)},
    "Examen directo (hongos/KOH)": {"fields": copy.deepcopy(EXAMEN_HONGOS_FIELDS)},
    "Contenido gástrico (en RN)": {"fields": copy.deepcopy(CONTENIDO_GASTRICO_FIELDS)},
    "Grupo sanguíneo y Factor Rh": {"fields": copy.deepcopy(GRUPO_RH_FIELDS)},
    "Reacción de Widal": {"fields": copy.deepcopy(WIDAL_FIELDS)}
}

# Simple numeric tests
SIMPLE_NUMERIC_TESTS = {
    "Hemoglobina": {"key": "hemoglobina", "label": "Hemoglobina", "unit": "g/dL",
                    "reference": "RN: 14.0-24.0 g/dL\n1-12 meses: 10.0-12.5 g/dL\nNiños 1-12 años: 11.5-15.5 g/dL\nMujeres adultas: 12.0-16.0 g/dL\nHombres adultos: 13.5-17.5 g/dL\nGestantes (2°-3° trim): ≥11.0 g/dL",
                    "placeholder": "Ej. 13.8"},
    "Recuento de leucocitos": {"key": "leucocitos_totales", "label": "Leucocitos", "unit": "/µL",
                                "reference": "RN: 9 000-30 000 /µL\nNiños 1-6 años: 5 000-15 500 /µL\nAdultos: 4 500-11 000 /µL",
                                "placeholder": "Ej. 8 200"},
    "Recuento de hematíes": {"key": "eritrocitos_totales", "label": "Recuento de hematíes",
                              "unit": "millones/µL",
                              "reference": "RN: 4.1-6.1 millones/µL\nNiños 1-10 años: 3.9-5.3 millones/µL\nHombres adultos: 4.5-6.0 millones/µL\nMujeres adultas: 4.0-5.4 millones/µL",
                              "placeholder": "Ej. 4.7"},
    "Recuento de plaquetas": {"key": "plaquetas_totales", "label": "Plaquetas", "unit": "/µL",
                               "reference": "RN y niños: 150 000-450 000 /µL | Adultos: 150 000-400 000 /µL",
                               "placeholder": "Ej. 210 000"},
    "Tiempo de coagulación": {"key": "tiempo_coagulacion", "label": "Tiempo de coagulación",
                               "unit": "min", "reference": "Adultos: 8-12 min (Lee-White) | Niños: 6-11 min",
                               "placeholder": "Ej. 9"},
    "Tiempo de sangría": {"key": "tiempo_sangria", "label": "Tiempo de sangría",
                           "unit": "min", "reference": "Mujeres: 2-7 min | Hombres: 2-6 min",
                           "placeholder": "Ej. 3"},
    "Velocidad de sedimentación globular (VSG)": {"key": "vsg", "label": "VSG", "unit": "mm/h",
                                                   "reference": "Hombres <50 a: 0-15 mm/h | Hombres ≥50 a: 0-20 mm/h\nMujeres <50 a: 0-20 mm/h | Mujeres ≥50 a: 0-30 mm/h\nNiños: 0-10 mm/h",
                                                   "placeholder": "Ej. 12"},
    "Glucosa": {"key": "glucosa", "label": "Glucosa en ayunas", "unit": "mg/dL",
                "reference": "Niños y adultos: 70-99 mg/dL | Gestantes: <95 mg/dL",
                "placeholder": "Ej. 88"},
    "Glucosa postprandial": {"key": "glucosa_postprandial", "label": "Glucosa 2 h postprandial",
                              "unit": "mg/dL",
                              "reference": "Niños y adultos: <140 mg/dL | Gestantes: <120 mg/dL",
                              "placeholder": "Ej. 128"},
    "Colesterol Total": {"key": "colesterol_total", "label": "Colesterol total", "unit": "mg/dL",
                          "reference": "Adultos: <200 mg/dL (deseable) | Niños: <170 mg/dL",
                          "placeholder": "Ej. 185"},
    "Triglicéridos": {"key": "trigliceridos", "label": "Triglicéridos", "unit": "mg/dL",
                      "reference": "Niños <9 a: <100 mg/dL | 10-19 a: <130 mg/dL | Adultos: <150 mg/dL",
                      "placeholder": "Ej. 135"},
    "Colesterol HDL": {"key": "hdl", "label": "Colesterol HDL", "unit": "mg/dL",
                        "reference": "Varones: ≥40 mg/dL | Mujeres: ≥50 mg/dL | Niños: ≥45 mg/dL",
                        "placeholder": "Ej. 52"},
    "Colesterol LDL": {"key": "ldl", "label": "Colesterol LDL", "unit": "mg/dL",
                        "reference": "Niños: <110 mg/dL | Adultos: <100 mg/dL (óptimo)",
                        "placeholder": "Ej. 98"},
    "Transaminasa Glutámico Oxalacética (TGO)": {"key": "tgo", "label": "TGO (AST)", "unit": "U/L",
                                                  "reference": "RN: <75 U/L | Niños: <50 U/L | Adultos: 10-40 U/L",
                                                  "placeholder": "Ej. 28"},
    "Transaminasa Glutámico Pirúvico (TGP)": {"key": "tgp", "label": "TGP (ALT)", "unit": "U/L",
                                               "reference": "RN: <60 U/L | Niños: <40 U/L | Adultos: 7-45 U/L",
                                               "placeholder": "Ej. 32"},
    "Bilirrubina Total": {"key": "bilirrubina_total", "label": "Bilirrubina total", "unit": "mg/dL",
                           "reference": "Adultos: 0.3-1.2 mg/dL | RN 24 h: <6 mg/dL | RN 48 h: <10 mg/dL",
                           "placeholder": "Ej. 0.8"},
    "Bilirrubina Directa": {"key": "bilirrubina_directa", "label": "Bilirrubina directa",
                             "unit": "mg/dL",
                             "reference": "Adultos: 0.0-0.3 mg/dL | RN: <0.5 mg/dL",
                             "placeholder": "Ej. 0.2"},
    "Úrea": {"key": "urea", "label": "Úrea", "unit": "mg/dL",
              "reference": "RN: 3-12 mg/dL | Niños: 5-18 mg/dL | Adultos: 15-40 mg/dL",
              "placeholder": "Ej. 28"},
    "Creatinina": {"key": "creatinina", "label": "Creatinina", "unit": "mg/dL",
                   "reference": "RN: 0.3-1.0 mg/dL | Niños: 0.2-0.7 mg/dL | Mujeres: 0.5-0.9 mg/dL | Hombres: 0.7-1.3 mg/dL",
                   "placeholder": "Ej. 0.9"},
    "Proteína de 24 horas": {"key": "proteina_24h", "label": "Proteína 24 h", "unit": "mg/24h",
                              "reference": "Adultos: <150 mg/24h | Gestantes: <300 mg/24h",
                              "placeholder": "Ej. 120"},
    "Fosfatasa alcalina": {"key": "fosfatasa_alcalina", "label": "Fosfatasa alcalina", "unit": "U/L",
                            "reference": "Niños: 150-380 U/L | Adultos: 44-147 U/L | Gestantes 3er trim: <240 U/L",
                            "placeholder": "Ej. 110"},
    "Ácido úrico": {"key": "acido_urico", "label": "Ácido úrico", "unit": "mg/dL",
                    "reference": "Niños: 2.0-5.5 mg/dL | Mujeres: 2.4-6.0 mg/dL | Hombres: 3.4-7.0 mg/dL",
                    "placeholder": "Ej. 4.8"},
    "Proteínas Totales": {"key": "proteinas_totales", "label": "Proteínas totales", "unit": "g/dL",
                           "reference": "RN: 4.6-7.4 g/dL | Niños: 6.0-8.0 g/dL | Adultos: 6.4-8.3 g/dL",
                           "placeholder": "Ej. 7.1"},
    "Albúmina": {"key": "albumina", "label": "Albúmina", "unit": "g/dL",
                  "reference": "RN: 2.8-4.4 g/dL | Niños: 3.5-5.5 g/dL | Adultos: 3.5-5.2 g/dL | Gestantes: 2.8-4.5 g/dL",
                  "placeholder": "Ej. 4.0"},
    "Amilasa": {"key": "amilasa", "label": "Amilasa", "unit": "U/L",
                "reference": "RN: 6-65 U/L | Niños: 30-90 U/L | Adultos: 28-100 U/L",
                "placeholder": "Ej. 62"},
    "Lipasa": {"key": "lipasa", "label": "Lipasa", "unit": "U/L",
               "reference": "RN: 6-51 U/L | Niños: 10-140 U/L | Adultos: 13-60 U/L",
               "placeholder": "Ej. 45"},
    "Gamma Glutamil transferasa (GGT)": {"key": "ggt", "label": "GGT", "unit": "U/L",
                                          "reference": "RN: 12-73 U/L | Niños: 12-43 U/L | Mujeres: 7-32 U/L | Hombres: 10-50 U/L",
                                          "placeholder": "Ej. 24"},
    "Globulina": {"key": "globulina", "label": "Globulina", "unit": "g/dL",
                  "reference": "Niños: 2.0-3.5 g/dL | Adultos: 2.3-3.5 g/dL",
                  "placeholder": "Ej. 2.7"},
    "Ferritina": {"key": "ferritina", "label": "Ferritina", "unit": "ng/mL",
                  "reference": "RN: 25-200 ng/mL\nNiños 1-5 a: 10-60 ng/mL | Niños 6-15 a: 7-140 ng/mL\nHombres adultos: 30-400 ng/mL\nMujeres adultas: 15-150 ng/mL\nGestantes: 1T 10-150 | 2T 6-74 | 3T 2-40 ng/mL",
                  "placeholder": "Ej. 55"},
    "Hemoglobina glicosilada": {"key": "hba1c", "label": "HbA1c", "unit": "%",
                                 "reference": "Normal <5.7 % | Prediabetes 5.7-6.4 % | Diabetes ≥6.5 % | Gestantes con diabetes: meta <6.0 %",
                                 "placeholder": "Ej. 5.6"},
    "Factor reumatoideo": {"key": "factor_reumatoideo", "label": "Factor reumatoideo", "unit": "UI/mL",
                            "reference": "Adultos: <14 UI/mL | Niños: <10 UI/mL",
                            "placeholder": "Ej. 8"},
    "PCR cuantitativo": {"key": "proteina_c", "label": "Proteína C reactiva", "unit": "mg/L",
                          "reference": "Adultos: <5 mg/L | RN: <10 mg/L",
                          "placeholder": "Ej. 3.2"},
    "ASO": {"key": "aso", "label": "Antiestreptolisinas (ASO)", "unit": "UI/mL",
             "reference": "Adultos: <200 UI/mL | Niños: <250 UI/mL",
             "placeholder": "Ej. 120"},
    "PSA (ELISA)": {"key": "psa", "label": "PSA total", "unit": "ng/mL",
                    "reference": "40-49 a: <2.5 | 50-59 a: <3.5 | 60-69 a: <4.5 | ≥70 a: <6.5 ng/mL",
                    "placeholder": "Ej. 2.1"}
}

SIMPLE_TEXTAREA_TESTS = {
    "Lámina periférica": {"key": "descripcion", "label": "Descripción morfológica",
                           "reference": "Eritrocitos normocíticos normocrómicos, leucocitos sin alteraciones, plaquetas adecuadas",
                           "placeholder": "Describa morfología observada"},
    "Identificación bioquímica": {"key": "panel_bioquimico", "label": "Perfil bioquímico",
                                   "reference": "Describa pruebas realizadas según manual CLSI vigente",
                                   "placeholder": "Ej. Enterobacter cloacae, panel API 20E"},
    "Antibiograma": {"key": "antibiograma", "label": "Antibiograma",
                      "reference": "Interpretar según guías CLSI/EUCAST",
                      "placeholder": "Antibiótico - Interpretación (S/I/R)"},
    "BK (resultado referencial)": {"key": "resultado", "label": "Resultado BK",
                                    "reference": "Describa gradación (Negativo, 1+, 2+, 3+) u observaciones del informe referencial",
                                    "placeholder": "Ej. Negativo / BK 1+"}
}

BOOL_TESTS = {
    "Células LE": {"positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
    "Gota gruesa": {"positive_text": "Hemoparásitos", "negative_text": "No se observan",
                     "reference": "No se observan Plasmodium spp."},
    "Frotis para Leishmaniasis": {"positive_text": "Leishmania sp.", "negative_text": "No se observan",
                                   "reference": "No se observan amastigotes"},
    "Cultivo de Neisseria gonorrhoeae": {"positive_text": "Aislamiento positivo",
                                          "negative_text": "Sin aislamiento",
                                          "reference": "No se aisla N. gonorrhoeae"},
    "Cultivo de Campylobacter spp.": {"positive_text": "Aislamiento positivo",
                                       "negative_text": "Sin aislamiento",
                                       "reference": "No se aisla Campylobacter spp."},
    "Frotis para Bartonella": {"positive_text": "Cuerpos de Bartonella",
                                "negative_text": "No se observan", "reference": "Negativo"},
    "Ácido sulfasalicílico al 3%": {"positive_text": "Positivo", "negative_text": "Negativo",
                                     "reference": "Negativo (proteínas ≤30 mg/dL)"},
    "Antígeno de superficie Hepatitis B (HBsAg)": {"positive_text": "Reactivo",
                                                     "negative_text": "No reactivo",
                                                     "reference": "No reactivo"},
    "Reagina plasmática rápida (RPR)": {"positive_text": "Reactivo", "negative_text": "No reactivo",
                                         "reference": "No reactivo"},
    "Proteína C reactiva (PCR) - Látex": {"positive_text": "Reactivo", "negative_text": "No reactivo",
                                           "reference": "No reactivo"},
    "BHCG (Prueba de embarazo en sangre)": {"positive_text": "Positivo", "negative_text": "Negativo",
                                             "reference": "Negativo (<5 mUI/mL)"},
    "Serología Dengue (referencial)": {"positive_text": "Positivo", "negative_text": "Negativo",
                                        "reference": "Negativo"},
    "Serología Leptospira (referencial)": {"positive_text": "Positivo", "negative_text": "Negativo",
                                            "reference": "Negativo"},
    "Serología Leishmaniasis (referencial)": {"positive_text": "Positivo", "negative_text": "Negativo",
                                               "reference": "Negativo"}
}

SAMPLE_TEMPLATES = {
    "Leishmaniasis (toma de muestra)": build_sample_tracking_template(
        "Registro de remisión según NTS para vigilancia de leishmaniasis"),
    "Dengue (toma de muestra)": build_sample_tracking_template("Mantener cadena de frío 2-8 °C"),
    "Leptospirosis (toma de muestra)": build_sample_tracking_template(
        "Documentar envío a laboratorio de referencia"),
    "Covid-19 (hisopado nasofaríngeo)": build_sample_tracking_template(
        "Remitir en medio viral a 4 °C"),
    "Carga viral de VIH / Recuento de CD4": build_sample_tracking_template(
        "Registrar código de envío y hora"),
    "CLIA (PSA, Perfil tiroideo, etc.)": build_sample_tracking_template(
        "Sin valores de referencia: registro de muestra derivada"),
    "Sangre venosa/arterial (examen de proceso)": build_sample_tracking_template(
        "Control de cadena de custodia (sin valores analíticos)"),
    "Covid-19 (Prueba antigénica)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Covid-19 (Prueba serológica)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Dengue NS1/IgM/IgG (Prueba rápida)": {
        "fields": [
            {"key": "ns1", "label": "NS1",  "type": "bool", "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
            {"key": "igm", "label": "IgM",  "type": "bool", "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
            {"key": "igg", "label": "IgG",  "type": "bool", "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
            {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True},
        ]
    },
    "Hepatitis A (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Hepatitis B (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "PSA (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Sangre oculta en heces (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Helicobacter pylori (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "VIH (Prueba rápida)": build_bool_observation_template("Reactivo", "No reactivo", "No reactivo"),
    "Sífilis (Prueba rápida)": build_bool_observation_template("Reactivo", "No reactivo", "No reactivo"),
    "VIH/Sífilis (Prueba combinada)": {
        "fields": [
            {"key": "vih",     "label": "VIH",    "type": "bool", "positive_text": "Reactivo", "negative_text": "No reactivo", "reference": "No reactivo"},
            {"key": "sifilis", "label": "Sífilis", "type": "bool", "positive_text": "Reactivo", "negative_text": "No reactivo", "reference": "No reactivo"},
            {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True},
        ]
    },
    "BHCG (Prueba de embarazo en sangre)": build_bool_observation_template(
        "Positivo", "Negativo", "Negativo (<5 mUI/mL)")
}

# Agregar SIMPLE_NUMERIC_TESTS al TEST_TEMPLATES
for _test_name, _info in SIMPLE_NUMERIC_TESTS.items():
    TEST_TEMPLATES[_test_name] = build_single_value_template(
        _info["key"], _info.get("label", _test_name),
        unit=_info.get("unit"), reference=_info.get("reference"),
        placeholder=_info.get("placeholder"), helper=_info.get("helper")
    )

# Agregar SIMPLE_TEXTAREA_TESTS
for _test_name, _info in SIMPLE_TEXTAREA_TESTS.items():
    TEST_TEMPLATES[_test_name] = build_single_value_template(
        _info["key"], _info.get("label", _test_name),
        reference=_info.get("reference"), placeholder=_info.get("placeholder"),
        field_type="text_area"
    )

# Agregar BOOL_TESTS
for _test_name, _params in BOOL_TESTS.items():
    TEST_TEMPLATES[_test_name] = build_bool_observation_template(
        _params.get("positive_text", "Positivo"),
        _params.get("negative_text", "Negativo"),
        _params.get("reference", "Negativo")
    )

# Agregar SAMPLE_TEMPLATES
for _test_name, _template in SAMPLE_TEMPLATES.items():
    TEST_TEMPLATES[_test_name] = copy.deepcopy(_template)

# Multi-muestra expandido
TEST_TEMPLATES["Parasitológico seriado"] = build_parasitologico_seriado_template(3)
TEST_TEMPLATES["Test de Graham"] = build_multi_sample_bool_template(
    sample_count=3, positive_text="Huevos presentes", negative_text="No se observan",
    reference_text="Sin huevos de Enterobius vermicularis"
)

# Baciloscopía con cruces y bacilos por campo
TEST_TEMPLATES["Baciloscopía"] = {
    "fields": [
        {"key": "resultado", "label": "Resultado (graduación)", "type": "choice",
         "choices": ["BAAR negativo", "BAAR escasos (1-9 BAAR/100 campos)",
                     "BAAR 1+ (10-99 BAAR/100 campos)", "BAAR 2+ (1-10 BAAR/campo)",
                     "BAAR 3+ (>10 BAAR/campo)", "BAAR 4+ (confluente, >10 BAAR/campo)"],
         "reference": "BAAR negativo"},
        {"key": "bacilos_por_campo", "label": "Promedio BAAR/campo", "optional": True,
         "placeholder": "Ej. 3-5"},
        {"key": "campos_observados", "label": "Campos observados",   "optional": True,
         "placeholder": "Ej. 100"},
        {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True},
    ]
}

# Hematocrito
HEMATOCRIT_BASE_TEMPLATE = build_single_value_template(
    "hematocrito", "Hematocrito", unit="%",
    reference="RN: 44-65 %\nNiños 1-10 a: 35-45 %\nHombres adultos: 40-54 %\nMujeres adultas: 36-47 %\nGestantes (2°-3° trim): 33-43 %",
    placeholder="Ej. 43"
)
TEST_TEMPLATES["Hematocrito"] = copy.deepcopy(HEMATOCRIT_BASE_TEMPLATE)

# Hemoglobina - Hematocrito combo
TEST_TEMPLATES["Hemoglobina - Hematocrito"] = {
    "fields": [
        {"key": "hemoglobina", "label": "Hemoglobina (Hb)", "unit": "g/dL",
         "reference": "RN: 14.0-24.0 g/dL\n1-12 meses: 10.0-12.5 g/dL\nNiños 1-12 años: 11.5-15.5 g/dL\nMujeres adultas: 12.0-16.0 g/dL\nHombres adultos: 13.5-17.5 g/dL\nGestantes (2°-3° trim): ≥11.0 g/dL",
         "placeholder": "Ej. 13.8"},
        {"key": "hematocrito", "label": "Hematocrito (Hto)", "unit": "%",
         "reference": "RN: 44-65 %\nNiños 1-10 a: 35-45 %\nHombres adultos: 40-54 %\nMujeres adultas: 36-47 %\nGestantes (2°-3° trim): 33-43 %",
         "placeholder": "Ej. 43"}
    ],
    "auto_calculations": [{"source": "hematocrito", "target": "hemoglobina",
                            "operation": "divide", "operand": 3.03, "decimals": 2,
                            "description": "Hb estimada = Hto / 3.03 (se puede ajustar manualmente)",
                            "only_if_empty": True}]
}

RAPID_TEST_NAMES = [
    "BHCG (Prueba de embarazo en sangre)", "VIH (Prueba rápida)", "Sífilis (Prueba rápida)",
    "VIH/Sífilis (Prueba combinada)", "Hepatitis A (Prueba rápida)", "Hepatitis B (Prueba rápida)",
    "PSA (Prueba rápida)", "Sangre oculta en heces (Prueba rápida)",
    "Helicobacter pylori (Prueba rápida)", "Covid-19 (Prueba antigénica)",
    "Covid-19 (Prueba serológica)", "Dengue NS1/IgM/IgG (Prueba rápida)"
]
for _rapid_test in RAPID_TEST_NAMES:
    if _rapid_test not in TEST_TEMPLATES:
        TEST_TEMPLATES[_rapid_test] = build_bool_observation_template()


# ---------------------------------------------------------------------------
# Helper público
# ---------------------------------------------------------------------------

def get_template_for_test(test_name: str) -> dict | None:
    """Retorna el template para un examen, o None si no existe."""
    return TEST_TEMPLATES.get(test_name)


def default_sample_type_for_test(test_name: str) -> str:
    """Retorna el tipo de muestra por defecto para un examen."""
    normalized = test_name.lower()
    for key, value in SAMPLE_TYPE_DEFAULTS.items():
        if key in normalized:
            return value
    if "orina" in normalized or "ego" in normalized:
        return "Orina de chorro medio"
    return "Muestra estándar"

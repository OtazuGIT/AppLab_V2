# main_window.py
import copy
import datetime
import inspect
import json
import os
import re
import unicodedata
from collections import OrderedDict
from PyQt5.QtWidgets import (QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
                             QStackedWidget, QTabWidget, QFormLayout, QScrollArea, QGroupBox, QComboBox,
                             QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox, QCheckBox,
                             QDateEdit, QRadioButton, QButtonGroup, QDialog, QDialogButtonBox, QListWidget, QListWidgetItem,
                             QSpinBox, QInputDialog, QAbstractItemView, QGridLayout)
from PyQt5.QtCore import QDate, QDateTime, Qt, QTimer
from PyQt5.QtGui import QColor, QFont
from fpdf import FPDF  # Asegúrese de tener fpdf instalado (pip install fpdf)

LAB_TITLE = "Laboratorio P.S. Iñapari - 002789"

MONTH_NAMES_ES = [
    "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
    "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"
]

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

REGISTRY_ABBREVIATIONS = {
    "hematocrito": "Hto",
    "hematocrito (hto)": "Hto",
    "hemoglobina": "Hb",
    "hemoglobina (hb)": "Hb",
    "hemoglobina - hematocrito": "Hb/Hto",
    "hemoglobina hematocrito": "Hb/Hto",
    "leucocitos": "Leu",
    "leucocitos totales": "Leu",
    "recuento de leucocitos": "Leu",
    "recuento de hematies": "RBC",
    "recuento de hematies (rbc)": "RBC",
    "hematies": "RBC",
    "plaquetas": "Plaq",
    "recuento de plaquetas": "Plaq",
    "plaquetas totales": "Plaq",
    "vcm": "VCM",
    "hcm": "HCM",
    "chcm": "CHCM",
    "rdw": "RDW",
    "segmentados": "Seg",
    "abastonados": "Abast",
    "linfocitos": "Lin",
    "monocitos": "Mon",
    "eosinofilos": "Eo",
    "eosinofilos": "Eo",
    "basofilos": "Bas",
    "mielocitos": "Mielo",
    "metamielocitos": "Meta",
    "otras anormalidades": "Otras",
    "observaciones microscopicas": "Obs mic",
    "observaciones": "Obs",
    "glucosa": "Glu",
    "glucosa en ayunas": "Glu ay",
    "glucosa 2 h postprandial": "Glu 2h",
    "glucosa postprandial": "Glu pp",
    "glucosa 60 min": "Glu60",
    "glucosa 120 min": "Glu120",
    "glucosa 180 min": "Glu180",
    "colesterol total": "ColT",
    "trigliceridos": "Trig",
    "colesterol hdl": "HDL",
    "colesterol ldl": "LDL",
    "transaminasa glutamico oxalacetica (tgo)": "TGO",
    "transaminasa glutamico piruvico (tgp)": "TGP",
    "tgo": "TGO",
    "tgp": "TGP",
    "bilirrubina total": "BilT",
    "bilirrubina directa": "BilD",
    "urea": "Urea",
    "creatinina": "Crea",
    "proteina de 24 horas": "Prot24h",
    "fosfatasa alcalina": "FosfAlc",
    "acido urico": "AcUr",
    "proteinas totales": "ProtTot",
    "albumina": "Alb",
    "amilasa": "Amil",
    "lipasa": "Lip",
    "gamma glutamil transferasa (ggt)": "GGT",
    "ggt": "GGT",
    "globulina": "Glob",
    "ferritina": "Ferr",
    "hemoglobina glicosilada": "HbA1c",
    "factor reumatoideo": "FR",
    "proteina c reactiva": "PCR",
    "resultado": "Res",
    "interpretacion": "Interp",
    "hora de toma/envio": "Hora toma",
    "fecha de toma": "F. toma",
    "fecha_toma": "F. toma",
    "destino / referencia": "Destino",
    "destino": "Destino",
    "observaciones (laboratorio)": "Obs",
    "observaciones adicionales": "Obs",
    "eritrocitos": "RBC",
    "eritrocitos totales": "RBC",
    "leucocitos/c": "Leu/c",
    "hematies/c": "Hto/c",
    "ph": "pH",
    "ph vaginal": "pH",
    "color": "Color",
    "aspecto": "Aspecto",
    "olor": "Olor",
    "densidad": "Dens",
    "protein as": "Prot",
    "proteinas": "Prot",
    "nitritos": "Nit",
    "glucosa (quimico)": "Glu",
    "cetonas": "Cet",
    "urobilinogeno": "Urob",
    "bilirrubina": "Bil",
    "leucocitos quimico": "Leu",
    "leucocitos/campo": "Leu/c",
    "celulas epiteliales/c": "Cel epi",
    "cilindros/c": "Cil",
    "otros hallazgos": "Otros",
    "parasitos": "Par",
    "levaduras": "Lev",
    "moco": "Moco",
    "consistencia": "Cons"
}

LEUCOCYTE_KEYS = [
    "segmentados",
    "abastonados",
    "linfocitos",
    "monocitos",
    "eosinofilos",
    "basofilos",
    "mielocitos",
    "metamielocitos",
]

# Definiciones de plantillas de resultados estructurados por examen
HEMOGRAM_BASE_FIELDS = [
    {
        "key": "hematocrito",
        "label": "Hematocrito (Hto)",
        "unit": "%",
        "reference": (
            "RN: 44-65 %\n"
            "Niños 1-10 a: 35-45 %\n"
            "Hombres adultos: 40-54 %\n"
            "Mujeres adultas: 36-47 %\n"
            "Gestantes (2°-3° trim): 33-43 %"
        ),
        "placeholder": "Ej. 42.5"
    },
    {
        "key": "hemoglobina",
        "label": "Hemoglobina (Hb)",
        "unit": "g/dL",
        "reference": (
            "RN: 14.0-24.0 g/dL\n"
            "1-12 meses: 10.0-12.5 g/dL\n"
            "Niños 1-12 años: 11.5-15.5 g/dL\n"
            "Mujeres adultas: 12.0-16.0 g/dL\n"
            "Hombres adultos: 13.5-17.5 g/dL\n"
            "Gestantes (2°-3° trim): ≥11.0 g/dL"
        ),
        "placeholder": "Ej. 14.1"
    },
    {
        "key": "leucocitos",
        "label": "Leucocitos",
        "unit": "/µL",
        "reference": (
            "RN: 9 000-30 000 /µL\n"
            "1-12 meses: 6 000-17 500 /µL\n"
            "Niños 1-6 años: 5 000-15 500 /µL\n"
            "Niños 6-18 años: 4 500-13 500 /µL\n"
            "Adultos: 4 500-11 000 /µL"
        ),
        "placeholder": "Ej. 7 500"
    },
    {
        "key": "eritrocitos",
        "label": "Recuento de hematíes (RBC)",
        "unit": "millones/µL",
        "reference": (
            "RN: 4.1-6.1 millones/µL\n"
            "Niños 1-10 años: 3.9-5.3 millones/µL\n"
            "Hombres adultos: 4.5-6.0 millones/µL\n"
            "Mujeres adultas: 4.0-5.4 millones/µL"
        ),
        "placeholder": "Ej. 4.8"
    },
    {
        "key": "plaquetas",
        "label": "Plaquetas",
        "unit": "/µL",
        "reference": (
            "RN: 150 000-450 000 /µL\n"
            "Niños: 150 000-450 000 /µL\n"
            "Adultos: 150 000-400 000 /µL"
        ),
        "placeholder": "Ej. 250 000"
    },
    {
        "key": "segmentados",
        "label": "Segmentados",
        "unit": "%",
        "reference": (
            "Adultos: 40-75 %\n"
            "Niños 1-6 años: 30-60 %"
        )
    },
    {
        "key": "abastonados",
        "label": "Abastonados",
        "unit": "%",
        "reference": "0-6 %",
        "optional": True
    },
    {
        "key": "linfocitos",
        "label": "Linfocitos",
        "unit": "%",
        "reference": (
            "RN: 22-35 %\n"
            "Niños 1-6 años: 40-65 %\n"
            "Adultos: 20-45 %"
        )
    },
    {
        "key": "monocitos",
        "label": "Monocitos",
        "unit": "%",
        "reference": "2-10 %"
    },
    {
        "key": "eosinofilos",
        "label": "Eosinófilos",
        "unit": "%",
        "reference": "0-6 %"
    },
    {
        "key": "basofilos",
        "label": "Basófilos",
        "unit": "%",
        "reference": "0-2 %",
        "optional": True
    },
    {
        "key": "mielocitos",
        "label": "Mielocitos",
        "unit": "%",
        "optional": True
    },
    {
        "key": "metamielocitos",
        "label": "Metamielocitos",
        "unit": "%",
        "optional": True
    },
    {
        "key": "otras_celulas",
        "label": "Otras anormalidades",
        "optional": True,
        "placeholder": "Ej. Células en banda"
    },
    {
        "key": "observaciones",
        "label": "Observaciones microscópicas",
        "type": "text_area",
        "optional": True,
        "placeholder": "Describe hallazgos morfológicos"
    }
]

URINE_BASE_FIELDS = [
    {"type": "section", "label": "Examen físico"},
    {"key": "color", "label": "Color", "reference": "Amarillo pajizo; RN: incoloro a amarillo claro"},
    {"key": "aspecto", "label": "Aspecto", "reference": "Transparente; leve turbidez fisiológica en gestantes"},
    {"key": "olor", "label": "Olor", "reference": "Aromático suave", "optional": True},
    {"type": "section", "label": "Examen químico"},
    {"key": "densidad", "label": "Densidad", "reference": "RN: 1.002-1.012 | Niños: 1.005-1.015 | Adultos: 1.005-1.030"},
    {"key": "ph", "label": "pH", "reference": "RN: 5.0-7.0 | Niños/Adultos: 5.0-7.5"},
    {"key": "urobilinogeno", "label": "Urobilinógeno", "reference": "0.1-1.0 mg/dL"},
    {"key": "bilirrubina", "label": "Bilirrubina", "reference": "Negativo"},
    {"key": "proteinas", "label": "Proteínas", "reference": "Negativo (<15 mg/dL)"},
    {"key": "nitritos", "label": "Nitritos", "reference": "Negativo"},
    {"key": "glucosa", "label": "Glucosa", "reference": "Negativo"},
    {"key": "cetonas", "label": "Cetonas", "reference": "Negativo"},
    {"key": "leucocitos_quimico", "label": "Leucocitos", "reference": "Negativo"},
    {"key": "acido_ascorbico", "label": "Ácido ascórbico", "reference": "Negativo", "optional": True},
    {"key": "sangre", "label": "Sangre", "reference": "Negativo"},
    {"type": "section", "label": "Sedimento urinario"},
    {"key": "celulas_epiteliales", "label": "Células epiteliales/c", "reference": "0-5 /campo"},
    {"key": "leucocitos_campo", "label": "Leucocitos/c", "reference": "0-5 /campo (mujeres hasta 10)"},
    {"key": "hematies_campo", "label": "Hematíes/c", "reference": "0-2 /campo"},
    {"key": "cristales", "label": "Cristales/c", "reference": "No se observan", "optional": True},
    {"key": "cilindros", "label": "Cilindros/c", "reference": "0-2 cilindros hialinos/campo"},
    {"key": "otros_hallazgos", "label": "Otros hallazgos", "type": "text_area", "optional": True}
]

COPRO_DIRECT_FIELDS = [
    {"type": "section", "label": "Evaluación macroscópica"},
    {"key": "consistencia", "label": "Consistencia", "reference": "Formada; lactantes semiformada"},
    {"key": "color", "label": "Color", "reference": "Pardo amarillento", "optional": True},
    {"key": "moco", "label": "Moco", "type": "choice", "choices": ["Ausente", "Escaso", "Moderado", "Abundante"], "reference": "Ausente o escaso"},
    {"type": "section", "label": "Evaluación microscópica"},
    {"key": "leucocitos", "label": "Leucocitos/c", "reference": "0-2 /campo"},
    {"key": "hematies", "label": "Hematíes/c", "reference": "0-1 /campo"},
    {"key": "parasitos", "label": "Parásitos observados", "type": "text_area", "reference": "No se observan", "optional": True},
    {"key": "levaduras", "label": "Levaduras", "reference": "Ausentes o escasas", "optional": True},
    {"key": "grasas", "label": "Grasas", "reference": "Ausentes", "optional": True},
    {"key": "reaccion_inflamatoria", "label": "Reacción inflamatoria", "optional": True, "helper": "Describa tinción Wright / diferenciación PMN-MMN"},
    {"key": "metodo", "label": "Método", "type": "choice", "choices": ["Directo", "Concentrado", "Serial"], "reference": "Registrar técnica aplicada"},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

COPRO_CONCENT_FIELDS = [
    {"type": "section", "label": "Procedimiento"},
    {"key": "metodo", "label": "Método", "type": "choice", "choices": ["Concentración", "Flotación", "Sedimentación"], "reference": "Indique técnica aplicada"},
    {"type": "section", "label": "Hallazgos"},
    {"key": "parasitos", "label": "Parásitos observados", "type": "text_area", "reference": "No se observan", "optional": True},
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
    {"key": "moco", "label": "Moco", "type": "choice", "choices": ["Ausente", "Escaso", "Moderado", "Abundante"], "reference": "Ausente o escaso", "optional": True},
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

def build_bool_observation_template(positive_text="Positivo", negative_text="Negativo", reference_text="Negativo"):
    return {
        "fields": [
            {
                "key": "resultado",
                "label": "Resultado",
                "type": "bool",
                "positive_text": positive_text,
                "negative_text": negative_text,
                "reference": reference_text
            },
            {
                "key": "observaciones",
                "label": "Observaciones",
                "type": "text_area",
                "optional": True,
                "placeholder": "Observaciones (opcional)"
            }
        ]
    }

def build_multi_sample_bool_template(
    sample_count=3,
    positive_text="Positivo",
    negative_text="Negativo",
    reference_text="Negativo",
    sample_label_prefix="Muestra",
):
    fields = []
    for idx in range(1, sample_count + 1):
        fields.append({"type": "section", "label": f"{sample_label_prefix} {idx}"})
        fields.append(
            {
                "key": f"muestra_{idx}",
                "label": f"Resultado {sample_label_prefix.lower()} {idx}",
                "type": "bool",
                "positive_text": positive_text,
                "negative_text": negative_text,
                "reference": reference_text,
            }
        )
    fields.append(
        {
            "key": "observaciones",
            "label": "Observaciones",
            "type": "text_area",
            "optional": True,
            "placeholder": "Observaciones generales",
        }
    )
    return {"fields": fields}

def build_single_value_template(key, label, unit=None, reference=None, placeholder=None, helper=None, optional=False, field_type="line", choices=None):
    field = {
        "key": key,
        "label": label
    }
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

SECRECION_VAGINAL_FIELDS = [
    {"type": "section", "label": "Evaluación clínica"},
    {"key": "ph", "label": "pH vaginal", "reference": "Mujer fértil: 3.8-4.5 | Postmenopáusica: hasta 5.0", "placeholder": "Ej. 4.2"},
    {"key": "aspecto", "label": "Aspecto", "reference": "Homogéneo, blanco lechoso", "optional": True},
    {"key": "olor", "label": "Olor", "reference": "Sin olor fétido", "optional": True},
    {"type": "section", "label": "Test de aminas"},
    {"key": "test_aminas", "label": "Test de aminas", "type": "bool", "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
    {"type": "section", "label": "Observación en fresco"},
    {"key": "celulas_epiteliales", "label": "Células epiteliales/campo", "reference": "Escasas", "optional": True},
    {"key": "leucocitos", "label": "Leucocitos/campo", "reference": "<10/campo de gran aumento"},
    {"key": "hematies", "label": "Hematíes/campo", "reference": "0-1/campo", "optional": True},
    {"key": "trichomonas", "label": "Trichomonas vaginalis", "reference": "No se observan", "optional": True},
    {"key": "levaduras", "label": "Levaduras / blastosporas", "reference": "No se observan", "optional": True},
    {"key": "otros_fresco", "label": "Otros hallazgos (fresco)", "optional": True, "placeholder": "Levaduras, bacterias u otros gérmenes"},
    {"type": "section", "label": "Coloración de Gram"},
    {"key": "puntaje_nugent", "label": "Puntaje de Nugent", "reference": "0-3 flora normal | 4-6 flora intermedia | 7-10 vaginosis"},
    {"key": "celulas_clue", "label": "Células clue", "reference": "Ausentes"},
    {"key": "bacilos_doderlein", "label": "Bacilos de Döderlein", "reference": "Abundantes"},
    {"key": "cocos_gram", "label": "Cocos / bacterias Gram variables", "optional": True},
    {"key": "leucocitos_gram", "label": "Leucocitos/campo (Gram)", "reference": "0-5/campo", "optional": True},
    {"key": "otros_gram", "label": "Otros gérmenes (Gram)", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True, "placeholder": "Hallazgos adicionales relevantes"}
]

SECRECION_GENERAL_FIELDS = [
    {"type": "section", "label": "Datos de la muestra"},
    {"key": "tipo_secrecion", "label": "Tipo de secreción", "type": "choice", "choices": ["Cervical", "Uretral", "Ocular", "Nasofaríngea", "Otorrinolaringológica", "Rectal", "Cutánea", "Otra"], "reference": "Seleccione sitio anatómico"},
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
    {"key": "vcm", "label": "VCM", "unit": "fL", "reference": "RN: 95-120 | Niños: 70-86 | Adultos: 80-96", "placeholder": "Ej. 88"},
    {"key": "hcm", "label": "HCM", "unit": "pg", "reference": "RN: 31-37 | Niños: 24-32 | Adultos: 27-33", "placeholder": "Ej. 29"},
    {"key": "chcm", "label": "CHCM", "unit": "g/dL", "reference": "Niños y adultos: 32-36 g/dL", "placeholder": "Ej. 33"},
    {"key": "rdw", "label": "RDW", "unit": "%", "reference": "11.5-14.5 %", "placeholder": "Ej. 13.2"}
]

TOLERANCIA_GLUCO_FIELDS = [
    {"key": "glucosa_ayunas", "label": "Glucosa en ayunas", "unit": "mg/dL", "reference": "Normal <100 mg/dL | Gestante <95 mg/dL", "placeholder": "Ej. 92"},
    {"key": "glucosa_60", "label": "Glucosa 60 min", "unit": "mg/dL", "reference": "Normal <180 mg/dL", "placeholder": "Ej. 155"},
    {"key": "glucosa_120", "label": "Glucosa 120 min", "unit": "mg/dL", "reference": "Normal <140 mg/dL | Gestante <153 mg/dL", "placeholder": "Ej. 132"},
    {"key": "glucosa_180", "label": "Glucosa 180 min", "unit": "mg/dL", "reference": "<140 mg/dL", "optional": True, "placeholder": "Ej. 124"}
]

GASES_ARTERIALES_FIELDS = [
    {"key": "ph", "label": "pH", "reference": "RN: 7.30-7.40 | Adultos: 7.35-7.45", "placeholder": "Ej. 7.39"},
    {"key": "pco2", "label": "pCO₂", "unit": "mmHg", "reference": "RN: 27-40 | Adultos: 35-45", "placeholder": "Ej. 40"},
    {"key": "po2", "label": "pO₂", "unit": "mmHg", "reference": "RN: 50-70 | Adultos: 80-100", "placeholder": "Ej. 92"},
    {"key": "hco3", "label": "HCO₃⁻", "unit": "mmol/L", "reference": "RN: 20-26 | Adultos: 22-26", "placeholder": "Ej. 24"},
    {"key": "exceso_base", "label": "Exceso de bases", "unit": "mmol/L", "reference": "-2 a +2", "placeholder": "Ej. -1"},
    {"key": "saturacion", "label": "SatO₂", "unit": "%", "reference": "RN: 90-95 % | Adultos: 95-100 %", "placeholder": "Ej. 97"},
    {"key": "lactato", "label": "Lactato", "unit": "mmol/L", "reference": "0.5-1.6 mmol/L", "optional": True, "placeholder": "Ej. 1.1"}
]

UROCULTIVO_FIELDS = [
    {"key": "recuento", "label": "Recuento bacteriano", "unit": "UFC/mL", "reference": "<10^5 UFC/mL: sin significancia clínica"},
    {"key": "microorganismo", "label": "Microorganismo aislado", "reference": "Sin desarrollo significativo", "optional": True},
    {"key": "interpretacion", "label": "Interpretación", "type": "text_area", "optional": True, "placeholder": "Sensibilidad recomendada"}
]

COPROCULTIVO_FIELDS = [
    {"key": "microorganismos", "label": "Microorganismos aislados", "reference": "No se aíslan patógenos entéricos", "optional": True},
    {"key": "resultado", "label": "Resultado", "reference": "Flora intestinal normal", "optional": True},
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
    {"key": "volumen", "label": "Volumen residual", "unit": "mL", "reference": "<20 mL", "placeholder": "Ej. 12"},
    {"key": "ph", "label": "pH", "reference": "1.0-4.0", "placeholder": "Ej. 2.5"},
    {"key": "aspecto", "label": "Aspecto", "reference": "Translúcido o ligeramente verdoso", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

GRUPO_RH_FIELDS = [
    {"key": "grupo_abo", "label": "Grupo ABO", "type": "choice", "choices": ["O", "A", "B", "AB"], "reference": "Reportar fenotipo ABO"},
    {"key": "factor_rh", "label": "Factor Rh", "type": "choice", "choices": ["Positivo", "Negativo"], "reference": "Factor Rh(D)"},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

WIDAL_FIELDS = [
    {"key": "antigeno_o", "label": "Antígeno O", "reference": "Negativo: <1:80"},
    {"key": "antigeno_h", "label": "Antígeno H", "reference": "Negativo: <1:160"},
    {"key": "antigeno_ah", "label": "Antígeno AH", "reference": "Negativo: <1:80", "optional": True},
    {"key": "antigeno_bh", "label": "Antígeno BH", "reference": "Negativo: <1:80", "optional": True},
    {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
]

def build_sample_tracking_template(reference_note):
    return {
        "fields": [
            {"key": "fecha_toma", "label": "Fecha de toma", "placeholder": "DD/MM/AAAA", "reference": "Coincide con el registro de 'F. muestra'"},
            {"key": "hora_toma", "label": "Hora de toma/envío", "placeholder": "HH:MM", "reference": "Registrar hora oficial de la toma"},
            {"key": "destino", "label": "Destino / referencia", "optional": True, "placeholder": "Ej. Laboratorio de referencia"},
            {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True, "reference": reference_note}
        ]
    }

TEST_TEMPLATES = {
    "Hemograma manual": {
        "fields": copy.deepcopy(HEMOGRAM_BASE_FIELDS),
        "auto_calculations": [
            {
                "source": "hematocrito",
                "target": "hemoglobina",
                "operation": "divide",
                "operand": 3.03,
                "decimals": 2,
                "description": "Hb = Hto / 3.03 (cálculo automático)",
            }
        ]
    },
    "Hemograma automatizado": {
        "fields": copy.deepcopy(HEMOGRAM_BASE_FIELDS),
        "auto_calculations": [
            {
                "source": "hematocrito",
                "target": "hemoglobina",
                "operation": "divide",
                "operand": 3.03,
                "decimals": 2,
                "description": "Hb = Hto / 3.03 (cálculo automático)",
            }
        ]
    },
    "Examen completo de orina": {"fields": copy.deepcopy(URINE_BASE_FIELDS)},
    "Sedimento urinario": {"fields": copy.deepcopy(SEDIMENTO_FIELDS)},
    "Examen coprológico (directo)": {"fields": copy.deepcopy(COPRO_DIRECT_FIELDS)},
    "Examen coprológico (concentración)": {"fields": copy.deepcopy(COPRO_CONCENT_FIELDS)},
    "Coloración de Gram": {"fields": copy.deepcopy(GRAM_FIELDS)},
    "Reacción inflamatoria": {"fields": copy.deepcopy(REACTION_FIELDS)},
    "Test de aminas": {
        "fields": [
            {"key": "resultado", "label": "Resultado", "type": "bool", "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
            {"key": "olor_caracteristico", "label": "Olor característico", "optional": True},
            {"key": "observaciones", "label": "Observaciones", "type": "text_area", "optional": True}
        ]
    },
    "Test de Helecho": {
        "fields": [
            {"key": "resultado", "label": "Resultado", "type": "bool", "positive_text": "Positivo", "negative_text": "Negativo", "reference": "Patrón negativo"},
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

SIMPLE_NUMERIC_TESTS = {
    "Hemoglobina": {
        "key": "hemoglobina",
        "label": "Hemoglobina",
        "unit": "g/dL",
        "reference": (
            "RN: 14.0-24.0 g/dL\n"
            "1-12 meses: 10.0-12.5 g/dL\n"
            "Niños 1-12 años: 11.5-15.5 g/dL\n"
            "Mujeres adultas: 12.0-16.0 g/dL\n"
            "Hombres adultos: 13.5-17.5 g/dL\n"
            "Gestantes (2°-3° trim): ≥11.0 g/dL"
        ),
        "placeholder": "Ej. 13.8"
    },
    "Recuento de leucocitos": {
        "key": "leucocitos_totales",
        "label": "Leucocitos",
        "unit": "/µL",
        "reference": (
            "RN: 9 000-30 000 /µL\n"
            "Niños 1-6 años: 5 000-15 500 /µL\n"
            "Adultos: 4 500-11 000 /µL"
        ),
        "placeholder": "Ej. 8 200"
    },
    "Recuento de hematíes": {
        "key": "eritrocitos_totales",
        "label": "Recuento de hematíes",
        "unit": "millones/µL",
        "reference": (
            "RN: 4.1-6.1 millones/µL\n"
            "Niños 1-10 años: 3.9-5.3 millones/µL\n"
            "Hombres adultos: 4.5-6.0 millones/µL\n"
            "Mujeres adultas: 4.0-5.4 millones/µL"
        ),
        "placeholder": "Ej. 4.7"
    },
    "Recuento de plaquetas": {
        "key": "plaquetas_totales",
        "label": "Plaquetas",
        "unit": "/µL",
        "reference": "RN y niños: 150 000-450 000 /µL | Adultos: 150 000-400 000 /µL",
        "placeholder": "Ej. 210 000"
    },
    "Tiempo de coagulación": {
        "key": "tiempo_coagulacion",
        "label": "Tiempo de coagulación",
        "unit": "min",
        "reference": "Adultos: 8-12 min (Lee-White) | Niños: 6-11 min",
        "placeholder": "Ej. 9"
    },
    "Tiempo de sangría": {
        "key": "tiempo_sangria",
        "label": "Tiempo de sangría",
        "unit": "min",
        "reference": "Mujeres: 2-7 min | Hombres: 2-6 min",
        "placeholder": "Ej. 3"
    },
    "Velocidad de sedimentación globular (VSG)": {
        "key": "vsg",
        "label": "VSG",
        "unit": "mm/h",
        "reference": (
            "Hombres <50 a: 0-15 mm/h | Hombres ≥50 a: 0-20 mm/h\n"
            "Mujeres <50 a: 0-20 mm/h | Mujeres ≥50 a: 0-30 mm/h\n"
            "Niños: 0-10 mm/h"
        ),
        "placeholder": "Ej. 12"
    },
    "Glucosa": {
        "key": "glucosa",
        "label": "Glucosa en ayunas",
        "unit": "mg/dL",
        "reference": "Niños y adultos: 70-99 mg/dL | Gestantes: <95 mg/dL",
        "placeholder": "Ej. 88"
    },
    "Glucosa postprandial": {
        "key": "glucosa_postprandial",
        "label": "Glucosa 2 h postprandial",
        "unit": "mg/dL",
        "reference": "Niños y adultos: <140 mg/dL | Gestantes: <120 mg/dL",
        "placeholder": "Ej. 128"
    },
    "Colesterol Total": {
        "key": "colesterol_total",
        "label": "Colesterol total",
        "unit": "mg/dL",
        "reference": "Adultos: <200 mg/dL (deseable) | Niños: <170 mg/dL",
        "placeholder": "Ej. 185"
    },
    "Triglicéridos": {
        "key": "trigliceridos",
        "label": "Triglicéridos",
        "unit": "mg/dL",
        "reference": "Niños <9 a: <100 mg/dL | 10-19 a: <130 mg/dL | Adultos: <150 mg/dL",
        "placeholder": "Ej. 135"
    },
    "Colesterol HDL": {
        "key": "hdl",
        "label": "Colesterol HDL",
        "unit": "mg/dL",
        "reference": "Varones: ≥40 mg/dL | Mujeres: ≥50 mg/dL | Niños: ≥45 mg/dL",
        "placeholder": "Ej. 52"
    },
    "Colesterol LDL": {
        "key": "ldl",
        "label": "Colesterol LDL",
        "unit": "mg/dL",
        "reference": "Niños: <110 mg/dL | Adultos: <100 mg/dL (óptimo)",
        "placeholder": "Ej. 98"
    },
    "Transaminasa Glutámico Oxalacética (TGO)": {
        "key": "tgo",
        "label": "TGO (AST)",
        "unit": "U/L",
        "reference": "RN: <75 U/L | Niños: <50 U/L | Adultos: 10-40 U/L",
        "placeholder": "Ej. 28"
    },
    "Transaminasa Glutámico Pirúvico (TGP)": {
        "key": "tgp",
        "label": "TGP (ALT)",
        "unit": "U/L",
        "reference": "RN: <60 U/L | Niños: <40 U/L | Adultos: 7-45 U/L",
        "placeholder": "Ej. 32"
    },
    "Bilirrubina Total": {
        "key": "bilirrubina_total",
        "label": "Bilirrubina total",
        "unit": "mg/dL",
        "reference": "Adultos: 0.3-1.2 mg/dL | RN 24 h: <6 mg/dL | RN 48 h: <10 mg/dL",
        "placeholder": "Ej. 0.8"
    },
    "Bilirrubina Directa": {
        "key": "bilirrubina_directa",
        "label": "Bilirrubina directa",
        "unit": "mg/dL",
        "reference": "Adultos: 0.0-0.3 mg/dL | RN: <0.5 mg/dL",
        "placeholder": "Ej. 0.2"
    },
    "Úrea": {
        "key": "urea",
        "label": "Úrea",
        "unit": "mg/dL",
        "reference": "RN: 3-12 mg/dL | Niños: 5-18 mg/dL | Adultos: 15-40 mg/dL",
        "placeholder": "Ej. 28"
    },
    "Creatinina": {
        "key": "creatinina",
        "label": "Creatinina",
        "unit": "mg/dL",
        "reference": "RN: 0.3-1.0 mg/dL | Niños: 0.2-0.7 mg/dL | Mujeres: 0.5-0.9 mg/dL | Hombres: 0.7-1.3 mg/dL",
        "placeholder": "Ej. 0.9"
    },
    "Proteína de 24 horas": {
        "key": "proteina_24h",
        "label": "Proteína 24 h",
        "unit": "mg/24h",
        "reference": "Adultos: <150 mg/24h | Gestantes: <300 mg/24h",
        "placeholder": "Ej. 120"
    },
    "Fosfatasa alcalina": {
        "key": "fosfatasa_alcalina",
        "label": "Fosfatasa alcalina",
        "unit": "U/L",
        "reference": "Niños: 150-380 U/L | Adultos: 44-147 U/L | Gestantes 3er trim: <240 U/L",
        "placeholder": "Ej. 110"
    },
    "Ácido úrico": {
        "key": "acido_urico",
        "label": "Ácido úrico",
        "unit": "mg/dL",
        "reference": "Niños: 2.0-5.5 mg/dL | Mujeres: 2.4-6.0 mg/dL | Hombres: 3.4-7.0 mg/dL",
        "placeholder": "Ej. 4.8"
    },
    "Proteínas Totales": {
        "key": "proteinas_totales",
        "label": "Proteínas totales",
        "unit": "g/dL",
        "reference": "RN: 4.6-7.4 g/dL | Niños: 6.0-8.0 g/dL | Adultos: 6.4-8.3 g/dL",
        "placeholder": "Ej. 7.1"
    },
    "Albúmina": {
        "key": "albumina",
        "label": "Albúmina",
        "unit": "g/dL",
        "reference": "RN: 2.8-4.4 g/dL | Niños: 3.5-5.5 g/dL | Adultos: 3.5-5.2 g/dL | Gestantes: 2.8-4.5 g/dL",
        "placeholder": "Ej. 4.0"
    },
    "Amilasa": {
        "key": "amilasa",
        "label": "Amilasa",
        "unit": "U/L",
        "reference": "RN: 6-65 U/L | Niños: 30-90 U/L | Adultos: 28-100 U/L",
        "placeholder": "Ej. 62"
    },
    "Lipasa": {
        "key": "lipasa",
        "label": "Lipasa",
        "unit": "U/L",
        "reference": "RN: 6-51 U/L | Niños: 10-140 U/L | Adultos: 13-60 U/L",
        "placeholder": "Ej. 45"
    },
    "Gamma Glutamil transferasa (GGT)": {
        "key": "ggt",
        "label": "GGT",
        "unit": "U/L",
        "reference": "RN: 12-73 U/L | Niños: 12-43 U/L | Mujeres: 7-32 U/L | Hombres: 10-50 U/L",
        "placeholder": "Ej. 24"
    },
    "Globulina": {
        "key": "globulina",
        "label": "Globulina",
        "unit": "g/dL",
        "reference": "Niños: 2.0-3.5 g/dL | Adultos: 2.3-3.5 g/dL",
        "placeholder": "Ej. 2.7"
    },
    "Ferritina": {
        "key": "ferritina",
        "label": "Ferritina",
        "unit": "ng/mL",
        "reference": (
            "RN: 25-200 ng/mL\n"
            "Niños 1-5 a: 10-60 ng/mL | Niños 6-15 a: 7-140 ng/mL\n"
            "Hombres adultos: 30-400 ng/mL\n"
            "Mujeres adultas: 15-150 ng/mL\n"
            "Gestantes: 1T 10-150 | 2T 6-74 | 3T 2-40 ng/mL"
        ),
        "placeholder": "Ej. 55"
    },
    "Hemoglobina glicosilada": {
        "key": "hba1c",
        "label": "HbA1c",
        "unit": "%",
        "reference": "Normal <5.7 % | Prediabetes 5.7-6.4 % | Diabetes ≥6.5 % | Gestantes con diabetes: meta <6.0 %",
        "placeholder": "Ej. 5.6"
    },
    "Factor reumatoideo": {
        "key": "factor_reumatoideo",
        "label": "Factor reumatoideo",
        "unit": "UI/mL",
        "reference": "Adultos: <14 UI/mL | Niños: <10 UI/mL",
        "placeholder": "Ej. 8"
    },
    "PCR cuantitativo": {
        "key": "proteina_c",
        "label": "Proteína C reactiva",
        "unit": "mg/L",
        "reference": "Adultos: <5 mg/L | RN: <10 mg/L",
        "placeholder": "Ej. 3.2"
    },
    "ASO": {
        "key": "aso",
        "label": "Antiestreptolisinas (ASO)",
        "unit": "UI/mL",
        "reference": "Adultos: <200 UI/mL | Niños: <250 UI/mL",
        "placeholder": "Ej. 120"
    },
    "PSA (ELISA)": {
        "key": "psa",
        "label": "PSA total",
        "unit": "ng/mL",
        "reference": "40-49 a: <2.5 | 50-59 a: <3.5 | 60-69 a: <4.5 | ≥70 a: <6.5 ng/mL",
        "placeholder": "Ej. 2.1"
    }
}

SIMPLE_TEXTAREA_TESTS = {
    "Lámina periférica": {
        "key": "descripcion",
        "label": "Descripción morfológica",
        "reference": "Eritrocitos normocíticos normocrómicos, leucocitos sin alteraciones, plaquetas adecuadas",
        "placeholder": "Describa morfología observada"
    },
    "Identificación bioquímica": {
        "key": "panel_bioquimico",
        "label": "Perfil bioquímico",
        "reference": "Describa pruebas realizadas según manual CLSI vigente",
        "placeholder": "Ej. Enterobacter cloacae, panel API 20E"
    },
    "Antibiograma": {
        "key": "antibiograma",
        "label": "Antibiograma",
        "reference": "Interpretar según guías CLSI/EUCAST",
        "placeholder": "Antibiótico - Interpretación (S/I/R)"
    },
    "BK (resultado referencial)": {
        "key": "resultado",
        "label": "Resultado BK",
        "reference": "Describa gradación (Negativo, 1+, 2+, 3+) u observaciones del informe referencial",
        "placeholder": "Ej. Negativo / BK 1+"
    }
}

BOOL_TESTS = {
    "Células LE": {"positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
    "Baciloscopía": {"positive_text": "BAAR positivo", "negative_text": "BAAR negativo", "reference": "No se observan bacilos ácido-alcohol resistentes"},
    "Gota gruesa": {"positive_text": "Hemoparásitos", "negative_text": "No se observan", "reference": "No se observan Plasmodium spp."},
    "Frotis para Leishmaniasis": {"positive_text": "Leishmania sp.", "negative_text": "No se observan", "reference": "No se observan amastigotes"},
    "Cultivo de Neisseria gonorrhoeae": {"positive_text": "Aislamiento positivo", "negative_text": "Sin aislamiento", "reference": "No se aisla N. gonorrhoeae"},
    "Cultivo de Campylobacter spp.": {"positive_text": "Aislamiento positivo", "negative_text": "Sin aislamiento", "reference": "No se aisla Campylobacter spp."},
    "Frotis para Bartonella": {"positive_text": "Cuerpos de Bartonella", "negative_text": "No se observan", "reference": "Negativo"},
    "Ácido sulfasalicílico al 3%": {"positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo (proteínas ≤30 mg/dL)"},
    "Antígeno de superficie Hepatitis B (HBsAg)": {
        "positive_text": "Reactivo",
        "negative_text": "No reactivo",
        "reference": "No reactivo"
    },
    "Reagina plasmática rápida (RPR)": {
        "positive_text": "Reactivo",
        "negative_text": "No reactivo",
        "reference": "No reactivo"
    },
    "Proteína C reactiva (PCR) - Látex": {"positive_text": "Reactivo", "negative_text": "No reactivo", "reference": "No reactivo"},
    "BHCG (Prueba de embarazo en sangre)": {"positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo (<5 mUI/mL)"},
    "Serología Dengue (referencial)": {"positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
    "Serología Leptospira (referencial)": {"positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"},
    "Serología Leishmaniasis (referencial)": {"positive_text": "Positivo", "negative_text": "Negativo", "reference": "Negativo"}
}

SAMPLE_TEMPLATES = {
    "Leishmaniasis (toma de muestra)": build_sample_tracking_template("Registro de remisión según NTS para vigilancia de leishmaniasis"),
    "Dengue (toma de muestra)": build_sample_tracking_template("Mantener cadena de frío 2-8 °C"),
    "Leptospirosis (toma de muestra)": build_sample_tracking_template("Documentar envío a laboratorio de referencia"),
    "Covid-19 (hisopado nasofaríngeo)": build_sample_tracking_template("Remitir en medio viral a 4 °C"),
    "Carga viral de VIH / Recuento de CD4": build_sample_tracking_template("Registrar código de envío y hora"),
    "CLIA (PSA, Perfil tiroideo, etc.)": build_sample_tracking_template("Sin valores de referencia: registro de muestra derivada"),
    "Sangre venosa/arterial (examen de proceso)": build_sample_tracking_template("Control de cadena de custodia (sin valores analíticos)"),
    "Covid-19 (Prueba antigénica)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Covid-19 (Prueba serológica)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Dengue NS1/IgM/IgG (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Hepatitis A (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Hepatitis B (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "PSA (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Sangre oculta en heces (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "Helicobacter pylori (Prueba rápida)": build_bool_observation_template("Positivo", "Negativo", "Negativo"),
    "VIH (Prueba rápida)": build_bool_observation_template("Reactivo", "No reactivo", "No reactivo"),
    "Sífilis (Prueba rápida)": build_bool_observation_template("Reactivo", "No reactivo", "No reactivo"),
    "VIH/Sífilis (Prueba combinada)": build_bool_observation_template("Reactivo", "No reactivo", "No reactivo"),
    "BHCG (Prueba de embarazo en sangre)": build_bool_observation_template("Positivo", "Negativo", "Negativo (<5 mUI/mL)")
}

for test_name, info in SIMPLE_NUMERIC_TESTS.items():
    TEST_TEMPLATES[test_name] = build_single_value_template(
        info["key"],
        info.get("label", test_name),
        unit=info.get("unit"),
        reference=info.get("reference"),
        placeholder=info.get("placeholder"),
        helper=info.get("helper")
    )

for test_name, info in SIMPLE_TEXTAREA_TESTS.items():
    TEST_TEMPLATES[test_name] = build_single_value_template(
        info["key"],
        info.get("label", test_name),
        reference=info.get("reference"),
        placeholder=info.get("placeholder"),
        field_type="text_area"
    )

for test_name, params in BOOL_TESTS.items():
    TEST_TEMPLATES[test_name] = build_bool_observation_template(
        params.get("positive_text", "Positivo"),
        params.get("negative_text", "Negativo"),
        params.get("reference", "Negativo")
    )

for test_name, template in SAMPLE_TEMPLATES.items():
    TEST_TEMPLATES[test_name] = copy.deepcopy(template)

# Plantillas específicas para exámenes con múltiples muestras
TEST_TEMPLATES["Parasitológico seriado"] = build_multi_sample_bool_template(
    sample_count=3,
    positive_text="Positivo",
    negative_text="Negativo",
    reference_text="No se observan parásitos",
)

TEST_TEMPLATES["Test de Graham"] = build_multi_sample_bool_template(
    sample_count=3,
    positive_text="Huevos presentes",
    negative_text="No se observan",
    reference_text="Sin huevos de Enterobius vermicularis",
)

# Plantilla base para Hematocrito sin cálculo automático
HEMATOCRIT_BASE_TEMPLATE = build_single_value_template(
    "hematocrito",
    "Hematocrito",
    unit="%",
    reference=(
        "RN: 44-65 %\n"
        "Niños 1-10 a: 35-45 %\n"
        "Hombres adultos: 40-54 %\n"
        "Mujeres adultas: 36-47 %\n"
        "Gestantes (2°-3° trim): 33-43 %"
    ),
    placeholder="Ej. 43"
)
TEST_TEMPLATES["Hematocrito"] = copy.deepcopy(HEMATOCRIT_BASE_TEMPLATE)


def build_hematocrit_template(include_auto_hemoglobin=False):
    template = copy.deepcopy(HEMATOCRIT_BASE_TEMPLATE)
    fields = copy.deepcopy(HEMATOCRIT_BASE_TEMPLATE.get("fields", []))
    if include_auto_hemoglobin:
        hb_reference = SIMPLE_NUMERIC_TESTS.get("Hemoglobina", {}).get("reference")
        fields.append(
            {
                "key": "hemoglobina",
                "label": "Hemoglobina (estimada)",
                "unit": "g/dL",
                "reference": hb_reference,
                "placeholder": "Calculada automáticamente"
            }
        )
        template["auto_calculations"] = [
            {
                "source": "hematocrito",
                "target": "hemoglobina",
                "operation": "divide",
                "operand": 3.03,
                "decimals": 2,
                "description": "Hb estimada = Hto / 3.03 (solo cuando se solicita Hematocrito)",
                "clear_on_invalid": True
            }
        ]
    template["fields"] = fields
    return template


def build_hemoglobin_hematocrit_combo_template():
    template = build_hematocrit_template(include_auto_hemoglobin=True)
    fields = template.get("fields", [])
    hb_info = SIMPLE_NUMERIC_TESTS.get("Hemoglobina", {})
    hematocrit_field = None
    hemoglobin_field = None
    for field in fields:
        if field.get("key") == "hematocrito":
            hematocrit_field = field
        elif field.get("key") == "hemoglobina":
            hemoglobin_field = field
    if hemoglobin_field:
        hb_label = hb_info.get("label", "Hemoglobina")
        if "hb" not in hb_label.lower():
            hb_label = f"{hb_label} (Hb)"
        hemoglobin_field["label"] = hb_label
        placeholder = hb_info.get("placeholder") or "Ej. 13.8"
        hemoglobin_field["placeholder"] = placeholder
        helper_text = hb_info.get("helper")
        if helper_text:
            hemoglobin_field["helper"] = helper_text
    ordered_fields = []
    if hemoglobin_field:
        ordered_fields.append(hemoglobin_field)
    if hematocrit_field:
        ordered_fields.append(hematocrit_field)
    if ordered_fields:
        template["fields"] = ordered_fields
    for calc in template.get("auto_calculations", []):
        calc["only_if_empty"] = True
        description = calc.get("description")
        if description:
            if "ajust" not in description.lower():
                calc["description"] = f"{description} (se puede ajustar manualmente)"
        else:
            calc["description"] = "Hb estimada = Hto / 3.03 (se puede ajustar manualmente)"
    return template


TEST_TEMPLATES["Hemoglobina - Hematocrito"] = build_hemoglobin_hematocrit_combo_template()

RAPID_TEST_NAMES = [
    "BHCG (Prueba de embarazo en sangre)",
    "VIH (Prueba rápida)",
    "Sífilis (Prueba rápida)",
    "VIH/Sífilis (Prueba combinada)",
    "Hepatitis A (Prueba rápida)",
    "Hepatitis B (Prueba rápida)",
    "PSA (Prueba rápida)",
    "Sangre oculta en heces (Prueba rápida)",
    "Helicobacter pylori (Prueba rápida)",
    "Covid-19 (Prueba antigénica)",
    "Covid-19 (Prueba serológica)",
    "Dengue NS1/IgM/IgG (Prueba rápida)"
]

for rapid_test in RAPID_TEST_NAMES:
    if rapid_test not in TEST_TEMPLATES:
        TEST_TEMPLATES[rapid_test] = build_bool_observation_template()



class AddTestsDialog(QDialog):
    def __init__(self, tests, disabled_tests=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Agregar pruebas a la orden")
        self.setMinimumSize(420, 480)
        layout = QVBoxLayout(self)
        description = QLabel("Seleccione las pruebas adicionales que desea agregar a la orden actual.")
        description.setWordWrap(True)
        layout.addWidget(description)
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.MultiSelection)
        disabled_set = set(disabled_tests or [])
        for name, category in tests:
            display_text = f"{name} ({category})" if category else name
            item = QListWidgetItem(display_text)
            item.setData(Qt.UserRole, name)
            if name in disabled_set:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
                item.setText(f"{display_text} - ya incluido")
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_selected_tests(self):
        return [item.data(Qt.UserRole) for item in self.list_widget.selectedItems() if item.flags() & Qt.ItemIsEnabled]


class ReasonDialog(QDialog):
    def __init__(self, title, prompt, parent=None, placeholder="Describa el motivo" ):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        label = QLabel(prompt)
        label.setWordWrap(True)
        layout.addWidget(label)
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText(placeholder)
        self.text_edit.setFixedHeight(120)
        layout.addWidget(self.text_edit)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def get_reason(self):
        return self.text_edit.toPlainText().strip()


class BatchEmitDialog(QDialog):
    def __init__(self, orders, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Emitir resultados en lote")
        self.setMinimumSize(540, 480)
        layout = QVBoxLayout(self)
        description = QLabel(
            "Seleccione las órdenes que desea incluir en el PDF."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.NoSelection)
        for order in orders:
            display = order.get("display", "")
            item = QListWidgetItem(display)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if order.get("preselect") else Qt.Unchecked)
            item.setData(Qt.UserRole, order.get("id"))
            if order.get("emitted"):
                item.setForeground(Qt.gray)
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def get_selected_ids(self):
        selected = []
        for index in range(self.list_widget.count()):
            item = self.list_widget.item(index)
            if item.checkState() == Qt.Checked:
                order_id = item.data(Qt.UserRole)
                if order_id is not None:
                    selected.append(int(order_id))
        return selected


class MainWindow(QMainWindow):
    def __init__(self, labdb, user):
        super().__init__()
        self.labdb = labdb
        self.user = user
        self.setWindowTitle(LAB_TITLE)
        # Configuración de ventana principal y menú lateral
        central_widget = QWidget()
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        side_menu_layout = QVBoxLayout()
        side_menu_layout.setContentsMargins(20, 28, 20, 28)
        side_menu_layout.setSpacing(18)
        side_menu_widget = QWidget()
        side_menu_widget.setObjectName("SideMenu")
        side_menu_widget.setLayout(side_menu_layout)
        side_menu_widget.setFixedWidth(220)
        title_label = QLabel(LAB_TITLE)
        title_label.setObjectName("SideMenuTitle")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setWordWrap(True)
        side_menu_layout.addWidget(title_label)
        side_menu_layout.addSpacing(12)
        # Estilos y configuración del menú de navegación
        self.nav_buttons = OrderedDict()
        self.nav_button_default_style = (
            "QPushButton {"
            "background-color: transparent;"
            "color: #f1f6ff;"
            "font-size: 14px;"
            "padding: 12px 14px;"
            "border: none;"
            "text-align: left;"
            "border-radius: 10px;"
            "}"
            "QPushButton:hover { background-color: rgba(255, 255, 255, 0.12); }"
        )
        self.nav_button_active_style = (
            "QPushButton {"
            "background-color: #2e86de;"
            "color: white;"
            "font-size: 14px;"
            "padding: 12px 14px;"
            "border: none;"
            "border-radius: 10px;"
            "font-weight: bold;"
            "}"
        )
        # Secciones/Páginas
        self.stack = QStackedWidget()
        self.current_order_context = None
        # Contenedor principal con cabecera y reloj
        content_widget = QWidget()
        content_widget.setObjectName("ContentArea")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(30, 30, 30, 30)
        content_layout.setSpacing(24)
        header_bar = QWidget()
        header_bar.setObjectName("HeaderBar")
        header_layout = QHBoxLayout(header_bar)
        header_layout.setContentsMargins(20, 16, 20, 16)
        header_layout.setSpacing(12)
        header_title = QLabel(LAB_TITLE)
        header_title.setObjectName("HeaderTitle")
        header_title.setWordWrap(True)
        self.clock_label = QLabel()
        self.clock_label.setObjectName("HeaderClock")
        self.clock_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        header_layout.addWidget(header_title)
        header_layout.addStretch()
        header_layout.addWidget(self.clock_label)
        content_layout.addWidget(header_bar)
        content_layout.addWidget(self.stack)
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #eef2f8;
            }
            QWidget#SideMenu {
                background-color: #1f2d3d;
            }
            QWidget#SideMenu QPushButton {
                font-weight: 600;
            }
            QLabel#SideMenuTitle {
                color: #f5f8ff;
                font-size: 18px;
                font-weight: 700;
                padding: 0 6px;
            }
            QWidget#ContentArea {
                background-color: #f9fbff;
            }
            QWidget#HeaderBar {
                background-color: #ffffff;
                border-radius: 16px;
                border: 1px solid #d7e1f0;
            }
            QLabel#HeaderTitle {
                font-size: 20px;
                font-weight: 700;
                color: #1f2d3d;
            }
            QLabel#HeaderClock {
                font-size: 16px;
                color: #0a84ff;
                font-weight: 600;
            }
            QLabel#TestCountLabel {
                font-weight: 700;
                color: #1f2d3d;
            }
            QWidget#TestsControlBar {
                background-color: rgba(46, 134, 222, 0.12);
                border: 1px solid #c7d7f0;
                border-radius: 12px;
            }
            QWidget#TestsControlBar QPushButton {
                background-color: transparent;
                color: #176b3a;
                border: 1px solid #1E8449;
                border-radius: 8px;
                padding: 6px 14px;
            }
            QWidget#TestsControlBar QPushButton:disabled {
                color: #8aa2c0;
                border-color: #b1c4dd;
            }
            QWidget#RegisterButtonBar {
                background-color: #ffffff;
                border: 1px solid #d7e1f0;
                border-radius: 16px;
            }
            QWidget#RegisterButtonBar QPushButton {
                min-height: 42px;
                font-size: 14px;
            }
            QGroupBox {
                border: 1px solid #dbe4f3;
                border-radius: 12px;
                margin-top: 12px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                color: #1f2d3d;
                font-weight: 600;
            }
            QGroupBox[categoryGroup="true"] {
                background-color: #eef4ff;
                border-color: #b8cbea;
            }
            QGroupBox[categoryGroup="true"]::title {
                color: #1c3f66;
                font-weight: 700;
            }
            QLabel#OrderInfoValue {
                font-weight: 600;
                color: #1f2d3d;
            }
            QLineEdit, QComboBox, QTextEdit, QDateEdit, QSpinBox {
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                padding: 6px 8px;
                background: #ffffff;
            }
            QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QDateEdit:focus, QSpinBox:focus {
                border-color: #3584e4;
            }
            QPushButton {
                background-color: #2e86de;
                color: white;
                border-radius: 10px;
                padding: 10px 16px;
                font-weight: 600;
            }
            QPushButton:hover:!disabled {
                background-color: #1b4f72;
            }
            QPushButton:disabled {
                background-color: #c5d3e6;
                color: #f5f6fa;
            }
            QTableWidget {
                background-color: #ffffff;
            }
            """
        )
        # 1. Página de Registro de Pacientes
        self.page_registro = QWidget(); self.init_registro_page()
        self.stack.addWidget(self.page_registro)
        btn_reg = self._create_nav_button("Registro", self.page_registro)
        side_menu_layout.addWidget(btn_reg)
        # 2. Página de Ingreso de Resultados
        self.page_resultados = QWidget(); self.init_resultados_page()
        self.stack.addWidget(self.page_resultados)
        btn_res = self._create_nav_button("Anotar Resultados", self.page_resultados)
        side_menu_layout.addWidget(btn_res)
        # 3. Página de Emisión de Resultados
        self.page_emitir = QWidget(); self.init_emitir_page()
        self.stack.addWidget(self.page_emitir)
        btn_emit = self._create_nav_button("Emitir Resultados", self.page_emitir)
        side_menu_layout.addWidget(btn_emit)
        # 4. Página de Análisis de Datos
        self.page_analisis = QWidget(); self.init_analisis_page()
        self.stack.addWidget(self.page_analisis)
        btn_an = self._create_nav_button("Análisis de Datos", self.page_analisis)
        side_menu_layout.addWidget(btn_an)
        # 5. Página de Configuración (solo visible para superusuario)
        if self.user['role'] == 'super':
            self.page_config = QWidget(); self.init_config_page()
            self.stack.addWidget(self.page_config)
            btn_conf = self._create_nav_button("Configuración", self.page_config)
            side_menu_layout.addWidget(btn_conf)
        side_menu_layout.addStretch()
        main_layout.addWidget(side_menu_widget)
        main_layout.addWidget(content_widget)
        self.setCentralWidget(central_widget)
        self.stack.setCurrentWidget(self.page_registro)  # Mostrar la sección de registro al inicio
        self._update_nav_styles()
        # Actualizar datos dinámicos al cambiar de página
        self.stack.currentChanged.connect(self.on_page_changed)
        # Variables auxiliares
        self.order_fields = {}        # Campos de resultado dinámicos por examen
        self.selected_order_id = None # Orden seleccionada actualmente en resultados
        self.last_order_registered = None  # Última orden registrada (para enlace rápido a resultados)
        self.pending_orders_cache = []    # Lista cacheada de órdenes pendientes para facilitar filtros
        self.completed_orders_cache = []  # Lista cacheada de órdenes completadas
        self._activity_cache = {"data": [], "description": "", "start": None, "end": None}
        # Reloj en tiempo real para la ventana principal
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start(1000)
        self._update_clock()
    def on_page_changed(self, index):
        current_widget = self.stack.widget(index)
        if current_widget == self.page_resultados:
            self.populate_pending_orders()
        elif current_widget == self.page_emitir:
            self.populate_completed_orders()
        elif current_widget == self.page_analisis:
            self.refresh_statistics()
        self._update_nav_styles()

    def _create_nav_button(self, text, page_widget):
        button = QPushButton(text)
        button.setCursor(Qt.PointingHandCursor)
        button.setStyleSheet(self.nav_button_default_style)
        button.clicked.connect(lambda: self.stack.setCurrentWidget(page_widget))
        self.nav_buttons[page_widget] = button
        return button

    def _update_nav_styles(self):
        current_widget = self.stack.currentWidget()
        for widget, button in self.nav_buttons.items():
            if widget == current_widget:
                button.setStyleSheet(self.nav_button_active_style)
            else:
                button.setStyleSheet(self.nav_button_default_style)
    def _update_clock(self):
        self.clock_label.setText(QDateTime.currentDateTime().toString("dd/MM/yyyy HH:mm:ss"))

    def _ensure_output_directory(self, category, filename=None):
        base_dir = os.path.join(os.getcwd(), "documentos")
        mapping = {
            "informes": "informes",
            "registros": "registros",
            "exportaciones": "exportaciones"
        }
        subdir = mapping.get(category, category)
        target_dir = os.path.join(base_dir, subdir)
        os.makedirs(target_dir, exist_ok=True)
        if filename:
            return os.path.join(target_dir, filename)
        return target_dir

    def _format_user_identity_for_delivery(self):
        lines = []
        full_name = (self.user.get('full_name') or '').strip()
        profession = (self.user.get('profession') or '').strip()
        license_code = (self.user.get('license') or '').strip()
        if full_name:
            lines.append(full_name)
        credentials = " / ".join(part for part in (profession, license_code) if part)
        if credentials:
            lines.append(credentials)
        if not lines:
            lines.append(self.user.get('username', ''))
        return "\n".join(lines)
    def init_registro_page(self):
        page_layout = QVBoxLayout(self.page_registro)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(20)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        page_layout.addWidget(scroll_area, 1)

        scroll_content = QWidget()
        scroll_area.setWidget(scroll_content)
        layout = QVBoxLayout(scroll_content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(24)

        top_layout = QHBoxLayout()
        top_layout.setSpacing(24)
        # Formulario de datos del paciente con dos columnas para reducir el scroll
        form_container = QWidget()
        form_grid = QGridLayout(form_container)
        form_grid.setContentsMargins(0, 0, 0, 0)
        form_grid.setHorizontalSpacing(20)
        form_grid.setVerticalSpacing(12)
        form_grid.setColumnStretch(0, 0)
        form_grid.setColumnStretch(1, 1)
        form_grid.setColumnStretch(2, 0)
        form_grid.setColumnStretch(3, 1)

        def add_form_row(row, column, label_text, widget):
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            form_grid.addWidget(label, row, column * 2)
            form_grid.addWidget(widget, row, column * 2 + 1)

        left_row = 0
        right_row = 0
        self.input_doc_type = QComboBox(); self.input_doc_type.addItems(["DNI", "Carnet Ext.", "Pasaporte"])
        self.input_doc_number = QLineEdit()
        btn_search = QPushButton("Buscar"); btn_search.setFixedWidth(60)
        btn_search.clicked.connect(self.autofill_patient)
        doc_hlayout = QHBoxLayout()
        doc_hlayout.setContentsMargins(0, 0, 0, 0)
        doc_hlayout.addWidget(self.input_doc_type); doc_hlayout.addWidget(self.input_doc_number); doc_hlayout.addWidget(btn_search)
        doc_widget = QWidget(); doc_widget.setLayout(doc_hlayout)
        add_form_row(left_row, 0, "Documento:", doc_widget); left_row += 1
        self.input_first_name = QLineEdit(); add_form_row(left_row, 0, "Nombre:", self.input_first_name); left_row += 1
        self.input_last_name = QLineEdit(); add_form_row(left_row, 0, "Apellidos:", self.input_last_name); left_row += 1
        # Fecha de nacimiento y edad calculada automáticamente (editable)
        self.input_birth_date = QDateEdit()
        self.input_birth_date.setDisplayFormat("dd/MM/yyyy")
        self.input_birth_date.setCalendarPopup(True)
        self.input_birth_date.setDate(QDate.currentDate())
        self.input_birth_date.dateChanged.connect(self.update_age_from_birth_date)
        add_form_row(left_row, 0, "F. Nacimiento:", self.input_birth_date); left_row += 1
        self.input_age = QLineEdit()
        self.input_age.setPlaceholderText("Edad estimada")
        add_form_row(left_row, 0, "Edad:", self.input_age); left_row += 1
        # Sexo como botones exclusivos
        self.sex_male_radio = QRadioButton("Masculino")
        self.sex_female_radio = QRadioButton("Femenino")
        self.sex_group = QButtonGroup(self.page_registro)
        self.sex_group.addButton(self.sex_male_radio)
        self.sex_group.addButton(self.sex_female_radio)
        self.sex_male_radio.setChecked(True)
        self.sex_male_radio.toggled.connect(self.update_pregnancy_visibility)
        self.sex_female_radio.toggled.connect(self.update_pregnancy_visibility)
        sex_layout = QHBoxLayout()
        sex_layout.setContentsMargins(0, 0, 0, 0)
        sex_layout.addWidget(self.sex_male_radio)
        sex_layout.addWidget(self.sex_female_radio)
        sex_layout.addStretch()
        sex_widget = QWidget(); sex_widget.setLayout(sex_layout)
        add_form_row(left_row, 0, "Sexo:", sex_widget); left_row += 1
        self.insurance_combo = QComboBox()
        self.insurance_combo.addItems(["SIS", "Particular"])
        add_form_row(left_row, 0, "Tipo de seguro:", self.insurance_combo); left_row += 1
        self.pregnancy_checkbox = QCheckBox("Paciente gestante")
        self.pregnancy_checkbox.stateChanged.connect(self.on_pregnancy_toggle)
        self.gestational_weeks_spin = QSpinBox()
        self.gestational_weeks_spin.setRange(0, 45)
        self.gestational_weeks_spin.setSuffix(" sem")
        self.gestational_weeks_spin.setEnabled(False)
        self.expected_delivery_date = QDateEdit(QDate.currentDate())
        self.expected_delivery_date.setDisplayFormat("dd/MM/yyyy")
        self.expected_delivery_date.setCalendarPopup(True)
        self.expected_delivery_date.setEnabled(False)
        self.pregnancy_container = QWidget()
        pregnancy_layout = QHBoxLayout(self.pregnancy_container)
        pregnancy_layout.setContentsMargins(0, 0, 0, 0)
        pregnancy_layout.addWidget(self.pregnancy_checkbox)
        pregnancy_layout.addSpacing(8)
        pregnancy_layout.addWidget(QLabel("Edad gestacional:"))
        pregnancy_layout.addWidget(self.gestational_weeks_spin)
        pregnancy_layout.addSpacing(8)
        pregnancy_layout.addWidget(QLabel("FPP:"))
        pregnancy_layout.addWidget(self.expected_delivery_date)
        pregnancy_layout.addStretch()
        add_form_row(left_row, 0, "Gestación:", self.pregnancy_container); left_row += 1
        self.update_pregnancy_visibility()
        # Procedencia con opción rápida P.S Iñapari u otros
        self.origin_combo = QComboBox()
        self.origin_combo.addItems(["P.S Iñapari", "Otros"])
        self.origin_combo.currentIndexChanged.connect(self.on_origin_changed)
        self.input_origin_other = QLineEdit()
        self.input_origin_other.setPlaceholderText("Especifique procedencia")
        self.input_origin_other.setEnabled(False)
        origin_layout = QHBoxLayout()
        origin_layout.setContentsMargins(0, 0, 0, 0)
        origin_layout.addWidget(self.origin_combo)
        origin_layout.addWidget(self.input_origin_other)
        origin_widget = QWidget(); origin_widget.setLayout(origin_layout)
        add_form_row(right_row, 1, "Procedencia:", origin_widget); right_row += 1
        self.input_hcl = QLineEdit(); add_form_row(right_row, 1, "HCL:", self.input_hcl); right_row += 1
        self.input_height = QLineEdit(); self.input_height.setPlaceholderText("cm")
        add_form_row(right_row, 1, "Talla (cm):", self.input_height); right_row += 1
        self.input_weight = QLineEdit(); self.input_weight.setPlaceholderText("kg")
        add_form_row(right_row, 1, "Peso (kg):", self.input_weight); right_row += 1
        self.input_blood_pressure = QLineEdit(); self.input_blood_pressure.setPlaceholderText("ej. 120/80")
        add_form_row(right_row, 1, "Presión Art.:", self.input_blood_pressure); right_row += 1
        self.input_diagnosis = QLineEdit(); self.input_diagnosis.setPlaceholderText("Ej. Síndrome febril")
        add_form_row(right_row, 1, "Diagnóstico presuntivo:", self.input_diagnosis); right_row += 1
        self.input_observations = QLineEdit()
        self.input_observations.setPlaceholderText("Observaciones (laboratorio)")
        self.input_observations.setText("N/A")
        obs_layout = QHBoxLayout()
        obs_layout.setContentsMargins(0, 0, 0, 0)
        obs_layout.addWidget(self.input_observations)
        btn_obs_na = QPushButton("Sin obs.")
        btn_obs_na.setFixedWidth(90)
        btn_obs_na.clicked.connect(lambda: self.input_observations.setText("N/A"))
        obs_layout.addWidget(btn_obs_na)
        obs_widget = QWidget(); obs_widget.setLayout(obs_layout)
        add_form_row(right_row, 1, "Observaciones:", obs_widget); right_row += 1
        self.sample_date_edit = QDateEdit()
        self.sample_date_edit.setDisplayFormat("dd/MM/yyyy")
        self.sample_date_edit.setCalendarPopup(True)
        self.sample_date_edit.setDate(QDate.currentDate())
        self.sample_today_checkbox = QCheckBox("Hoy")
        self.sample_today_checkbox.setChecked(True)
        self.sample_today_checkbox.stateChanged.connect(self.on_sample_today_toggle)
        self.sample_date_edit.setEnabled(False)
        sample_layout = QHBoxLayout()
        sample_layout.setContentsMargins(0, 0, 0, 0)
        sample_layout.addWidget(self.sample_date_edit)
        sample_layout.addWidget(self.sample_today_checkbox)
        sample_layout.addStretch()
        sample_widget = QWidget(); sample_widget.setLayout(sample_layout)
        add_form_row(right_row, 1, "F. muestra:", sample_widget); right_row += 1
        self.input_requested_by = QComboBox()
        self.input_requested_by.setEditable(True)
        self.input_requested_by.setInsertPolicy(QComboBox.NoInsert)
        self.input_requested_by.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        add_form_row(right_row, 1, "Solicitante:", self.input_requested_by); right_row += 1
        # Placeholder después de crear el combo editable
        if self.input_requested_by.lineEdit():
            self.input_requested_by.lineEdit().setPlaceholderText("Seleccione o escriba el médico solicitante")
        self.populate_requesters()
        top_layout.addWidget(form_container, 2)
        # Listado de pruebas por categoría (con scroll)
        tests_scroll = QScrollArea(); tests_scroll.setWidgetResizable(True)
        tests_container = QWidget()
        tests_layout = QGridLayout(tests_container)
        tests_layout.setContentsMargins(0, 0, 0, 0)
        tests_layout.setHorizontalSpacing(16)
        tests_layout.setVerticalSpacing(16)
        tests_layout.setColumnStretch(0, 1)
        tests_layout.setColumnStretch(1, 1)
        self.test_checkboxes = []
        tests_controls_widget = QWidget()
        tests_controls_widget.setObjectName("TestsControlBar")
        tests_controls_layout = QHBoxLayout(tests_controls_widget)
        tests_controls_layout.setContentsMargins(16, 12, 16, 12)
        tests_controls_layout.setSpacing(12)
        self.test_selection_count_label = QLabel("Pruebas seleccionadas: 0")
        self.test_selection_count_label.setObjectName("TestCountLabel")
        tests_controls_layout.addWidget(self.test_selection_count_label)
        tests_controls_layout.addStretch()
        self.clear_tests_button = QPushButton("Borrar todas las pruebas")
        self.clear_tests_button.setToolTip("Desmarca todas las pruebas seleccionadas")
        self.clear_tests_button.clicked.connect(self.clear_selected_tests)
        tests_controls_layout.addWidget(self.clear_tests_button)
        # Obtener pruebas agrupadas por categoría de la BD
        categories = {}
        self.labdb.cur.execute("SELECT category, name FROM tests")
        for cat, name in self.labdb.cur.fetchall():
            categories.setdefault(cat, []).append(name)
        ordered_categories = sorted(
            categories.items(),
            key=lambda item: (
                CATEGORY_DISPLAY_ORDER.index(item[0]) if item[0] in CATEGORY_DISPLAY_ORDER else len(CATEGORY_DISPLAY_ORDER),
                item[0]
            )
        )
        columns = 2
        for index, (cat, tests) in enumerate(ordered_categories):
            group_box = QGroupBox(cat)
            group_box.setProperty("categoryGroup", True)
            group_layout = QVBoxLayout()
            group_layout.setContentsMargins(16, 12, 16, 16)
            group_layout.setSpacing(8)
            for test_name in sorted(tests):
                cb = QCheckBox(test_name)
                group_layout.addWidget(cb)
                self.test_checkboxes.append(cb)
                cb.toggled.connect(self.update_test_selection_count)
            group_box.setLayout(group_layout)
            row = index // columns
            column = index % columns
            tests_layout.addWidget(group_box, row, column)
        total_rows = (len(ordered_categories) + columns - 1) // columns
        tests_layout.setRowStretch(total_rows, 1)
        tests_scroll.setWidget(tests_container)
        tests_panel = QWidget()
        tests_panel_layout = QVBoxLayout(tests_panel)
        tests_panel_layout.setContentsMargins(0, 0, 0, 0)
        tests_panel_layout.setSpacing(16)
        tests_panel_layout.addWidget(tests_controls_widget)
        tests_panel_layout.addWidget(tests_scroll)
        top_layout.addWidget(tests_panel, 3)
        layout.addLayout(top_layout)
        layout.addStretch()
        self.update_test_selection_count()
        # Botones de acción
        btn_register = QPushButton("Registrar paciente y pruebas")
        btn_new = QPushButton("Registrar nuevo paciente")
        btn_to_results = QPushButton("Anotar resultado de este paciente")
        btn_to_results.setEnabled(False)
        btn_register.clicked.connect(lambda: self.register_patient(btn_to_results))
        btn_new.clicked.connect(self.clear_registration_form)
        btn_to_results.clicked.connect(self.go_to_results)
        button_bar = QWidget()
        button_bar.setObjectName("RegisterButtonBar")
        btns_layout = QHBoxLayout(button_bar)
        btns_layout.setContentsMargins(20, 16, 20, 16)
        btns_layout.setSpacing(16)
        btns_layout.addWidget(btn_register)
        btns_layout.addWidget(btn_new)
        btns_layout.addWidget(btn_to_results)
        page_layout.addWidget(button_bar, 0)
    def populate_requesters(self, keep_current=False):
        current_text = self.input_requested_by.currentText().strip() if keep_current else ""
        items_lower = set()
        self.input_requested_by.blockSignals(True)
        self.input_requested_by.clear()
        self.input_requested_by.addItem("N/A")
        for requester in self.labdb.get_distinct_requesters():
            clean = requester.strip()
            if clean and clean.lower() not in ("n/a", "na"):
                self.input_requested_by.addItem(clean)
                items_lower.add(clean.lower())
        self.input_requested_by.blockSignals(False)
        if keep_current and current_text:
            idx = self.input_requested_by.findText(current_text)
            if idx == -1 and current_text.lower() not in items_lower:
                self.input_requested_by.addItem(current_text)
                idx = self.input_requested_by.count() - 1
            if idx >= 0:
                self.input_requested_by.setCurrentIndex(idx)
        else:
            self.input_requested_by.setCurrentIndex(0)
        if self.input_requested_by.lineEdit():
            if self.input_requested_by.currentIndex() <= 0:
                self.input_requested_by.lineEdit().clear()
            else:
                self.input_requested_by.lineEdit().setText(self.input_requested_by.currentText())
            self.input_requested_by.lineEdit().setPlaceholderText("Seleccione o escriba el médico solicitante")

    def update_test_selection_count(self):
        count = sum(1 for cb in getattr(self, 'test_checkboxes', []) if cb.isChecked())
        if hasattr(self, 'test_selection_count_label'):
            self.test_selection_count_label.setText(f"Pruebas seleccionadas: {count}")
        if hasattr(self, 'clear_tests_button'):
            self.clear_tests_button.setEnabled(count > 0)

    def clear_selected_tests(self):
        for cb in getattr(self, 'test_checkboxes', []):
            cb.blockSignals(True)
            cb.setChecked(False)
            cb.blockSignals(False)
        self.update_test_selection_count()
    def update_age_from_birth_date(self, qdate=None):
        if qdate is None:
            qdate = self.input_birth_date.date()
        if isinstance(qdate, QDate) and qdate.isValid():
            years = max(0, qdate.daysTo(QDate.currentDate()) // 365)
            self.input_age.setText(str(years))
        else:
            self.input_age.clear()
    def on_origin_changed(self, index):
        use_other = self.origin_combo.currentText() == "Otros"
        self.input_origin_other.setEnabled(use_other)
        if not use_other:
            self.input_origin_other.clear()

    def on_sample_today_toggle(self, state):
        use_today = state == Qt.Checked
        if hasattr(self, 'sample_date_edit'):
            self.sample_date_edit.setEnabled(not use_today)
            if use_today:
                self.sample_date_edit.setDate(QDate.currentDate())
    def on_pregnancy_toggle(self, state):
        is_checked = state == Qt.Checked
        if hasattr(self, 'gestational_weeks_spin'):
            self.gestational_weeks_spin.setEnabled(is_checked)
            if not is_checked:
                self.gestational_weeks_spin.setValue(0)
        if hasattr(self, 'expected_delivery_date'):
            self.expected_delivery_date.setEnabled(is_checked)
            if not is_checked:
                self.expected_delivery_date.setDate(QDate.currentDate())

    def update_pregnancy_visibility(self):
        is_female = self.sex_female_radio.isChecked() if hasattr(self, 'sex_female_radio') else False
        if hasattr(self, 'pregnancy_container'):
            self.pregnancy_container.setVisible(is_female)
        if hasattr(self, 'pregnancy_checkbox'):
            self.pregnancy_checkbox.setEnabled(is_female)
            if not is_female:
                self.pregnancy_checkbox.blockSignals(True)
                self.pregnancy_checkbox.setChecked(False)
                self.pregnancy_checkbox.blockSignals(False)
                self.on_pregnancy_toggle(Qt.Unchecked)
            else:
                state = Qt.Checked if self.pregnancy_checkbox.isChecked() else Qt.Unchecked
                self.on_pregnancy_toggle(state)
    def get_current_origin(self):
        if self.origin_combo.currentText() == "Otros":
            other = self.input_origin_other.text().strip()
            return other if other else "Otros"
        return "P.S Iñapari"
    def set_origin_value(self, value):
        if value and value.strip().lower() not in ("p.s iñapari", "ps iñapari", "p.s. iñapari"):
            self.origin_combo.setCurrentIndex(1)
            self.input_origin_other.setEnabled(True)
            self.input_origin_other.setText(value)
        else:
            self.origin_combo.setCurrentIndex(0)
            self.input_origin_other.setEnabled(False)
            self.input_origin_other.clear()
    def _format_number(self, value):
        if value in (None, ""):
            return ""
        if isinstance(value, float):
            if value.is_integer():
                return str(int(value))
            return f"{value:.2f}".rstrip('0').rstrip('.')
        return str(value)
    def _format_date_display(self, value, placeholder="—"):
        if value in (None, ""):
            return placeholder
        if isinstance(value, QDate):
            if value.isValid():
                return value.toString("dd/MM/yyyy")
            return placeholder
        if isinstance(value, datetime.date) and not isinstance(value, datetime.datetime):
            return value.strftime("%d/%m/%Y")
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
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

    def _format_datetime_display(self, value, placeholder="—", include_seconds=False):
        if value in (None, ""):
            return placeholder
        if isinstance(value, QDateTime):
            if value.isValid():
                fmt = "dd/MM/yyyy HH:mm:ss" if include_seconds else "dd/MM/yyyy HH:mm"
                return value.toString(fmt)
            return placeholder
        if isinstance(value, datetime.datetime):
            fmt = "%d/%m/%Y %H:%M:%S" if include_seconds else "%d/%m/%Y %H:%M"
            return value.strftime(fmt)
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                parsed = datetime.datetime.strptime(str(value), fmt)
                fmt_out = "%d/%m/%Y %H:%M:%S" if include_seconds else "%d/%m/%Y %H:%M"
                return parsed.strftime(fmt_out)
            except (ValueError, TypeError):
                continue
        try:
            parsed = datetime.datetime.fromisoformat(str(value))
            fmt_out = "%d/%m/%Y %H:%M:%S" if include_seconds else "%d/%m/%Y %H:%M"
            return parsed.strftime(fmt_out)
        except Exception:
            return str(value)
    def autofill_patient(self):
        doc_type = self.input_doc_type.currentText()
        doc_number = self.input_doc_number.text().strip()
        if doc_number == "":
            return
        patient = self.labdb.find_patient(doc_type, doc_number)
        if patient:
            # Rellenar campos con datos existentes
            (_, _, _, first_name, last_name, birth_date, sex, origin, hcl,
             height, weight, blood_pressure, is_pregnant, gest_age, expected_delivery) = patient
            self.input_first_name.setText((first_name or "").upper()); self.input_last_name.setText((last_name or "").upper())
            if birth_date:
                bd = QDate.fromString(birth_date, "yyyy-MM-dd")
                if bd.isValid():
                    self.input_birth_date.setDate(bd)
                else:
                    self.input_birth_date.setDate(QDate.currentDate())
                    self.input_age.clear()
            else:
                self.input_birth_date.setDate(QDate.currentDate())
                self.input_age.clear()
            if sex == "Femenino":
                self.sex_female_radio.setChecked(True)
            else:
                self.sex_male_radio.setChecked(True)
            self.update_pregnancy_visibility()
            self.set_origin_value(origin or "")
            self.input_hcl.setText(hcl or "")
            self.input_height.setText(self._format_number(height))
            self.input_weight.setText(self._format_number(weight))
            self.input_blood_pressure.setText(blood_pressure or "")
            preg_flag = bool(is_pregnant) if is_pregnant not in (None, "") else False
            self.pregnancy_checkbox.blockSignals(True)
            self.pregnancy_checkbox.setChecked(preg_flag)
            self.pregnancy_checkbox.blockSignals(False)
            self.on_pregnancy_toggle(Qt.Checked if preg_flag else Qt.Unchecked)
            if preg_flag:
                if gest_age is not None:
                    try:
                        self.gestational_weeks_spin.setValue(int(gest_age))
                    except (TypeError, ValueError):
                        self.gestational_weeks_spin.setValue(0)
                if expected_delivery:
                    edd = QDate.fromString(expected_delivery, "yyyy-MM-dd")
                    if edd.isValid():
                        self.expected_delivery_date.setDate(edd)
                    else:
                        self.expected_delivery_date.setDate(QDate.currentDate())
            else:
                self.gestational_weeks_spin.setValue(0)
                self.expected_delivery_date.setDate(QDate.currentDate())
            QMessageBox.information(self, "Paciente encontrado", "Datos del paciente cargados.")
    def register_patient(self, btn_to_results):
        doc_type = self.input_doc_type.currentText()
        doc_number = self.input_doc_number.text().strip()
        if doc_number == "" or self.input_first_name.text().strip() == "" or self.input_last_name.text().strip() == "":
            QMessageBox.warning(self, "Datos incompletos", "Ingrese al menos Documento, Nombre y Apellidos.")
            return
        # Validar formato de documento
        if doc_type == "DNI":
            if len(doc_number) != 8 or not doc_number.isdigit():
                QMessageBox.warning(self, "Documento inválido", "El DNI debe tener 8 dígitos.")
                return
        else:
            if len(doc_number) > 20:
                QMessageBox.warning(self, "Documento inválido", f"El {doc_type} no debe exceder 20 caracteres.")
                return
        # Obtener datos del formulario
        first_name = self.input_first_name.text().strip().upper()
        last_name = self.input_last_name.text().strip().upper()
        self.input_first_name.setText(first_name)
        self.input_last_name.setText(last_name)
        birth_date = self.input_birth_date.date().toString("yyyy-MM-dd")
        sex = "Femenino" if self.sex_female_radio.isChecked() else "Masculino"
        insurance_type = self.insurance_combo.currentText() if hasattr(self, 'insurance_combo') else "SIS"
        origin = self.get_current_origin()
        if self.origin_combo.currentText() == "Otros" and (not self.input_origin_other.text().strip()):
            QMessageBox.warning(self, "Procedencia requerida", "Indique la procedencia del paciente cuando seleccione 'Otros'.")
            return
        hcl = self.input_hcl.text().strip()
        height = self.input_height.text().strip()
        weight = self.input_weight.text().strip()
        bp = self.input_blood_pressure.text().strip()
        diagnosis = self.input_diagnosis.text().strip()
        observations = self.input_observations.text().strip() or "N/A"
        requested_by_text = self.input_requested_by.currentText().strip() if self.input_requested_by.count() else ""
        if requested_by_text == "":
            requested_by_text = "N/A"
        if diagnosis == "":
            diagnosis = "N/A"
        age_text = self.input_age.text().strip()
        if age_text:
            try:
                age_years = int(age_text)
            except ValueError:
                QMessageBox.warning(self, "Edad inválida", "Ingrese la edad en años utilizando solo números enteros.")
                return
        else:
            age_years = None
        try:
            height_val = float(height) if height else None
        except:
            height_val = None
        try:
            weight_val = float(weight) if weight else None
        except:
            weight_val = None
        is_pregnant = self.pregnancy_checkbox.isChecked() if hasattr(self, 'pregnancy_checkbox') else False
        gest_age_weeks = None
        if is_pregnant and hasattr(self, 'gestational_weeks_spin'):
            gest_age_weeks = self.gestational_weeks_spin.value()
        expected_delivery_date = None
        if is_pregnant and hasattr(self, 'expected_delivery_date'):
            edd_qdate = self.expected_delivery_date.date()
            if isinstance(edd_qdate, QDate) and edd_qdate.isValid():
                expected_delivery_date = edd_qdate.toString("yyyy-MM-dd")
        sample_date = None
        if hasattr(self, 'sample_date_edit'):
            qdate = self.sample_date_edit.date()
            if isinstance(qdate, QDate) and qdate.isValid():
                sample_date = qdate.toString("yyyy-MM-dd")
        if hasattr(self, 'sample_today_checkbox') and self.sample_today_checkbox.isChecked():
            sample_date = QDate.currentDate().toString("yyyy-MM-dd")

        # Insertar o actualizar paciente en BD
        patient_id = self.labdb.add_or_update_patient(
            doc_type,
            doc_number,
            first_name,
            last_name,
            birth_date,
            sex,
            origin,
            hcl,
            height_val,
            weight_val,
            bp,
            is_pregnant=is_pregnant,
            gestational_age_weeks=gest_age_weeks,
            expected_delivery_date=expected_delivery_date
        )

        # Obtener lista de pruebas seleccionadas
        selected_tests = [cb.text() for cb in getattr(self, 'test_checkboxes', []) if cb.isChecked()]

        if not selected_tests:
            QMessageBox.warning(self, "Sin pruebas", "Seleccione al menos una prueba.")
            return
        duplicate_order = self.labdb.find_recent_duplicate_order(patient_id, selected_tests)
        if duplicate_order:
            reply = QMessageBox.question(
                self,
                "Posible duplicado",
                f"Existe una orden reciente (#{duplicate_order}) con las mismas pruebas. ¿Desea continuar?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        # Crear orden en BD con las pruebas seleccionadas
        order_id = self.labdb.add_order_with_tests(
            patient_id,
            selected_tests,
            self.user['id'],
            observations=observations,
            requested_by=requested_by_text,
            diagnosis=diagnosis,
            insurance_type=insurance_type,
            age_years=age_years,
            sample_date=sample_date
        )
        sample_display = self._format_date_display(sample_date, "-")
        patient_display = f"{first_name} {last_name}".strip()
        if not patient_display:
            patient_display = "Paciente registrado"
        message_lines = [
            patient_display,
            f"F. toma de muestra: {sample_display}",
            f"Orden #{order_id} registrada correctamente."
        ]
        QMessageBox.information(self, "Registro exitoso", "\n".join(message_lines))
        # Habilitar botón para ir a anotar resultados de esta orden
        btn_to_results.setEnabled(True)
        self.last_order_registered = order_id
        # Actualizar historial de solicitantes para próximas atenciones
        self.populate_requesters(keep_current=True)
    def clear_registration_form(self):
        # Limpiar todos los campos del formulario de registro
        self.input_doc_number.clear(); self.input_first_name.clear(); self.input_last_name.clear()
        self.input_birth_date.blockSignals(True)
        self.input_birth_date.setDate(QDate.currentDate())
        self.input_birth_date.blockSignals(False)
        self.input_age.clear()
        self.sex_male_radio.setChecked(True)
        if hasattr(self, 'insurance_combo'):
            self.insurance_combo.setCurrentIndex(0)
        self.set_origin_value("P.S Iñapari")
        self.input_hcl.clear()
        self.input_height.clear(); self.input_weight.clear(); self.input_blood_pressure.clear()
        self.input_diagnosis.clear()
        self.input_observations.setText("N/A")
        if hasattr(self, 'pregnancy_checkbox'):
            self.pregnancy_checkbox.blockSignals(True)
            self.pregnancy_checkbox.setChecked(False)
            self.pregnancy_checkbox.blockSignals(False)
            self.on_pregnancy_toggle(Qt.Unchecked)
        if hasattr(self, 'gestational_weeks_spin'):
            self.gestational_weeks_spin.setValue(0)
        if hasattr(self, 'expected_delivery_date'):
            self.expected_delivery_date.setDate(QDate.currentDate())
        if hasattr(self, 'sample_date_edit'):
            self.sample_date_edit.blockSignals(True)
            self.sample_date_edit.setDate(QDate.currentDate())
            self.sample_date_edit.blockSignals(False)
        if hasattr(self, 'sample_today_checkbox'):
            self.sample_today_checkbox.setChecked(True)
        if self.input_requested_by.count():
            self.input_requested_by.setCurrentIndex(0)
        if self.input_requested_by.lineEdit():
            self.input_requested_by.lineEdit().clear()
        for cb in getattr(self, 'test_checkboxes', []):
            cb.setChecked(False)
        self.update_pregnancy_visibility()
        self.update_test_selection_count()

    def go_to_results(self):
        # Navegar a la página de resultados para la última orden registrada
        if self.last_order_registered:
            self.stack.setCurrentWidget(self.page_resultados)
            self.populate_pending_orders()
            # Seleccionar automáticamente la orden recién creada en el combo
            self._select_order_in_combo(self.combo_orders, self.last_order_registered)
            self.load_order_fields()
    def init_resultados_page(self):
        layout = QVBoxLayout(self.page_resultados)
        search_layout = QHBoxLayout()
        search_label = QLabel("Buscar:")
        self.order_search_input = QLineEdit()
        self.order_search_input.setPlaceholderText("Nombre, documento o # de orden")
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.order_search_input, 1)
        sort_label = QLabel("Ordenar:")
        self.pending_sort_combo = QComboBox()
        self.pending_sort_combo.addItems([
            "Fecha (recientes primero)",
            "Fecha (antiguas primero)",
            "Número de orden (descendente)",
            "Número de orden (ascendente)"
        ])
        search_layout.addWidget(sort_label)
        search_layout.addWidget(self.pending_sort_combo)
        search_layout.addStretch()
        layout.addLayout(search_layout)
        top_layout = QHBoxLayout()
        lbl = QLabel("Orden pendiente:")
        self.combo_orders = QComboBox()
        self.combo_orders.setMinimumWidth(350)
        btn_load = QPushButton("Cargar")
        self.results_add_tests_btn = QPushButton("Agregar pruebas")
        self.results_add_tests_btn.setEnabled(False)
        self.pending_overview_btn = QPushButton("Pendientes (0)")
        self.pending_overview_btn.setEnabled(False)
        btn_delete_order = QPushButton("Eliminar orden")
        btn_delete_order.setStyleSheet(
            "QPushButton { background-color: #ffe8e6; color: #c0392b; border-radius: 10px; border: 1px solid #c0392b; }"
            "QPushButton:hover:!disabled { background-color: #fbd1ce; }"
        )
        top_layout.addWidget(lbl)
        top_layout.addWidget(self.combo_orders)
        top_layout.addWidget(btn_load)
        top_layout.addWidget(self.results_add_tests_btn)
        top_layout.addWidget(self.pending_overview_btn)
        top_layout.addWidget(btn_delete_order)
        layout.addLayout(top_layout)
        # Área scrollable para campos de resultados
        self.results_area = QScrollArea()
        self.results_area.setWidgetResizable(True)
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setContentsMargins(10, 10, 10, 10)
        self.results_layout.setSpacing(14)
        self.results_area.setWidget(self.results_container)
        layout.addWidget(self.results_area)
        btn_save = QPushButton("Guardar Resultados")
        layout.addWidget(btn_save)
        btn_load.clicked.connect(self.load_order_fields)
        btn_save.clicked.connect(self.save_results)
        btn_delete_order.clicked.connect(self.delete_order_from_results)
        self.results_add_tests_btn.clicked.connect(self.add_tests_to_selected_order)
        self.pending_overview_btn.clicked.connect(self.show_pending_tests_overview)
        self.order_search_input.textChanged.connect(self.filter_pending_orders)
        self.pending_sort_combo.currentIndexChanged.connect(
            lambda: self.filter_pending_orders(self.order_search_input.text(), prefer_order=self.selected_order_id)
        )
        self.update_pending_overview_button()
    def populate_pending_orders(self):
        # Llenar combo de órdenes pendientes (no completadas)
        pending = self.labdb.get_pending_orders()
        self.pending_orders_cache = []
        for row in pending:
            oid, first, last, date, sample_date, doc_type, doc_number = row
            self.pending_orders_cache.append({
                "id": oid,
                "first_name": (first or "").upper(),
                "last_name": (last or "").upper(),
                "date": date,
                "sample_date": sample_date,
                "doc_type": doc_type or "",
                "doc_number": doc_number or ""
            })
        search_text = self.order_search_input.text() if hasattr(self, 'order_search_input') else ""
        prefer_id = self.selected_order_id or self.last_order_registered
        self.filter_pending_orders(search_text, prefer_order=prefer_id)
        self.update_pending_overview_button()
    def filter_pending_orders(self, text="", prefer_order=None):
        if not hasattr(self, 'combo_orders'):
            return
        filter_text = (text or "").strip().lower()
        current_data = self.combo_orders.currentData()
        self.combo_orders.blockSignals(True)
        self.combo_orders.clear()
        orders = getattr(self, 'pending_orders_cache', [])
        filtered_orders = []
        for order in orders:
            search_blob = " ".join([
                str(order['id']),
                order['first_name'] or "",
                order['last_name'] or "",
                order['doc_type'] or "",
                order['doc_number'] or "",
                order.get('date') or "",
                order.get('sample_date') or ""
            ]).lower()
            if filter_text in search_blob:
                filtered_orders.append(order)
        sort_mode = self.pending_sort_combo.currentIndex() if hasattr(self, 'pending_sort_combo') else 0
        sorted_orders = self._sort_orders(filtered_orders, sort_mode)
        matching_ids = [order['id'] for order in sorted_orders]
        for order in sorted_orders:
            display = self._format_order_display(order)
            self.combo_orders.addItem(display, order['id'])
        if not matching_ids:
            self.combo_orders.addItem("(No hay órdenes pendientes)", None)
        self.combo_orders.blockSignals(False)
        target_candidates = [
            prefer_order,
            current_data,
            self.selected_order_id,
            self.last_order_registered
        ]
        selected = None
        for candidate in target_candidates:
            if candidate is not None and candidate in matching_ids:
                selected = candidate
                break
        if selected is not None:
            self._select_order_in_combo(self.combo_orders, selected)
        else:
            self.combo_orders.setCurrentIndex(0)

    def update_pending_overview_button(self):
        if not hasattr(self, 'pending_overview_btn'):
            return
        try:
            count = self.labdb.count_pending_tests()
        except Exception:
            count = 0
        self.pending_overview_btn.setText(f"Pendientes ({count})")
        self.pending_overview_btn.setEnabled(count > 0)
        tooltip = "Ver lista de exámenes marcados como pendientes." if count else "No hay exámenes pendientes registrados."
        self.pending_overview_btn.setToolTip(tooltip)

    def show_pending_tests_overview(self):
        rows = []
        try:
            rows = self.labdb.get_pending_tests_overview()
        except Exception:
            rows = []
        if not rows:
            QMessageBox.information(self, "Sin pendientes", "No hay exámenes marcados como pendientes.")
            self.update_pending_overview_button()
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Exámenes pendientes")
        dialog.setModal(True)
        layout = QVBoxLayout(dialog)
        summary_label = QLabel(f"Pendientes registrados: {len(rows)}")
        summary_label.setStyleSheet("font-weight: 600; color: #2c3e50;")
        layout.addWidget(summary_label)
        table = QTableWidget(len(rows), 6)
        headers = ["Orden", "Paciente", "Documento", "Examen", "Pendiente desde", "Motivo"]
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        for row_idx, row in enumerate(rows):
            (
                order_id,
                test_name,
                first,
                last,
                doc_type,
                doc_number,
                pending_since,
                sample_issue,
                sample_date,
                order_date
            ) = row
            patient_name = " ".join(part for part in [(first or "").upper(), (last or "").upper()] if part).strip() or "-"
            doc_text = " ".join(part for part in (doc_type, doc_number) if part).strip() or "-"
            pending_display = self._format_datetime_display(pending_since, "—") if pending_since else "—"
            if pending_display == "—" and sample_date:
                pending_display = self._format_date_display(sample_date, "—")
            if pending_display == "—" and order_date:
                pending_display = self._format_datetime_display(order_date, "—")
            motive = sample_issue.strip() if isinstance(sample_issue, str) else sample_issue or "—"
            values = [
                str(order_id),
                patient_name,
                doc_text,
                test_name,
                pending_display,
                motive,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 0:
                    item.setTextAlignment(Qt.AlignCenter)
                table.setItem(row_idx, col, item)
        table.resizeColumnsToContents()
        layout.addWidget(table)
        close_btn = QDialogButtonBox(QDialogButtonBox.Close)
        close_btn.rejected.connect(dialog.reject)
        layout.addWidget(close_btn)
        dialog.resize(720, 360)
        dialog.exec_()
    def _format_order_display(self, order):
        doc_type = order.get('doc_type') or ""
        doc_number = order.get('doc_number') or ""
        doc_text = f" ({doc_type} {doc_number})" if doc_type and doc_number else ""
        first = (order.get('first_name') or "").upper()
        last = (order.get('last_name') or "").upper()
        name_text = (f"{first} {last}").strip()
        status_tag = ""
        if 'emitted' in order:
            status_tag = " [EMITIDO]" if order.get('emitted') else " [POR EMITIR]"
        order_timestamp = self._format_datetime_display(order.get('date'), "-")
        sample_display = self._format_date_display(order.get('sample_date'), "-")
        name_section = name_text if name_text else "Sin paciente"
        return (
            f"Orden #{order['id']} · {name_section}{doc_text} · "
            f"Registro: {order_timestamp} · F. muestra: {sample_display}{status_tag}"
        )
    def _select_order_in_combo(self, combo, order_id):
        for idx in range(combo.count()):
            if combo.itemData(idx) == order_id:
                combo.setCurrentIndex(idx)
                return

    def _parse_order_datetime(self, order):
        date_str = order.get('date') if isinstance(order, dict) else None
        if not date_str:
            return datetime.datetime.min
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(date_str, fmt)
            except (ValueError, TypeError):
                continue
        return datetime.datetime.min

    def _sort_orders(self, orders, sort_mode):
        if not orders:
            return []
        if sort_mode == 0:  # Fecha descendente (recientes primero)
            return sorted(
                orders,
                key=lambda o: (self._parse_order_datetime(o), o.get('id', 0)),
                reverse=True
            )
        if sort_mode == 1:  # Fecha ascendente (antiguas primero)
            return sorted(
                orders,
                key=lambda o: (self._parse_order_datetime(o), o.get('id', 0))
            )
        if sort_mode == 2:  # Número de orden descendente
            return sorted(orders, key=lambda o: o.get('id', 0), reverse=True)
        # Número de orden ascendente (predeterminado restante)
        return sorted(orders, key=lambda o: o.get('id', 0))

    def _refresh_completed_combo(self, prefer_order=None):
        if not hasattr(self, 'combo_completed'):
            return
        current_data = self.combo_completed.currentData()
        orders = getattr(self, 'completed_orders_cache', [])
        sort_mode = self.completed_sort_combo.currentIndex() if hasattr(self, 'completed_sort_combo') else 0
        sorted_orders = self._sort_orders(orders, sort_mode)
        self.combo_completed.blockSignals(True)
        self.combo_completed.clear()
        if not sorted_orders:
            self.combo_completed.addItem("(No hay resultados)", None)
            self.combo_completed.blockSignals(False)
            self.combo_completed.setCurrentIndex(0)
            return
        for order in sorted_orders:
            self.combo_completed.addItem(self._format_order_display(order), order['id'])
        def normalize_candidate(candidate):
            try:
                return int(candidate)
            except (TypeError, ValueError):
                return None
        normalized_prefer = normalize_candidate(prefer_order)
        normalized_current = normalize_candidate(current_data)
        available_ids = {order['id'] for order in sorted_orders}
        target_candidates = [normalized_prefer, normalized_current]
        selected = None
        for candidate in target_candidates:
            if candidate is not None and candidate in available_ids:
                selected = candidate
                break
        if selected is not None:
            self._select_order_in_combo(self.combo_completed, selected)
        else:
            self.combo_completed.setCurrentIndex(0)
        self.combo_completed.blockSignals(False)
    def load_order_fields(self):
        # Cargar campos de resultado para la orden seleccionada
        self._clear_results_layout()
        self.order_fields.clear()
        if hasattr(self, 'results_add_tests_btn'):
            self.results_add_tests_btn.setEnabled(False)
        data = self.combo_orders.currentData() if hasattr(self, 'combo_orders') else None
        if data is None:
            self.selected_order_id = None
            placeholder = QLabel("Seleccione una orden pendiente para registrar resultados.")
            placeholder.setStyleSheet("color: #555; font-style: italic;")
            placeholder.setWordWrap(True)
            self.results_layout.addWidget(placeholder)
            self.results_layout.addStretch()
            return
        order_id = int(data)
        self.selected_order_id = order_id
        info = self.labdb.get_order_details(order_id)
        if not info:
            empty_label = QLabel("La orden seleccionada no tiene pruebas registradas.")
            empty_label.setStyleSheet("color: #555; font-style: italic;")
            empty_label.setWordWrap(True)
            self.results_layout.addWidget(empty_label)
            self.results_layout.addStretch()
            self.populate_pending_orders()
            return
        patient_info = info.get("patient", {})
        order_info = info.get("order", {})
        rows = info.get("results", [])
        self.current_order_context = {"patient": patient_info, "order": order_info}
        if not rows:
            empty_label = QLabel("La orden seleccionada no tiene pruebas asociadas.")
            empty_label.setStyleSheet("color: #555; font-style: italic;")
            empty_label.setWordWrap(True)
            self.results_layout.addWidget(empty_label)
            self.results_layout.addStretch()
            return
        summary_group = QGroupBox("Resumen de la orden")
        summary_group.setObjectName("OrderSummaryGroup")
        summary_layout = QGridLayout(summary_group)
        summary_layout.setContentsMargins(18, 12, 18, 12)
        summary_layout.setHorizontalSpacing(18)
        summary_layout.setVerticalSpacing(10)
        summary_layout.setColumnStretch(1, 1)
        summary_layout.setColumnStretch(3, 1)

        def _add_summary(row, col, label_text, value_text):
            label = QLabel(label_text)
            label.setStyleSheet("color: #5a6b7b; font-weight: 600;")
            value = QLabel(value_text if value_text not in (None, "") else "-")
            value.setObjectName("OrderInfoValue")
            value.setWordWrap(True)
            summary_layout.addWidget(label, row, col)
            summary_layout.addWidget(value, row, col + 1)

        patient_name = patient_info.get("name") or "-"
        doc_display = " ".join(part for part in (
            patient_info.get("doc_type"),
            patient_info.get("doc_number")
        ) if part) or "-"
        order_timestamp = self._format_datetime_display(order_info.get('date'), "-")
        sample_display = self._format_date_display(order_info.get('sample_date'), "-")
        requester_display = order_info.get('requested_by') or "-"
        origin_display = (patient_info.get('origin') or '-').upper()
        insurance_display = self._format_insurance_display(order_info.get('insurance_type'))
        _add_summary(0, 0, "Paciente", patient_name)
        _add_summary(0, 2, "Documento", doc_display)
        _add_summary(1, 0, "F. registro", order_timestamp)
        _add_summary(1, 2, "F. muestra", sample_display)
        _add_summary(2, 0, "Solicitante", requester_display)
        _add_summary(2, 2, "Procedencia", origin_display)
        _add_summary(3, 0, "Seguro", insurance_display)
        fua_display = order_info.get('fua_number') or "-"
        _add_summary(3, 2, "FUA", fua_display if insurance_display != "PARTICULAR" else "No aplica")
        self.results_layout.addWidget(summary_group)
        if hasattr(self, 'results_add_tests_btn'):
            self.results_add_tests_btn.setEnabled(True)
        order_test_names = [name for (name, *_rest) in rows]
        for entry in rows:
            (
                test_name,
                raw_result,
                category,
                sample_status,
                sample_issue,
                observation,
                _entry_id,
                pending_since
            ) = entry
            template = None
            template_name = test_name
            if test_name == "Hematocrito":
                auto_mode = self._should_auto_calculate_hb(order_test_names)
                template = build_hematocrit_template(auto_mode)
                if auto_mode:
                    template_name = "Hematocrito (automático)"
                    TEST_TEMPLATES[template_name] = copy.deepcopy(template)
            else:
                base_template = TEST_TEMPLATES.get(test_name)
                if base_template is not None:
                    template = copy.deepcopy(base_template)
                elif category == "PRUEBAS RÁPIDAS":
                    template = build_bool_observation_template()
                    TEST_TEMPLATES[test_name] = copy.deepcopy(template)
            group_box = QGroupBox(test_name)
            group_box.setStyleSheet("QGroupBox { font-weight: bold; }")
            container_layout = QVBoxLayout()
            header_layout = QHBoxLayout()
            header_layout.addStretch()
            status_container = QWidget()
            status_layout = QHBoxLayout(status_container)
            status_layout.setContentsMargins(0, 0, 0, 0)
            status_layout.setSpacing(6)
            status_label = QLabel("Estado de muestra:")
            status_combo = QComboBox()
            status_combo.addItem("Recibida", "recibida")
            status_combo.addItem("Pendiente", "pendiente")
            status_combo.addItem("Rechazada", "rechazada")
            status_value = (sample_status or "recibida").strip().lower()
            idx = status_combo.findData(status_value)
            if idx >= 0:
                status_combo.setCurrentIndex(idx)
            issue_input = QLineEdit()
            issue_input.setPlaceholderText("Detalle / motivo (si aplica)")
            if sample_issue:
                issue_input.setText(str(sample_issue))
            btn_pending = QPushButton("Marcar pendiente")
            btn_pending.setStyleSheet("QPushButton { font-size: 10px; }")
            status_layout.addWidget(status_label)
            status_layout.addWidget(status_combo)
            status_layout.addWidget(issue_input, 1)
            status_layout.addWidget(btn_pending)
            pending_since_label = QLabel()
            pending_since_label.setStyleSheet("color: #8e44ad; font-size: 11px;")
            status_layout.addWidget(pending_since_label)
            observation_edit = QTextEdit()
            observation_edit.setFixedHeight(40)
            observation_edit.setPlaceholderText("Observaciones de la muestra (opcional)")
            if observation:
                observation_edit.setPlainText(str(observation))
            remove_button = QPushButton("Quitar examen")
            remove_button.setStyleSheet("QPushButton { font-size: 10px; color: #c0392b; }")
            remove_button.clicked.connect(lambda _=False, name=test_name: self._prompt_remove_test(name))
            header_layout.addWidget(remove_button)
            container_layout.addLayout(header_layout)
            container_layout.addWidget(status_container)
            group_layout = QFormLayout()
            group_layout.setLabelAlignment(Qt.AlignLeft)
            container_layout.addLayout(group_layout)
            group_box.setLayout(container_layout)
            parsed = self._parse_stored_result(raw_result)
            existing_values = {}
            if parsed.get("type") == "structured":
                existing_values = parsed.get("values", {})
            field_entries = {}
            if template:
                for field_def in template.get("fields", []):
                    if field_def.get("type") == "section":
                        section_label = QLabel(field_def.get("label", ""))
                        section_label.setStyleSheet("font-weight: bold; color: #2c3e50; padding-top:4px;")
                        group_layout.addRow(section_label)
                        continue
                    label_text, field_widget, widget_info = self._create_structured_field(field_def, existing_values, self.current_order_context)
                    widget_info["definition"] = field_def
                    key = field_def.get("key")
                    if key:
                        field_entries[key] = widget_info
                    group_layout.addRow(f"{label_text}:", field_widget)
                self._apply_auto_calculations(field_entries, template)
                self.order_fields[test_name] = {
                    "template": template,
                    "template_name": template_name,
                    "fields": field_entries
                }
            else:
                default_value = ""
                if parsed.get("type") == "text":
                    default_value = parsed.get("value", "")
                elif parsed.get("type") == "structured":
                    default_value = self._structured_dict_to_text(parsed.get("values", {}))
                edit = QLineEdit()
                edit.setText(default_value)
                group_layout.addRow("Resultado:", edit)
                self.order_fields[test_name] = {
                    "template": None,
                    "fields": {
                        "__value__": {
                            "type": "line",
                            "widget": edit,
                            "definition": {"key": "__value__", "label": "Resultado"}
                        }
                    }
                }
            group_layout.addRow("Obs. de la muestra:", observation_edit)
            meta_info = {
                "status_widget": status_combo,
                "issue_widget": issue_input,
                "observation_widget": observation_edit,
                "initial_status": status_value,
                "pending_since": pending_since,
                "pending_label": pending_since_label,
            }

            def _refresh_pending_label():
                current_index = status_combo.currentIndex()
                current_value = status_combo.itemData(current_index)
                if current_value == "pendiente":
                    timestamp = meta_info.get("pending_since")
                    if timestamp:
                        display = self._format_datetime_display(timestamp, "-", include_seconds=False)
                        pending_since_label.setText(f"Pendiente desde: {display}")
                    else:
                        pending_since_label.setText("Pendiente desde: se registrará al guardar")
                    pending_since_label.setVisible(True)
                else:
                    pending_since_label.clear()
                    pending_since_label.setVisible(False)

            def _update_issue_state(index):
                value = status_combo.itemData(index)
                needs_detail = value in {"pendiente", "rechazada"}
                issue_input.setEnabled(needs_detail)
                if value == "pendiente":
                    if not meta_info.get("pending_since"):
                        meta_info["pending_since"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                else:
                    meta_info["pending_since"] = None
                _refresh_pending_label()

            status_combo.currentIndexChanged.connect(_update_issue_state)
            _update_issue_state(status_combo.currentIndex())

            def _set_pending():
                pending_index = status_combo.findData("pendiente")
                if pending_index >= 0:
                    status_combo.setCurrentIndex(pending_index)
                issue_input.setFocus()

            btn_pending.clicked.connect(_set_pending)

            self.order_fields[test_name]["meta"] = meta_info
            self._maybe_add_leukocyte_counter(test_name, self.order_fields[test_name], container_layout)
            self.results_layout.addWidget(group_box)
        self.results_layout.addStretch()

    def _should_auto_calculate_hb(self, order_test_names):
        valid_names = [name for name in order_test_names if name]
        return valid_names.count("Hematocrito") == 1 and len(valid_names) == 1

    def _prompt_remove_test(self, test_name):
        if not self.selected_order_id:
            return
        reply = QMessageBox.question(
            self,
            "Quitar examen",
            f"¿Desea quitar la prueba '{test_name}' de la orden seleccionada?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.No:
            return
        removed = self.labdb.remove_test_from_order(self.selected_order_id, test_name)
        if removed:
            QMessageBox.information(self, "Prueba eliminada", f"Se quitó '{test_name}' de la orden.")
            self.populate_pending_orders()
            self.populate_completed_orders()
            self.load_order_fields()
        else:
            QMessageBox.warning(self, "Acción no realizada", "No se pudo quitar la prueba seleccionada.")

    def save_results(self):
        # Guardar los resultados ingresados para la orden seleccionada
        if not self.selected_order_id:
            return
        results_payload = {}
        has_empty = False
        pending_samples = 0
        pending_tests = []
        missing_notes = []
        for test_name, info in self.order_fields.items():
            template = info.get("template")
            meta = info.get("meta", {})
            status_combo = meta.get("status_widget")
            issue_widget = meta.get("issue_widget")
            observation_widget = meta.get("observation_widget")
            pending_since_value = meta.get("pending_since")
            status_value = "recibida"
            if status_combo:
                status_data = status_combo.currentData()
                if status_data:
                    status_value = str(status_data).strip().lower()
                else:
                    status_value = status_combo.currentText().strip().lower() or "recibida"
            issue_value = issue_widget.text().strip() if issue_widget else ""
            observation_value = observation_widget.toPlainText().strip() if observation_widget else ""
            if status_value == "pendiente":
                pending_samples += 1
                pending_tests.append({
                    "name": test_name,
                    "issue": issue_value,
                })
            else:
                pending_since_value = None
            if status_value == "recibida":
                issue_value = ""
            if status_value in {"pendiente", "rechazada"} and not issue_value:
                missing_notes.append(test_name)
            if template:
                values = {}
                for key, field_info in info["fields"].items():
                    value = self._get_widget_value(field_info)
                    values[key] = value
                    if status_value == "recibida" and value == "" and not field_info["definition"].get("optional", False):
                        has_empty = True
                result_value = {
                    "type": "structured",
                    "template": info.get("template_name", test_name),
                    "values": values
                }
            else:
                field_info = info["fields"].get("__value__")
                value = self._get_widget_value(field_info)
                if status_value == "recibida" and value == "":
                    has_empty = True
                result_value = value
            results_payload[test_name] = {
                "result": result_value,
                "sample_status": status_value,
                "sample_issue": issue_value,
                "observation": observation_value,
                "pending_since": pending_since_value
            }
        if missing_notes:
            detalle = ", ".join(missing_notes)
            QMessageBox.warning(
                self,
                "Motivo requerido",
                f"Indique el motivo o detalle para las muestras marcadas como pendientes/rechazadas: {detalle}"
            )
            return
        if has_empty:
            reply = QMessageBox.question(
                self,
                "Confirmar",
                "Hay pruebas o campos sin resultado. ¿Guardar de todos modos?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        completed = self.labdb.save_results(self.selected_order_id, results_payload)
        followup_order_id = None
        updated_completion = None
        if pending_tests:
            followup_order_id, updated_completion = self.labdb.ensure_followup_order_for_pending(
                self.selected_order_id,
                pending_tests,
                self.user.get('id')
            )
            if updated_completion is not None:
                completed = updated_completion
                self.populate_pending_orders()
                self.populate_completed_orders()
                if self.selected_order_id:
                    self._select_order_in_combo(self.combo_orders, self.selected_order_id)
            elif followup_order_id:
                self.populate_pending_orders()
                if self.selected_order_id:
                    self._select_order_in_combo(self.combo_orders, self.selected_order_id)
        self.update_pending_overview_button()
        base_message = "Resultados guardados. Orden marcada como completada." if completed else "Resultados guardados (orden aún incompleta)."
        if pending_samples:
            base_message += "\nHay muestras pendientes o rechazadas registradas."
        if followup_order_id:
            base_message += f"\nSe generó la orden #{followup_order_id} para el seguimiento de las pruebas pendientes."
        if completed:
            QMessageBox.information(self, "Completado", base_message)
            self.selected_order_id = None
            self.populate_pending_orders()
            self._clear_results_layout()
            msg = QLabel("Seleccione otra orden pendiente para continuar con la digitación de resultados.")
            msg.setStyleSheet("color: #555; font-style: italic;")
            msg.setWordWrap(True)
            self.results_layout.addWidget(msg)
            self.results_layout.addStretch()
        else:
            QMessageBox.information(self, "Guardado", base_message)
            self.load_order_fields()

    def _clear_results_layout(self):
        if not hasattr(self, 'results_layout'):
            return
        self.current_order_context = None
        while self.results_layout.count():
            item = self.results_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        if hasattr(self, 'results_add_tests_btn'):
            self.results_add_tests_btn.setEnabled(False)
    def _create_structured_field(self, field_def, existing_values, context=None):
        key = field_def.get("key")
        value = ""
        if key:
            value = existing_values.get(key, "")
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        widget_info = {"key": key, "container": container}
        field_type = field_def.get("type", "text")
        if field_type == "choice":
            combo = QComboBox()
            combo.addItems(field_def.get("choices", []))
            if value:
                idx = combo.findText(value)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
                else:
                    combo.addItem(value)
                    combo.setCurrentIndex(combo.count() - 1)
            else:
                if combo.count():
                    combo.setCurrentIndex(-1)
            layout.addWidget(combo)
            widget_info.update({"type": "combo", "widget": combo})
        elif field_type == "bool":
            pos_text = field_def.get("positive_text", "Positivo")
            neg_text = field_def.get("negative_text", "Negativo")
            pos_radio = QRadioButton(pos_text)
            neg_radio = QRadioButton(neg_text)
            group = QButtonGroup(container)
            group.addButton(pos_radio)
            group.addButton(neg_radio)
            layout.addWidget(pos_radio)
            layout.addWidget(neg_radio)
            widget_info.update({
                "type": "bool",
                "group": group,
                "positive": pos_radio,
                "negative": neg_radio,
                "positive_text": pos_text,
                "negative_text": neg_text
            })
            if value:
                if value.lower() == pos_text.lower() or value.lower() == "positivo":
                    pos_radio.setChecked(True)
                elif value.lower() == neg_text.lower() or value.lower() == "negativo":
                    neg_radio.setChecked(True)
        elif field_type == "text_area":
            text_edit = QTextEdit()
            text_edit.setFixedHeight(field_def.get("height", 70))
            placeholder = field_def.get("placeholder")
            if placeholder:
                text_edit.setPlaceholderText(placeholder)
            if value:
                text_edit.setPlainText(value)
            layout.addWidget(text_edit)
            widget_info.update({"type": "text_area", "widget": text_edit})
        else:
            edit = QLineEdit()
            placeholder = field_def.get("placeholder")
            if placeholder:
                edit.setPlaceholderText(placeholder)
            if value:
                edit.setText(value)
            layout.addWidget(edit)
            widget_info.update({"type": "line", "widget": edit})
        unit = field_def.get("unit")
        if unit and field_type not in ("bool",):
            unit_label = QLabel(unit)
            unit_label.setStyleSheet("color: #555; font-size: 11px;")
            layout.addWidget(unit_label)
        reference = self._get_field_reference(field_def, context)
        if reference:
            ref_label = QLabel(f"Ref: {reference}")
            ref_label.setWordWrap(True)
            ref_label.setStyleSheet("color: #777; font-size: 11px;")
            layout.addWidget(ref_label)
        helper = field_def.get("helper")
        if helper:
            helper_label = QLabel(helper)
            helper_label.setWordWrap(True)
            helper_label.setStyleSheet("color: #0a84ff; font-size: 10px;")
            layout.addWidget(helper_label)
        layout.addStretch()
        widget_info["unit"] = unit
        widget_info["reference"] = reference
        return field_def.get("label", key or ""), container, widget_info

    def _maybe_add_leukocyte_counter(self, test_name, field_info, container_layout):
        if not field_info or not container_layout:
            return
        template_name = field_info.get("template_name") or test_name or ""
        if "hemograma" not in str(template_name).lower():
            return
        fields = field_info.get("fields", {})
        widgets = []
        for key in LEUCOCYTE_KEYS:
            info = fields.get(key)
            if not info:
                continue
            widget = info.get("widget")
            if isinstance(widget, QLineEdit):
                widgets.append(widget)
        if not widgets:
            return
        counter_label = QLabel("Suma fórmula leucocitaria: —")
        counter_label.setAlignment(Qt.AlignRight)
        counter_label.setStyleSheet("color: #5a6b7b; font-style: italic;")
        container_layout.addWidget(counter_label)

        def _update_counter():
            total = 0.0
            has_value = False
            for widget in widgets:
                value = self._to_float(widget.text().strip()) if widget else None
                if value is None:
                    continue
                has_value = True
                total += value
            if not has_value:
                counter_label.setText("Suma fórmula leucocitaria: —")
                counter_label.setStyleSheet("color: #5a6b7b; font-style: italic;")
                return
            total_text = f"{total:.1f}".rstrip('0').rstrip('.')
            counter_label.setText(f"Suma fórmula leucocitaria: {total_text}%")
            if abs(total - 100) <= 0.5:
                counter_label.setStyleSheet("color: #1e8449; font-weight: 600;")
            else:
                counter_label.setStyleSheet("color: #c0392b; font-weight: 600;")

        for widget in widgets:
            widget.textChanged.connect(_update_counter)
        _update_counter()
        meta = field_info.setdefault("meta", {})
        meta["leukocyte_counter_label"] = counter_label
    def _apply_auto_calculations(self, field_entries, template):
        for calc in template.get("auto_calculations", []):
            self._setup_auto_calculation(field_entries, calc)
    def _setup_auto_calculation(self, field_entries, calc):
        source_key = calc.get("source")
        target_key = calc.get("target")
        if not source_key or not target_key:
            return
        source_info = field_entries.get(source_key)
        target_info = field_entries.get(target_key)
        if not source_info or not target_info:
            return
        if source_info.get("type") not in ("line",):
            return
        if target_info.get("type") not in ("line",):
            return
        source_widget = source_info.get("widget")
        target_widget = target_info.get("widget")
        if not source_widget or not target_widget:
            return
        operation = calc.get("operation")
        operand = calc.get("operand")
        decimals = calc.get("decimals", 2)
        only_if_empty = calc.get("only_if_empty", False)
        apply_on_load = calc.get("apply_on_load", True)
        description = calc.get("description")
        if description and not target_info.get("has_auto_helper"):
            container = target_info.get("container")
            if container and container.layout():
                helper_label = QLabel(description)
                helper_label.setWordWrap(True)
                helper_label.setStyleSheet("color: #0a84ff; font-size: 10px;")
                container.layout().addWidget(helper_label)
                target_info["has_auto_helper"] = True
        auto_state = target_info.setdefault("_auto_calc_state", {
            "manual_override": False,
            "last_auto_value": "",
            "listener_connected": False
        })

        def _handle_target_edit(text):
            stripped = text.strip()
            if stripped:
                auto_state["manual_override"] = True
            else:
                auto_state["manual_override"] = False
                auto_state["last_auto_value"] = ""

        if not auto_state.get("listener_connected"):
            target_widget.textEdited.connect(_handle_target_edit)
            auto_state["listener_connected"] = True
        def on_change(text):
            value = self._to_float(text)
            if value is None:
                if calc.get("clear_on_invalid", False):
                    target_widget.blockSignals(True)
                    target_widget.clear()
                    target_widget.blockSignals(False)
                    auto_state["last_auto_value"] = ""
                    auto_state["manual_override"] = False
                return
            result = None
            if operation == "divide":
                if operand in (0, None):
                    return
                result = value / operand
            elif operation == "multiply" and operand is not None:
                result = value * operand
            elif operation == "add" and operand is not None:
                result = value + operand
            elif operation == "subtract" and operand is not None:
                result = value - operand
            if result is None:
                return
            current_text = target_widget.text().strip()
            if only_if_empty and auto_state.get("manual_override") and current_text:
                return
            if target_widget.hasFocus() and not calc.get("update_while_editing", False):
                return
            if decimals is not None:
                formatted = f"{result:.{decimals}f}".rstrip('0').rstrip('.')
            else:
                formatted = str(result)
            target_widget.blockSignals(True)
            target_widget.setText(formatted)
            target_widget.blockSignals(False)
            auto_state["last_auto_value"] = formatted
            auto_state["manual_override"] = False
        source_widget.textChanged.connect(on_change)
        if apply_on_load:
            on_change(source_widget.text())
    def _structured_dict_to_text(self, values):
        if not isinstance(values, dict):
            return ""
        parts = []
        for key, val in values.items():
            if val:
                parts.append(f"{key}: {val}")
        return "; ".join(parts)
    def _parse_stored_result(self, raw_result):
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
    def _get_widget_value(self, field_info):
        if not field_info:
            return ""
        field_type = field_info.get("type")
        if field_type == "line":
            widget = field_info.get("widget")
            return widget.text().strip() if widget else ""
        if field_type == "text_area":
            widget = field_info.get("widget")
            return widget.toPlainText().strip() if widget else ""
        if field_type == "combo":
            widget = field_info.get("widget")
            return widget.currentText().strip() if widget else ""
        if field_type == "bool":
            if field_info.get("positive") and field_info["positive"].isChecked():
                return field_info.get("positive_text", "Positivo")
            if field_info.get("negative") and field_info["negative"].isChecked():
                return field_info.get("negative_text", "Negativo")
            return ""
        return ""
    def _to_float(self, text):
        if text in (None, ""):
            return None
        try:
            return float(str(text).replace(',', '.'))
        except ValueError:
            return None

    def _add_pdf_page(self, pdf, orientation=None, page_format=None):
        """Compatibilidad para agregar páginas en diferentes versiones de FPDF."""

        attempts = [
            ((), {}),  # Compatibilidad con versiones antiguas que no aceptan argumentos.
        ]

        if orientation:
            # Intentos sin argumentos de formato para FPDF heredado.
            attempts.append(((orientation,), {}))

        base_kwargs = {}
        if orientation:
            base_kwargs["orientation"] = orientation

        if page_format is not None:
            kwargs_format = {**base_kwargs, "format": page_format}
            attempts.append(((), kwargs_format))

            kwargs_size = {**base_kwargs, "size": page_format}
            attempts.append(((), kwargs_size))
        else:
            attempts.append(((), base_kwargs))

        positional_args = []
        if orientation:
            positional_args.append(orientation)

        if page_format is not None:
            attempts.append((tuple(positional_args + [page_format]), {}))
            attempts.append((tuple(positional_args), {"format": page_format}))
            attempts.append((tuple(positional_args), {"size": page_format}))
        else:
            attempts.append((tuple(positional_args), {}))

        for args, kwargs in attempts:
            try:
                pdf.add_page(*args, **kwargs)
                return
            except TypeError:
                continue

        raise TypeError("No se pudo agregar la página al PDF con los parámetros proporcionados")

    def _ensure_latin1(self, text):
        if text is None:
            return ""
        if not isinstance(text, str):
            text = str(text)
        replacements = {
            '\u2013': '-',
            '\u2014': '-',
            '\u2018': "'",
            '\u2019': "'",
            '\u201c': '"',
            '\u201d': '"'
        }
        for bad, good in replacements.items():
            text = text.replace(bad, good)
        try:
            text.encode('latin-1')
            return text
        except UnicodeEncodeError:
            return text.encode('latin-1', 'replace').decode('latin-1')

    def _is_blank_result(self, value):
        if value is None:
            return True
        if isinstance(value, str):
            return value.strip() == ""
        return False
    def _format_result_lines(self, test_name, raw_result, context=None):
        parsed = self._parse_stored_result(raw_result)
        template = TEST_TEMPLATES.get(test_name)
        effective_context = context or self.current_order_context
        if parsed.get("type") == "structured" and template:
            values = parsed.get("values", {})
            value_lines = []
            pending_section = None
            for field_def in template.get("fields", []):
                if field_def.get("type") == "section":
                    section_label = field_def.get("label", "")
                    pending_section = f"  {section_label}:" if section_label else None
                    continue
                key = field_def.get("key")
                if not key:
                    continue
                value = values.get(key, "")
                if isinstance(value, str):
                    stripped = value.strip()
                    if stripped == "":
                        continue
                    display_value = " ".join(value.splitlines()).strip()
                else:
                    if self._is_blank_result(value):
                        continue
                    display_value = value
                unit = field_def.get("unit")
                field_type = field_def.get("type")
                if unit and field_type not in ("bool", "text_area", "choice"):
                    display_text = str(display_value)
                    if not display_text.endswith(unit):
                        display_value = f"{display_text} {unit}"
                reference = self._get_field_reference(field_def, effective_context)
                label = field_def.get("label", key)
                if pending_section:
                    value_lines.append(pending_section)
                    pending_section = None
                bullet = f"  • {label}: {display_value}"
                if reference:
                    bullet += f" (Ref: {reference})"
                value_lines.append(bullet)
            if not value_lines:
                return []
            return [f"{test_name}:"] + value_lines
        text_value = parsed.get("value", raw_result or "")
        if isinstance(text_value, str):
            text_value = text_value.strip()
            if text_value == "":
                return []
        elif self._is_blank_result(text_value):
            return []
        return [f"{test_name}: {text_value}"]
    def _format_result_for_export(self, test_name, raw_result, context=None):
        lines = self._format_result_lines(test_name, raw_result, context=context)
        if not lines:
            return ""
        if len(lines) <= 1:
            line = lines[0]
            parts = line.split(": ", 1)
            return parts[1] if len(parts) > 1 else line
        cleaned = []
        for line in lines[1:]:
            stripped = line.strip()
            if stripped.endswith(":") and "•" not in stripped:
                continue
            cleaned.append(stripped.replace("• ", ""))
        return " | ".join(cleaned)

    def _build_registry_summary(self, test_name, raw_result, context=None):
        sections = self._collect_registry_sections(test_name, raw_result, context=context)
        if not sections:
            return []
        lines = []
        for section_idx, pairs in enumerate(sections):
            processed_pairs = self._post_process_registry_pairs(pairs)
            if not processed_pairs:
                continue
            first_entry = processed_pairs[0]
            if first_entry.get("key") == "resultado":
                result_value = first_entry.get("value")
                if result_value:
                    lines.append(f"{test_name}: {result_value}")
                for extra in processed_pairs[1:]:
                    extra_value = extra.get("value")
                    if not extra_value:
                        continue
                    label = extra.get("label", "")
                    if label:
                        lines.append(f"{label}: {extra_value}")
                    else:
                        lines.append(str(extra_value))
                continue
            parts = []
            for entry in processed_pairs:
                label = entry.get("label", "")
                value = entry.get("value", "")
                if not value:
                    continue
                if label:
                    parts.append(f"{label}: {value}")
                else:
                    parts.append(str(value))
            if parts:
                line_text = ", ".join(parts)
                if section_idx == 0 and test_name:
                    normalized_line = self._normalize_text(line_text)
                    normalized_test = self._normalize_text(test_name)
                    expected_label = self._abbreviate_registry_label(test_name)
                    normalized_expected = self._normalize_text(expected_label) if expected_label else ""
                    include_name = True
                    if normalized_test and normalized_test in normalized_line:
                        include_name = False
                    elif normalized_expected and normalized_expected in normalized_line:
                        include_name = False
                    if include_name:
                        line_text = f"{test_name}: {line_text}"
                lines.append(line_text)
        return lines

    def _collect_registry_sections(self, test_name, raw_result, context=None):
        parsed = self._parse_stored_result(raw_result)
        template_key = parsed.get("template") if isinstance(parsed, dict) else None
        template = TEST_TEMPLATES.get(template_key) if template_key in TEST_TEMPLATES else TEST_TEMPLATES.get(test_name)
        if parsed.get("type") == "structured" and template:
            values = parsed.get("values", {})
            sections = []
            current_section = []
            for field_def in template.get("fields", []):
                if field_def.get("type") == "section":
                    if current_section:
                        sections.append(current_section)
                        current_section = []
                    continue
                key = field_def.get("key")
                if not key:
                    continue
                value = values.get(key, "")
                normalized_value = self._normalize_registry_value(value)
                if normalized_value is None:
                    continue
                label = field_def.get("label", key)
                short_label = self._abbreviate_registry_label(label, key)
                current_section.append({
                    "label": short_label,
                    "value": normalized_value,
                    "key": key
                })
            if current_section:
                sections.append(current_section)
            return sections
        text_value = parsed.get("value", raw_result or "")
        if isinstance(text_value, str):
            text_value = text_value.strip()
        if not text_value:
            return []
        label = self._abbreviate_registry_label(test_name)
        normalized_value = self._normalize_registry_value(text_value)
        if normalized_value is None:
            return []
        return [[{"label": label, "value": normalized_value, "key": None}]]

    def _normalize_registry_value(self, value):
        if value in (None, ""):
            return None
        if isinstance(value, str):
            cleaned = " ".join(value.split())
            return cleaned if cleaned else None
        if isinstance(value, (int, float)):
            return self._format_decimal(value)
        return str(value).strip() or None

    def _abbreviate_registry_label(self, label, key=None):
        candidates = []
        if key:
            candidates.append(self._normalize_text(key))
        if label:
            candidates.append(self._normalize_text(label))
        for candidate in candidates:
            if candidate in REGISTRY_ABBREVIATIONS:
                return REGISTRY_ABBREVIATIONS[candidate]
        if label:
            base = label.split('(')[0].strip()
            if len(base) <= 6:
                return base
            words = base.split()
            if len(words) == 1:
                return words[0][:4].capitalize()
            abbreviation = "".join(word[0] for word in words[:2]).upper()
            if len(abbreviation) >= 2:
                return abbreviation
            return base[:4].capitalize()
        if key:
            return key
        return ""

    def _post_process_registry_pairs(self, pairs):
        if not pairs:
            return []
        processed = list(pairs)
        processed = self._ensure_hematocrit_pair(processed)
        return processed

    def _ensure_hematocrit_pair(self, pairs):
        hematocrit_index = None
        hemoglobin_index = None
        for idx, entry in enumerate(pairs):
            if entry.get("key") == "hematocrito":
                hematocrit_index = idx
            if entry.get("key") == "hemoglobina":
                hemoglobin_index = idx
        if hematocrit_index is None:
            return pairs
        hematocrit_value = self._extract_numeric_value(pairs[hematocrit_index].get("value"))
        hemoglobin_present = False
        if hemoglobin_index is not None and pairs[hemoglobin_index].get("value") not in (None, ""):
            hemoglobin_present = True
        if hematocrit_value is not None and not hemoglobin_present:
            hb_value = self._format_decimal(hematocrit_value / 3.03)
            hb_entry = {
                "label": self._abbreviate_registry_label("Hemoglobina", "hemoglobina"),
                "value": hb_value,
                "key": "hemoglobina"
            }
            insert_index = hematocrit_index + 1
            pairs = pairs[:insert_index] + [hb_entry] + pairs[insert_index:]
            hemoglobin_index = insert_index
        if hemoglobin_index is not None and hemoglobin_index != hematocrit_index + 1:
            hb_entry = pairs.pop(hemoglobin_index)
            insert_index = min(hematocrit_index + 1, len(pairs))
            pairs.insert(insert_index, hb_entry)
        return pairs

    def _extract_numeric_value(self, text):
        if text in (None, ""):
            return None
        match = re.search(r'-?\d+(?:[\.,]\d+)?', str(text))
        if not match:
            return None
        try:
            return float(match.group(0).replace(',', '.'))
        except ValueError:
            return None

    def _format_decimal(self, value, decimals=2):
        try:
            number = float(value)
        except (TypeError, ValueError):
            return str(value)
        formatted = f"{number:.{decimals}f}"
        if "." in formatted:
            formatted = formatted.rstrip('0').rstrip('.')
        return formatted

    def _map_category_group(self, category):
        normalized = (category or "").strip().upper()
        if normalized == "HEMATOLOGÍA":
            return "hematology"
        if normalized == "BIOQUÍMICA":
            return "biochemistry"
        if normalized in {"MICROBIOLOGÍA", "PARASITOLOGÍA", "MICROSCOPÍA"}:
            return "micro_parasito"
        if normalized == "LABORATORIO REFERENCIAL":
            return "others"
        return "others"

    def _aggregate_results_by_order(self, records):
        group_keys = ["hematology", "biochemistry", "micro_parasito", "others"]
        aggregated = []
        grouped = OrderedDict()
        for record in records:
            summary_items = record.get("summary_items")
            if not summary_items:
                result_value = record.get("result", "")
                if isinstance(result_value, str) and result_value.strip():
                    summary_items = [result_value.strip()]
                elif not self._is_blank_result(result_value):
                    summary_items = [str(result_value)]
            if not summary_items:
                continue
            order_id = record.get("order_id")
            if order_id is None:
                continue
            entry = grouped.get(order_id)
            if not entry:
                entry = {
                    "order_id": order_id,
                    "date": record.get("date", ""),
                    "order_date_raw": record.get("order_date_raw"),
                    "sample_date_raw": record.get("sample_date_raw"),
                    "patient": record.get("patient", ""),
                    "document": record.get("document", ""),
                    "doc_type": record.get("doc_type"),
                    "doc_number": record.get("doc_number"),
                    "birth_date": record.get("birth_date"),
                    "hcl": record.get("hcl"),
                    "sex": record.get("sex"),
                    "origin": record.get("origin"),
                    "is_pregnant": record.get("is_pregnant"),
                    "gestational_age_weeks": record.get("gestational_age_weeks"),
                    "expected_delivery_date": record.get("expected_delivery_date"),
                    "age": record.get("age", ""),
                    "first_name": record.get("first_name"),
                    "last_name": record.get("last_name"),
                    "observations": record.get("order_observations"),
                    "insurance_type": record.get("insurance_type"),
                    "fua_number": record.get("fua_number"),
                    "emitted": record.get("emitted"),
                    "emitted_at": record.get("emitted_at"),
                    "groups": {key: [] for key in group_keys},
                    "tests": [],
                    "sample_statuses": []
                }
                grouped[order_id] = entry
            group_key = self._map_category_group(record.get("category"))
            for item in summary_items:
                cleaned = str(item).strip()
                if cleaned:
                    entry["groups"].setdefault(group_key, []).append(cleaned)
            test_name = record.get("test")
            if test_name:
                test_clean = str(test_name).strip()
                if test_clean and test_clean not in entry.setdefault("tests", []):
                    entry["tests"].append(test_clean)
            status_info = {
                "test": record.get("test"),
                "status": record.get("sample_status"),
                "issue": record.get("sample_issue"),
                "pending_since": record.get("pending_since"),
            }
            entry.setdefault("sample_statuses", []).append(status_info)
        for entry in grouped.values():
            obs_text = entry.get("observations")
            if obs_text:
                obs_clean = " ".join(str(obs_text).split())
                if obs_clean and obs_clean.lower() not in {"n/a", "na", "-"}:
                    entry["groups"].setdefault("others", []).append(f"Obs: {obs_clean}")
            if any(entry["groups"].get(key) for key in group_keys):
                aggregated.append(entry)
        return aggregated

    def _format_short_date(self, value):
        return self._format_date_display(value, "—")

    def _format_patient_block_for_registry(self, entry):
        def clean(text):
            if not text:
                return ""
            return " ".join(str(text).split())
        def to_title(text):
            return text.title() if text else ""
        first = to_title(clean(entry.get("first_name")))
        last = to_title(clean(entry.get("last_name")))
        if last and first:
            name_line = f"{last}, {first}"
        elif last:
            name_line = last
        elif first:
            name_line = first
        else:
            fallback = clean(entry.get("patient"))
            name_line = to_title(fallback) if fallback else "—"
        doc_type_value = entry.get("doc_type")
        doc_label = doc_type_value.upper() if doc_type_value else "Doc."
        doc_number = clean(entry.get("doc_number")) or "—"
        doc_line = f"{doc_label}: {doc_number}" if doc_label else f"Documento: {doc_number}"
        birth_line = f"F. Nac.: {self._format_short_date(entry.get('birth_date'))}"
        hcl_value = clean(entry.get("hcl")) or "—"
        hcl_line = f"HCL: {hcl_value}"
        lines = [name_line or "—", doc_line, birth_line, hcl_line]
        insurance_display = self._format_insurance_display(entry.get("insurance_type"))
        if insurance_display:
            lines.append(f"Seguro: {insurance_display}")
        pregnancy_line = self._format_registry_pregnancy_line(entry)
        if pregnancy_line:
            lines.append(pregnancy_line)
        return "\n".join(lines)

    def _format_date_for_registry(self, entry):
        sample = entry.get("sample_date_raw")
        if sample:
            formatted = self._format_short_date(sample)
            if formatted:
                return formatted
        raw_date = entry.get("order_date_raw") or entry.get("date")
        return self._format_short_date(raw_date)

    def _format_emission_status(self, emitted_flag, emitted_at):
        if emitted_flag:
            if emitted_at:
                display = self._format_date_display(emitted_at, None)
                if display and display not in {"—", None}:
                    return f"Sí ({display})"
                return "Sí"
            return "Sí"
        if emitted_flag == 0:
            return "No"
        return "-"

    def _format_birth_for_history(self, birth_value):
        if not birth_value:
            return "-"
        display = self._format_short_date(birth_value)
        return "-" if display == "—" else display

    def _format_sex_display(self, sex_value):
        if sex_value in (None, ""):
            return "-"
        text = str(sex_value).strip()
        if not text:
            return "-"
        normalized = text.lower()
        if normalized.startswith("f"):
            return "F"
        if normalized.startswith("m"):
            return "M"
        return text.title()

    def _format_insurance_display(self, insurance_value):
        if not insurance_value:
            return "SIS"
        return str(insurance_value).strip().upper() or "SIS"

    def _normalize_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            normalized = unicodedata.normalize("NFD", value.strip().lower())
            normalized = "".join(ch for ch in normalized if unicodedata.category(ch) != 'Mn')
            return normalized in {"1", "true", "t", "si", "s", "y", "yes"}
        return False

    def _format_registry_pregnancy_line(self, entry):
        is_pregnant = self._normalize_bool(entry.get("is_pregnant"))
        if not is_pregnant:
            return None
        gest_weeks = entry.get("gestational_age_weeks")
        due_raw = entry.get("expected_delivery_date")
        display = "Gestante: Sí"
        if gest_weeks not in (None, "", 0):
            try:
                display += f" ({int(gest_weeks)} sem)"
            except (TypeError, ValueError):
                pass
        if due_raw:
            due_display = self._format_short_date(due_raw)
            if due_display == "—":
                due_display = str(due_raw)
            if due_display:
                display += f" - FPP: {due_display}"
        return display

    def _format_fua_display(self, entry):
        insurance = (entry.get("insurance_type") or "").strip().lower()
        fua_value = entry.get("fua_number")
        if insurance == "particular":
            return "No aplica"
        if isinstance(fua_value, str):
            fua_value = fua_value.strip()
        if fua_value:
            return str(fua_value)
        return "Pendiente"

    def _format_sample_status_text(self, status_value, note, pending_since=None):
        value = (status_value or "recibida").strip().lower()
        if value == "recibida":
            return ""
        label = "Pendiente" if value == "pendiente" else "Rechazada"
        date_suffix = ""
        if value == "pendiente" and pending_since:
            display = self._format_datetime_display(pending_since, "")
            if display:
                date_suffix = f" (desde {display})"
        base = f"{label}{date_suffix}"
        if note:
            return f"{base} - {note}"
        return base

    def _format_history_sample_status(self, entry):
        statuses = entry.get("sample_statuses") or []
        parts = []
        for status_info in statuses:
            text = self._format_sample_status_text(
                status_info.get("status"),
                status_info.get("issue"),
                status_info.get("pending_since")
            )
            if not text:
                text = "Recibida"
            test_name = status_info.get("test")
            if test_name:
                parts.append(f"{test_name}: {text}")
            else:
                parts.append(text)
        return "\n".join(parts) if parts else "-"

    def _format_history_gestation(self, entry):
        display = self._format_registry_pregnancy_line(entry)
        return display if display else "-"

    def _build_history_row_values(self, entry):
        return [
            self._format_date_for_registry(entry),
            str(entry.get("order_id", "-")),
            entry.get("patient", "-"),
            entry.get("document", "-"),
            self._format_birth_for_history(entry.get("birth_date")),
            entry.get("age", "-"),
            self._format_history_gestation(entry),
            self._format_sex_display(entry.get("sex")),
            entry.get("origin", "-") or "-",
            entry.get("hcl", "-") or "-",
            self._format_insurance_display(entry.get("insurance_type")),
            self._format_fua_display(entry),
            self._format_history_sample_status(entry),
            "\n".join(sorted(entry.get("tests", []))) or "-",
            "\n  ".join(entry.get("groups", {}).get("hematology", [])) or "-",
            "\n  ".join(entry.get("groups", {}).get("biochemistry", [])) or "-",
            "\n  ".join(entry.get("groups", {}).get("micro_parasito", [])) or "-",
            "\n  ".join(entry.get("groups", {}).get("others", [])) or "-",
            self._format_emission_status(entry.get("emitted"), entry.get("emitted_at"))
        ]

    def _populate_history_table_widget(self, table_widget, aggregated):
        headers = getattr(self, 'history_headers', [])
        if not headers or not isinstance(aggregated, list):
            return
        table_widget.setRowCount(len(aggregated))
        for row_idx, entry in enumerate(aggregated):
            values = self._build_history_row_values(entry)
            for col_idx, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if headers[col_idx] in {"Orden", "Edad", "F. Nacimiento", "Sexo", "Tipo de seguro", "FUA", "Gestación"}:
                    item.setTextAlignment(Qt.AlignCenter)
                table_widget.setItem(row_idx, col_idx, item)
    def _calculate_age_years(self, patient_info, order_info):
        age_value = order_info.get('age_years') if isinstance(order_info, dict) else None
        if age_value is not None:
            try:
                return int(age_value)
            except (TypeError, ValueError):
                age_value = None
        if age_value is None:
            birth_date = patient_info.get('birth_date') if isinstance(patient_info, dict) else None
            if birth_date:
                bd = QDate.fromString(birth_date, "yyyy-MM-dd")
                if bd.isValid():
                    age_value = bd.daysTo(QDate.currentDate()) // 365
        return age_value
    def _format_age_text(self, patient_info, order_info):
        age_value = self._calculate_age_years(patient_info, order_info)
        return f"{age_value} años" if age_value is not None else "-"

    def _get_field_reference(self, field_def, context=None):
        if not field_def:
            return None
        reference = field_def.get("reference")
        if not reference:
            return reference
        effective_context = context or self.current_order_context
        return self._filter_reference_for_context(reference, effective_context)

    def _filter_reference_for_context(self, reference, context):
        if not reference or not isinstance(reference, str):
            return reference
        if not context:
            return reference
        patient_info = context.get("patient", {}) if isinstance(context, dict) else {}
        order_info = context.get("order", {}) if isinstance(context, dict) else {}
        age_value = self._calculate_age_years(patient_info, order_info)
        sex_text = self._normalize_text(patient_info.get("sex", ""))
        segments = self._split_reference_segments(reference)
        applicable = []
        general_segments = []
        for segment in segments:
            classification = self._classify_reference_segment(segment)
            if self._segment_matches_context(classification, age_value, sex_text):
                applicable.append(segment.strip())
            elif not classification['groups'] and not classification['sexes']:
                general_segments.append(segment.strip())
        if applicable:
            return "\n".join(applicable)
        if general_segments:
            return "\n".join(general_segments)
        return reference

    def _split_reference_segments(self, reference_text):
        segments = []
        for raw_line in str(reference_text).split('\n'):
            for part in raw_line.split('|'):
                cleaned = part.strip()
                if cleaned:
                    segments.append(cleaned)
        return segments or [str(reference_text).strip()]

    def _normalize_text(self, text):
        if not isinstance(text, str):
            text = str(text or "")
        normalized = unicodedata.normalize("NFD", text.lower())
        return "".join(ch for ch in normalized if unicodedata.category(ch) != 'Mn')

    def _classify_reference_segment(self, segment):
        normalized = self._normalize_text(segment)
        groups = set()
        sexes = set()
        if any(keyword in normalized for keyword in ["rn", "recien nacido", "neon", "lactant"]):
            groups.add('newborn')
        if any(keyword in normalized for keyword in ["nino", "ninos", "infantil", "pediatr", "menor", "adolesc"]):
            groups.add('child')
        if "mes" in normalized:
            groups.add('child')
        if any(keyword in normalized for keyword in ["adulto", "adultos", "mayor", "ancian", "geriatr"]):
            groups.add('adult')
        if any(keyword in normalized for keyword in ["mujer", "mujeres", "femen"]):
            sexes.add('female')
            groups.add('adult')
        if any(keyword in normalized for keyword in ["hombre", "hombres", "varon", "varones", "mascul"]):
            sexes.add('male')
            groups.add('adult')
        if "gestant" in normalized or "embaraz" in normalized:
            sexes.add('female')
            groups.add('adult')
        for match in re.finditer(r'(\d+)\s*[-–]\s*(\d+)\s*(?:anos|ano|a)', normalized):
            start = int(match.group(1))
            end = int(match.group(2))
            self._assign_age_range_groups(groups, start, end)
        for match in re.finditer(r'(?:>=|<=|>|<)?\s*(\d+)\s*(?:anos|ano|a)', normalized):
            age = int(match.group(1))
            self._assign_age_range_groups(groups, age, age)
        for match in re.finditer(r'(\d+)\s*(?:mes|meses)', normalized):
            months = int(match.group(1))
            groups.add('child')
            if months <= 1:
                groups.add('newborn')
        return {"groups": groups, "sexes": sexes}

    def _assign_age_range_groups(self, groups, start_age, end_age):
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

    def _segment_matches_context(self, classification, age_value, normalized_sex):
        groups = classification.get('groups', set())
        sexes = classification.get('sexes', set())
        if age_value is None:
            return self._segment_matches_sex(sexes, normalized_sex)
        target_groups = set()
        if age_value <= 0:
            target_groups.add('newborn')
        if age_value < 18:
            target_groups.add('child')
        if age_value >= 18:
            target_groups.add('adult')
        if groups and not groups.intersection(target_groups):
            return False
        return self._segment_matches_sex(sexes, normalized_sex)

    def _segment_matches_sex(self, sexes, normalized_sex):
        if not sexes:
            return True
        if not normalized_sex:
            return True
        if any(keyword in normalized_sex for keyword in ["femen", "mujer"]):
            return 'female' in sexes
        if any(keyword in normalized_sex for keyword in ["mascul", "hombre", "varon"]):
            return 'male' in sexes
        return True
    def _extract_result_structure(self, test_name, raw_result, context=None):
        parsed = self._parse_stored_result(raw_result)
        template_key = parsed.get("template") if isinstance(parsed, dict) else None
        template = TEST_TEMPLATES.get(template_key) if template_key in TEST_TEMPLATES else TEST_TEMPLATES.get(test_name)
        effective_context = context or self.current_order_context
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
                    if self._is_blank_result(value):
                        continue
                    display_value = value
                unit = field_def.get("unit")
                field_type = field_def.get("type")
                if unit and field_type not in ("bool", "text_area", "choice"):
                    display_value = f"{display_value} {unit}" if not str(display_value).endswith(unit) else display_value
                if pending_section:
                    items.append({"type": "section", "label": pending_section})
                    pending_section = None
                items.append({
                    "type": "value",
                    "label": field_def.get("label", key),
                    "value": display_value,
                    "reference": self._get_field_reference(field_def, effective_context)
                })
            return {"type": "structured", "items": items}
        text_value = parsed.get("value", raw_result or "")
        if isinstance(text_value, str):
            text_value = text_value.strip()
            if text_value == "":
                return {"type": "text", "value": ""}
        elif self._is_blank_result(text_value):
            return {"type": "text", "value": ""}
        return {"type": "text", "value": text_value}
    def _find_logo_path(self, position):
        if position not in {"left", "center", "right"}:
            return None
        search_dirs = ["", "assets", "resources", "images", "img", "static"]
        base_names = [
            f"logo_{position}.png",
            f"logo_{position}.jpg",
            f"logo_{position}.jpeg",
            f"{position}_logo.png",
            f"{position}_logo.jpg",
        ]
        if position == "center":
            base_names.extend([
                "logo.png",
                "logo_central.png",
                "logo_central.jpg",
                "logo_centro.png",
            ])
        if position == "right":
            base_names.extend(["logo_secondary.png", "logo_secundario.png"])
        for directory in search_dirs:
            for name in base_names:
                candidate = os.path.join(directory, name) if directory else name
                if os.path.exists(candidate):
                    return candidate
        return None
    def init_emitir_page(self):
        layout = QVBoxLayout(self.page_emitir)
        top_layout = QHBoxLayout()
        lbl = QLabel("Orden completada:")
        self.combo_completed = QComboBox()
        btn_view = QPushButton("Ver")
        btn_add_tests = QPushButton("Agregar pruebas")
        btn_delete_completed = QPushButton("Eliminar orden")
        btn_delete_completed.setStyleSheet(
            "QPushButton { background-color: #ffe8e6; color: #c0392b; border-radius: 10px; border: 1px solid #c0392b; }"
            "QPushButton:hover:!disabled { background-color: #fbd1ce; }"
        )
        top_layout.addWidget(lbl)
        top_layout.addWidget(self.combo_completed, 1)
        top_layout.addWidget(btn_view)
        top_layout.addWidget(btn_add_tests)
        top_layout.addWidget(btn_delete_completed)
        layout.addLayout(top_layout)
        sort_layout = QHBoxLayout()
        self.include_emitted_checkbox = QCheckBox("Mostrar emitidos")
        sort_layout.addWidget(self.include_emitted_checkbox)
        sort_layout.addStretch()
        sort_label = QLabel("Ordenar:")
        self.completed_sort_combo = QComboBox()
        self.completed_sort_combo.addItems([
            "Fecha (recientes primero)",
            "Fecha (antiguas primero)",
            "Número de orden (descendente)",
            "Número de orden (ascendente)"
        ])
        sort_layout.addWidget(sort_label)
        sort_layout.addWidget(self.completed_sort_combo)
        layout.addLayout(sort_layout)
        self.output_text = QTextEdit(); self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)
        btn_pdf = QPushButton("Emitir en PDF"); btn_excel = QPushButton("Exportar a Excel")
        btn_pdf_batch = QPushButton("Emitir PDF en lote")
        btns_layout = QHBoxLayout(); btns_layout.addWidget(btn_pdf); btns_layout.addWidget(btn_pdf_batch); btns_layout.addWidget(btn_excel)
        layout.addLayout(btns_layout)
        btn_view.clicked.connect(self.display_selected_result)
        btn_pdf.clicked.connect(self.export_pdf)
        btn_excel.clicked.connect(self.export_excel)
        btn_pdf_batch.clicked.connect(self.export_pdf_batch)
        btn_add_tests.clicked.connect(self.add_tests_to_selected_order)
        btn_delete_completed.clicked.connect(self.delete_order_from_emission)
        self.include_emitted_checkbox.toggled.connect(self.populate_completed_orders)
        self.completed_sort_combo.currentIndexChanged.connect(lambda: self._refresh_completed_combo())
    def populate_completed_orders(self):
        # Llenar combo de órdenes completadas
        include_emitted = False
        if hasattr(self, 'include_emitted_checkbox'):
            include_emitted = self.include_emitted_checkbox.isChecked()
        completed_rows = self.labdb.get_completed_orders(include_emitted=include_emitted)
        self.completed_orders_cache = []
        for row in completed_rows:
            oid, first, last, date, sample_date, doc_type, doc_number, emitted, emitted_at = row
            order = {
                "id": oid,
                "first_name": (first or "").upper(),
                "last_name": (last or "").upper(),
                "date": date,
                "sample_date": sample_date,
                "doc_type": doc_type or "",
                "doc_number": doc_number or "",
                "emitted": bool(emitted),
                "emitted_at": emitted_at
            }
            self.completed_orders_cache.append(order)
        self._refresh_completed_combo()


    def delete_order_from_results(self):
        if not hasattr(self, 'combo_orders'):
            return
        data = self.combo_orders.currentData()
        if data is None:
            QMessageBox.information(self, "Sin selección", "Seleccione una orden pendiente para eliminar.")
            return
        self._confirm_delete_order(int(data))

    def delete_order_from_emission(self):
        if not hasattr(self, 'combo_completed'):
            return
        data = self.combo_completed.currentData()
        if data is None:
            QMessageBox.information(self, "Sin selección", "Seleccione una orden completada para eliminar.")
            return
        self._confirm_delete_order(int(data))

    def _confirm_delete_order(self, order_id):
        if not order_id:
            return
        info = self.labdb.get_order_details(order_id)
        if not info:
            QMessageBox.warning(self, "Orden no disponible", "La orden seleccionada ya no está disponible.")
            self.populate_pending_orders()
            self.populate_completed_orders()
            return
        pat = info.get("patient", {})
        ord_inf = info.get("order", {})
        patient_name = pat.get("name") or "-"
        confirm = QMessageBox.question(
            self,
            "Eliminar orden",
            f"¿Desea eliminar la orden #{order_id} asociada a {patient_name}?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.No:
            return
        dialog = ReasonDialog(
            "Motivo de eliminación",
            "Indique el motivo por el que se elimina la orden.",
            self,
            placeholder="Motivo (ej. duplicado, prueba, error de digitación)"
        )
        dialog.text_edit.setPlainText("Duplicidad de registro")
        if dialog.exec_() != QDialog.Accepted:
            return
        reason = dialog.get_reason() or "Sin motivo"
        deleted = self.labdb.mark_order_deleted(order_id, reason, self.user.get('id'))
        if deleted:
            QMessageBox.information(self, "Orden eliminada", f"La orden #{order_id} fue eliminada correctamente.")
            if getattr(self, 'selected_order_id', None) == order_id:
                self.selected_order_id = None
            self.populate_pending_orders()
            self.populate_completed_orders()
            self.load_activity_summary()
            self.output_text.clear()
            self._clear_results_layout()
        else:
            QMessageBox.warning(self, "Sin cambios", "No se pudo eliminar la orden seleccionada.")

    def add_tests_to_selected_order(self):
        sender = self.sender()
        triggered_from_results = sender == getattr(self, 'results_add_tests_btn', None)
        order_id = None
        if triggered_from_results:
            if self.selected_order_id:
                order_id = int(self.selected_order_id)
            elif hasattr(self, 'combo_orders'):
                data = self.combo_orders.currentData()
                if data is not None:
                    order_id = int(data)
            if not order_id:
                QMessageBox.information(self, "Sin selección", "Cargue una orden pendiente antes de agregar pruebas.")
                return
        else:
            data = self.combo_completed.currentData() if hasattr(self, 'combo_completed') else None
            if data is None:
                QMessageBox.information(self, "Sin selección", "Seleccione una orden para agregar pruebas adicionales.")
                return
            order_id = int(data)
        all_tests = self.labdb.get_all_tests()
        existing = self.labdb.get_tests_for_order(order_id)
        dialog = AddTestsDialog(all_tests, existing, self)
        if dialog.exec_() != QDialog.Accepted:
            return
        selected = dialog.get_selected_tests()
        if not selected:
            QMessageBox.information(self, "Sin cambios", "No se seleccionaron nuevas pruebas.")
            return
        added = self.labdb.add_tests_to_order(order_id, selected)
        if not added:
            QMessageBox.information(self, "Sin cambios", "Las pruebas seleccionadas ya estaban asociadas a la orden.")
            return
        if triggered_from_results:
            QMessageBox.information(
                self,
                "Pruebas agregadas",
                "Se agregaron {0} prueba(s). Las nuevas pruebas aparecerán en el formulario.".format(len(added))
            )
            self.selected_order_id = order_id
            self.populate_pending_orders()
            self.load_order_fields()
        else:
            QMessageBox.information(
                self,
                "Pruebas agregadas",
                "Se agregaron {0} prueba(s). Registre los resultados antes de emitir nuevamente.".format(len(added))
            )
            self.selected_order_id = order_id
            self.populate_pending_orders()
            self.populate_completed_orders()
            reply = QMessageBox.question(
                self,
                "Registrar resultados",
                "¿Desea ir a la pantalla de resultados para completar las nuevas pruebas?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.stack.setCurrentWidget(self.page_resultados)
                if hasattr(self, 'combo_orders'):
                    self._select_order_in_combo(self.combo_orders, order_id)
                self.load_order_fields()

    def display_selected_result(self):
        # Mostrar los resultados de la orden seleccionada en el cuadro de texto
        data = self.combo_completed.currentData()
        if data is None:
            return
        order_id = int(data)
        info = self.labdb.get_order_details(order_id)
        if not info:
            return
        pat = info["patient"]
        ord_inf = info["order"]
        results = info["results"]
        context = {"patient": pat, "order": ord_inf}
        doc_text = " ".join([part for part in (pat.get('doc_type'), pat.get('doc_number')) if part]) or "-"
        lines = [f"PACIENTE: {pat.get('name') or '-'}", f"DOCUMENTO: {doc_text}"]
        age_value = self._calculate_age_years(pat, ord_inf)
        lines.append(f"EDAD: {age_value} AÑOS" if age_value is not None else "EDAD: -")
        lines.append(f"SEXO: {pat.get('sex') or '-'}")
        pregnancy_flag = pat.get('is_pregnant')
        gest_weeks = pat.get('gestational_age_weeks')
        due_raw = pat.get('expected_delivery_date')
        if pregnancy_flag or due_raw or gest_weeks not in (None, ''):
            if pregnancy_flag:
                weeks_text = ''
                if gest_weeks not in (None, '', 0):
                    try:
                        weeks_text = f"{int(gest_weeks)} SEMANAS"
                    except (TypeError, ValueError):
                        weeks_text = ''
                line = 'GESTANTE: SÍ'
                if weeks_text:
                    line += f" ({weeks_text})"
            else:
                line = 'GESTANTE: NO'
            lines.append(line)
            if due_raw:
                due_display = self._format_short_date(due_raw)
                if due_display == '—':
                    due_display = due_raw
                lines.append(f"FPP: {due_display}")
        lines.append(f"HISTORIA CLÍNICA: {pat.get('hcl') or '-'}")
        lines.append(f"PROCEDENCIA: {pat.get('origin') or '-'}")
        insurance_display = self._format_insurance_display(ord_inf.get('insurance_type'))
        lines.append(f"SEGURO: {insurance_display}")
        requester = ord_inf.get('requested_by') or '-'
        lines.append(f"SOLICITANTE: {requester}")
        emission_raw = ord_inf.get('emitted_at')
        if emission_raw:
            emission_display = self._format_datetime_display(emission_raw, emission_raw)
        else:
            emission_display = "Pendiente de emisión"
        lines.append(f"FECHA DEL INFORME: {emission_display}")
        sample_raw = ord_inf.get('sample_date')
        sample_display = self._format_date_display(sample_raw, "-")
        lines.append(f"FECHA DE TOMA DE MUESTRA: {sample_display}")
        lines.append("RESULTADOS:")
        for test_name, raw_result, _, sample_status, sample_issue, observation, _, pending_since in results:
            formatted_lines = self._format_result_lines(test_name, raw_result, context=context)
            if formatted_lines:
                lines.extend(formatted_lines)
            status_text = self._format_sample_status_text(sample_status, sample_issue, pending_since)
            if status_text:
                lines.append(f"    Estado de muestra: {status_text}")
            if observation:
                lines.append(f"    Observación: {observation}")
        if ord_inf["observations"]:
            lines.append(f"Observaciones generales: {ord_inf['observations']}")
        self.output_text.setPlainText("\n".join(lines))


    def export_pdf(self):
        data = self.combo_completed.currentData()
        if data is None:
            return
        order_id = int(data)
        info = self.labdb.get_order_details(order_id)
        if not info:
            QMessageBox.warning(self, "Orden no disponible", "La orden seleccionada ya no está disponible.")
            self.populate_completed_orders()
            return
        ord_inf = info["order"]
        suggested_name = f"Orden_{order_id}.pdf"
        options = QFileDialog.Options()
        default_path = self._ensure_output_directory("informes", suggested_name)
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar PDF",
            default_path,
            "Archivos PDF (*.pdf)",
            options=options
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".pdf"):
            file_path += ".pdf"
        existing_emission = ord_inf.get('emitted') and ord_inf.get('emitted_at')
        mark_as_emitted = False
        is_copy = False
        print_display = None
        if existing_emission:
            reply = QMessageBox.question(
                self,
                "Emitido previamente",
                "El informe ya fue emitido anteriormente. ¿Desea generar una copia?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
            emission_timestamp = ord_inf.get('emitted_at')
            try:
                emission_dt = datetime.datetime.strptime(emission_timestamp, "%Y-%m-%d %H:%M:%S")
                emission_display = emission_dt.strftime("%d/%m/%Y %H:%M")
            except Exception:
                emission_display = emission_timestamp or "-"
            copy_time = datetime.datetime.now()
            print_display = copy_time.strftime("%d/%m/%Y %H:%M")
            is_copy = True
        else:
            mark_as_emitted = True
            emission_time = datetime.datetime.now()
            emission_timestamp = emission_time.strftime("%Y-%m-%d %H:%M:%S")
            emission_display = emission_time.strftime("%d/%m/%Y %H:%M")
            print_display = emission_display
        pdf = FPDF('P', 'mm', 'A4')
        pdf.set_margins(12, 12, 12)
        pdf.set_auto_page_break(True, margin=14)
        pdf.add_page()
        self._render_order_pdf(
            pdf,
            info,
            emission_display,
            print_display=print_display,
            is_copy=is_copy
        )
        try:
            pdf.output(file_path)
        except Exception as exc:
            QMessageBox.warning(self, "Error", f"No se pudo guardar el PDF:\n{exc}")
            return
        if mark_as_emitted:
            self.labdb.mark_order_emitted(order_id, emission_timestamp)
        QMessageBox.information(self, "Informe emitido", f"Reporte guardado en:\n{file_path}")
        self.populate_completed_orders()
        self.output_text.clear()

    def _render_order_pdf(self, pdf, info, emission_display, print_display=None, is_copy=False):
        pat = info["patient"]
        ord_inf = info["order"]
        results = info["results"]
        context = {"patient": pat, "order": ord_inf}
        doc_text = " ".join([part for part in (pat.get('doc_type'), pat.get('doc_number')) if part]) or "-"
        patient_name = (pat.get('name') or '-').upper()
        age_text = self._format_age_text(pat, ord_inf)
        sex_text = (pat.get('sex') or '-').upper()
        hcl_text = (pat.get('hcl') or '-').upper()
        origin_text = (pat.get('origin') or '-').upper()
        requester_text = (ord_inf.get('requested_by') or '-').upper()
        header_image_path = os.path.join("img", "img.png")
        pregnancy_flag = pat.get('is_pregnant')
        gest_weeks = pat.get('gestational_age_weeks')
        due_raw = pat.get('expected_delivery_date')
        due_display = '-'
        if due_raw:
            due_display = self._format_short_date(due_raw)
            if due_display == '—':
                due_display = due_raw
        pregnancy_text = None
        if pregnancy_flag or due_raw or gest_weeks not in (None, ''):
            if pregnancy_flag:
                weeks_text = ''
                if gest_weeks not in (None, '', 0):
                    try:
                        weeks_text = f"{int(gest_weeks)} sem"
                    except (TypeError, ValueError):
                        weeks_text = ''
                pregnancy_text = 'Sí'
                if weeks_text:
                    pregnancy_text = f"{pregnancy_text} ({weeks_text})"
            else:
                pregnancy_text = 'No'
        sample_date_raw = ord_inf.get('sample_date')
        sample_date_display = self._format_date_display(sample_date_raw, '-')
        if not print_display:
            print_display = emission_display
        insurance_display = self._format_insurance_display(ord_inf.get('insurance_type'))
        info_pairs = [
            (("Paciente", patient_name), ("Edad", age_text)),
            (("Documento", doc_text.upper() if doc_text else "-"), ("Sexo", sex_text)),
            (("Seguro", insurance_display), ("Historia clínica", hcl_text)),
            (("Procedencia", origin_text), ("Fecha del informe", emission_display)),
            (("Solicitante", requester_text), ("Fecha de toma de muestra", sample_date_display)),
        ]
        if pregnancy_text:
            info_pairs.append((("Gestante", pregnancy_text), ("FPP", due_display)))

        def draw_patient_info():
            col_width = (pdf.w - pdf.l_margin - pdf.r_margin) / 2

            def wrap_value_lines(text, width):
                safe_value = str(text) if text not in (None, "") else "-"
                safe_value = self._ensure_latin1(safe_value)
                segments = []
                for part in safe_value.split('\n'):
                    part = part.strip()
                    if part:
                        segments.append(part)
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
                pdf.cell(width, 3.2, self._ensure_latin1(f"{label.upper()}:"), border=0)
                pdf.set_font("Arial", '', 7.2)
                current_y = start_y + 3.2
                value_lines = wrap_value_lines(value, width - 1.2)
                line_height = 3.0
                for line in value_lines:
                    pdf.set_xy(x_start, current_y)
                    pdf.cell(width, line_height, line, border=0)
                    current_y += line_height
                return current_y

            pdf.set_font("Arial", 'B', 8.8)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 5, self._ensure_latin1("Datos del paciente"), ln=1)
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
                    header_height = 27
                    pdf.image(header_image_path, x=pdf.l_margin, y=top_y, w=header_width, h=header_height)
                    pdf.set_y(top_y + header_height + 2)
                    header_drawn = True
                except Exception:
                    header_drawn = False
            if not header_drawn:
                fallback_logo = self._find_logo_path('center')
                if fallback_logo:
                    try:
                        pdf.image(fallback_logo, x=(pdf.w - 28) / 2, y=top_y, w=28)
                        pdf.set_y(top_y + 30)
                        header_drawn = True
                    except Exception:
                        header_drawn = False
            if not header_drawn:
                pdf.set_y(pdf.t_margin)
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(0, 6, self._ensure_latin1(LAB_TITLE), ln=1, align='C')
                pdf.ln(2)
            draw_patient_info()
            pdf.ln(1.0)
            if is_copy:
                copy_note = f"Copia reimpresa el {print_display}" if print_display else "Copia reimpresa"
                pdf.set_font("Arial", 'B', 8.5)
                pdf.set_text_color(110, 110, 110)
                pdf.cell(0, 4, self._ensure_latin1(copy_note), ln=1, align='R')
                pdf.set_text_color(0, 0, 0)
                pdf.ln(0.5)

        def ensure_space(required_height):
            if pdf.get_y() + required_height > pdf.h - pdf.b_margin:
                pdf.add_page()
                draw_page_header()
                return True
            return False

        def wrap_text(text, max_width):
            if max_width <= 0:
                return [str(text)]
            if text in (None, ""):
                text = "-"
            text = self._ensure_latin1(str(text)).replace('\r', ' ')
            segments = []
            for part in text.split('\n'):
                stripped = part.strip()
                if stripped:
                    segments.append(stripped)
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

        def render_table_header(widths, on_new_page=None):
            header_height = 6
            if ensure_space(header_height) and on_new_page:
                on_new_page()
                ensure_space(header_height)
            pdf.set_font("Arial", 'B', 7.2)
            pdf.set_text_color(255, 255, 255)
            pdf.set_fill_color(46, 117, 182)
            x_start = pdf.l_margin
            pdf.set_x(x_start)
            headers = ["Parámetro", "Resultado", "Valores de referencia"]
            for idx, title in enumerate(headers):
                pdf.cell(widths[idx], header_height, self._ensure_latin1(title), border=1, align='C', fill=True)
            pdf.ln(header_height)
            pdf.set_text_color(0, 0, 0)

        def render_table_row(texts, widths, on_new_page):
            line_height = 3.4
            padding_x = 1.4
            padding_y = 0.9
            pdf.set_font("Arial", '', 6.8)
            lines_by_cell = []
            max_lines = 1
            for idx, text in enumerate(texts):
                available = max(widths[idx] - 2 * padding_x, 1)
                lines = wrap_text(text, available)
                lines_by_cell.append(lines)
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
            for idx, lines in enumerate(lines_by_cell):
                cell_width = widths[idx]
                x_pos = x_start + sum(widths[:idx])
                pdf.set_fill_color(255, 255, 255)
                pdf.rect(x_pos, y_start, cell_width, row_height)
                text_y = y_start + padding_y
                for line in lines:
                    line = self._ensure_latin1(line)
                    pdf.set_xy(x_pos + padding_x, text_y)
                    pdf.cell(cell_width - 2 * padding_x, line_height, line, border=0)
                    text_y += line_height
            pdf.set_xy(pdf.l_margin, y_start + row_height)

        def render_section_row(label, total_width, widths, on_new_page):
            section_height = 4.2
            if ensure_space(section_height + 1):
                on_new_page()
                render_table_header(widths, on_new_page)
            pdf.set_font("Arial", 'B', 6.8)
            pdf.set_fill_color(242, 246, 253)
            pdf.set_text_color(47, 84, 150)
            pdf.cell(total_width, section_height, self._ensure_latin1(label), border=1, ln=1, align='L', fill=True)
            pdf.set_text_color(0, 0, 0)

        draw_page_header()

        table_total_width = pdf.w - pdf.l_margin - pdf.r_margin
        column_widths = [table_total_width * 0.38, table_total_width * 0.27, table_total_width * 0.35]

        def draw_test_header(title):
            ensure_space(9)
            pdf.set_font("Arial", 'B', 8.6)
            pdf.set_text_color(255, 255, 255)
            pdf.set_fill_color(46, 117, 182)
            pdf.cell(0, 6, self._ensure_latin1(title.upper()), ln=1, fill=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1.2)

        for test_name, raw_result, _, sample_status, sample_issue, observation, _, pending_since in results:
            structure = self._extract_result_structure(test_name, raw_result, context=context)
            if structure.get("type") == "structured":
                items = structure.get("items", [])
                if not any(item.get("type") == "value" for item in items):
                    continue
            else:
                value_text = structure.get("value", "")
                if isinstance(value_text, str):
                    if value_text.strip() == "":
                        continue
                elif self._is_blank_result(value_text):
                    continue
            draw_test_header(test_name)

            def on_new_page():
                draw_test_header(test_name)

            if structure.get("type") == "structured":
                render_table_header(column_widths, on_new_page)
                for item in structure.get("items", []):
                    if item.get("type") == "section":
                        render_section_row(item.get("label", ""), sum(column_widths), column_widths, on_new_page)
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
                pdf.set_font("Arial", '', 7)
                pdf.multi_cell(0, 4, self._ensure_latin1(text_value))
            status_text = self._format_sample_status_text(sample_status, sample_issue, pending_since)
            if status_text:
                ensure_space(5)
                pdf.set_font("Arial", 'I', 6.6)
                pdf.set_text_color(166, 38, 38)
                pdf.multi_cell(0, 3.8, self._ensure_latin1(f"Estado de muestra: {status_text}"))
                pdf.set_text_color(0, 0, 0)
            if observation:
                ensure_space(5)
                pdf.set_font("Arial", 'I', 6.6)
                pdf.multi_cell(0, 3.8, self._ensure_latin1(f"Observación: {observation}"))
            pdf.ln(2)

        if ord_inf.get('observations') and str(ord_inf['observations']).strip().upper() not in {"", "N/A"}:
            ensure_space(8)
            pdf.set_font("Arial", 'B', 7.4)
            pdf.cell(0, 4.2, "Observaciones generales", ln=1)
            pdf.set_font("Arial", '', 6.9)
            pdf.multi_cell(0, 3.6, self._ensure_latin1(ord_inf['observations']))
            pdf.ln(1.5)

    def export_pdf_batch(self):
        orders = getattr(self, 'completed_orders_cache', [])
        if not orders:
            QMessageBox.information(self, "Sin órdenes", "No hay órdenes completadas para emitir.")
            return
        options = []
        for order in orders:
            option = {
                "id": order["id"],
                "display": self._format_order_display(order),
                "preselect": not order.get("emitted"),
                "emitted": order.get("emitted")
            }
            options.append(option)
        dialog = BatchEmitDialog(options, self)
        if dialog.exec_() != QDialog.Accepted:
            return
        selected_ids = dialog.get_selected_ids()
        if not selected_ids:
            QMessageBox.information(self, "Sin selección", "Seleccione al menos una orden para emitir.")
            return
        orders_to_emit = []
        already_emitted = []
        for oid in selected_ids:
            info = self.labdb.get_order_details(oid)
            if not info:
                continue
            ord_inf = info["order"]
            existing_emission = ord_inf.get('emitted') and ord_inf.get('emitted_at')
            if existing_emission:
                already_emitted.append(oid)
                emission_timestamp = ord_inf.get('emitted_at')
                try:
                    emission_dt = datetime.datetime.strptime(emission_timestamp, "%Y-%m-%d %H:%M:%S")
                    emission_display = emission_dt.strftime("%d/%m/%Y %H:%M")
                except Exception:
                    emission_display = emission_timestamp or "-"
                mark = False
                copy_time = datetime.datetime.now()
                print_display = copy_time.strftime("%d/%m/%Y %H:%M")
                is_copy = True
            else:
                emission_time = datetime.datetime.now()
                emission_timestamp = emission_time.strftime("%Y-%m-%d %H:%M:%S")
                emission_display = emission_time.strftime("%d/%m/%Y %H:%M")
                mark = True
                print_display = emission_display
                is_copy = False
            orders_to_emit.append({
                "id": oid,
                "info": info,
                "emission_display": emission_display,
                "emission_timestamp": emission_timestamp,
                "mark": mark,
                "print_display": print_display,
                "is_copy": is_copy
            })
        if not orders_to_emit:
            QMessageBox.information(self, "Sin datos", "Las órdenes seleccionadas no están disponibles para emitir.")
            return
        if already_emitted:
            reply = QMessageBox.question(
                self,
                "Emitir copias",
                "Algunas órdenes ya fueron emitidas. ¿Desea generar copias junto con los nuevos informes?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                orders_to_emit = [entry for entry in orders_to_emit if entry.get("mark")]
                if not orders_to_emit:
                    return
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar lote",
            self._ensure_output_directory("informes", "Resultados_lote.pdf"),
            "Archivos PDF (*.pdf)"
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".pdf"):
            file_path += ".pdf"
        pdf = FPDF('P', 'mm', 'A4')
        pdf.set_margins(12, 12, 12)
        pdf.set_auto_page_break(True, margin=14)
        for idx, entry in enumerate(orders_to_emit):
            pdf.add_page()
            self._render_order_pdf(
                pdf,
                entry["info"],
                entry["emission_display"],
                print_display=entry.get("print_display"),
                is_copy=entry.get("is_copy")
            )
        try:
            pdf.output(file_path)
        except Exception as exc:
            QMessageBox.warning(self, "Error", f"No se pudo guardar el PDF:\n{exc}")
            return
        for entry in orders_to_emit:
            if entry.get("mark"):
                self.labdb.mark_order_emitted(entry["id"], entry["emission_timestamp"])
        QMessageBox.information(self, "Informe emitido", f"Resultados guardados en:\n{file_path}")
        self.populate_completed_orders()

    def export_excel(self):
        # Exportar todos los resultados a un archivo CSV (Excel puede abrirlo)
        options = QFileDialog.Options()
        default_path = self._ensure_output_directory("exportaciones", "exportacion.csv")
        file_path, _ = QFileDialog.getSaveFileName(self, "Exportar datos", default_path, "Archivo CSV (*.csv)", options=options)
        if not file_path:
            return
        if not file_path.lower().endswith(".csv"):
            file_path += ".csv"
        self.labdb.cur.execute("""
            SELECT p.first_name, p.last_name, p.doc_type, p.doc_number, p.sex, p.birth_date,
                   t.name, ot.result, o.date, o.requested_by, ot.sample_status, ot.sample_issue, ot.observation, o.age_years
            FROM order_tests ot
            JOIN orders o ON ot.order_id = o.id
            JOIN patients p ON o.patient_id = p.id
            JOIN tests t ON ot.test_id = t.id
            WHERE (o.deleted IS NULL OR o.deleted=0) AND (ot.deleted IS NULL OR ot.deleted=0)
        """)
        rows = self.labdb.cur.fetchall()
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("Nombre,Apellidos,Documento,Prueba,Resultado,Fecha,Solicitante,Estado de muestra,Observación muestra,Edad (años)\n")
                for first, last, doc_type, doc_num, sex, birth_date, test_name, result, date, requester, sample_status, sample_issue, observation, age_years in rows:
                    name = (first or "").upper(); surn = (last or "").upper(); doc = f"{doc_type} {doc_num}".strip()
                    context = {
                        "patient": {"sex": sex, "birth_date": birth_date},
                        "order": {"age_years": age_years}
                    }
                    res = self._format_result_for_export(test_name, result, context=context)
                    res = res.replace('"', "'")
                    dt = date
                    req = (requester or "").upper()
                    status_text = self._format_sample_status_text(sample_status, sample_issue) or "-"
                    obs_text = (observation or "").strip().replace('"', "'")
                    age_txt = str(age_years) if age_years is not None else ""
                    line = f"{name},{surn},{doc},{test_name},\"{res}\",{dt},{req},{status_text},\"{obs_text}\",{age_txt}\n"
                    f.write(line)
            QMessageBox.information(self, "Exportado", f"Datos exportados a:\n{file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"No se pudo exportar:\n{e}")
    def init_analisis_page(self):
        main_layout = QVBoxLayout(self.page_analisis)
        self.analysis_tabs = QTabWidget()
        main_layout.addWidget(self.analysis_tabs)

        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        stats_controls_layout = QHBoxLayout()
        stats_controls_layout.addWidget(QLabel("Visualizar por:"))
        self.stats_mode_combo = QComboBox()
        self.stats_mode_combo.addItems(["Mes", "Trimestre"])
        stats_controls_layout.addWidget(self.stats_mode_combo)
        today = datetime.date.today()
        self.stats_month_label = QLabel("Mes:")
        stats_controls_layout.addWidget(self.stats_month_label)
        self.stats_month_combo = QComboBox()
        self.stats_month_combo.addItems(MONTH_NAMES_ES)
        self.stats_month_combo.setCurrentIndex(max(0, today.month - 1))
        stats_controls_layout.addWidget(self.stats_month_combo)
        self.stats_quarter_label = QLabel("Trimestre:")
        stats_controls_layout.addWidget(self.stats_quarter_label)
        self.stats_quarter_combo = QComboBox()
        self.stats_quarter_combo.addItems(["I", "II", "III", "IV"])
        self.stats_quarter_combo.setCurrentIndex((today.month - 1) // 3)
        stats_controls_layout.addWidget(self.stats_quarter_combo)
        stats_controls_layout.addWidget(QLabel("Año:"))
        self.stats_year_spin = QSpinBox()
        self.stats_year_spin.setRange(2000, 2100)
        self.stats_year_spin.setValue(today.year)
        stats_controls_layout.addWidget(self.stats_year_spin)
        stats_controls_layout.addStretch()
        stats_layout.addLayout(stats_controls_layout)
        self.stats_label = QLabel()
        self.stats_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.stats_label)
        self.stats_table = QTableWidget(0, 3)
        self.stats_table.setHorizontalHeaderLabels(["Área", "Examen", "Cantidad"])
        self.stats_table.setAlternatingRowColors(True)
        self.stats_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.stats_table.setSelectionMode(QAbstractItemView.NoSelection)
        self.stats_table.verticalHeader().setVisible(False)
        self.stats_table.horizontalHeader().setStretchLastSection(True)
        stats_layout.addWidget(self.stats_table)
        self.analysis_tabs.addTab(stats_tab, "Estadísticas")

        activity_tab = QWidget()
        activity_layout = QVBoxLayout(activity_tab)
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Período:"))
        self.range_combo = QComboBox()
        self.range_combo.addItems([
            "Hoy",
            "Esta semana",
            "Este mes",
            "Últimos 30 días",
            "Rango personalizado"
        ])
        controls_layout.addWidget(self.range_combo)
        controls_layout.addSpacing(10)
        self.start_date_edit = QDateEdit(QDate.currentDate())
        self.start_date_edit.setDisplayFormat("dd/MM/yyyy")
        self.start_date_edit.setCalendarPopup(True)
        controls_layout.addWidget(QLabel("Desde:"))
        controls_layout.addWidget(self.start_date_edit)
        self.end_date_edit = QDateEdit(QDate.currentDate())
        self.end_date_edit.setDisplayFormat("dd/MM/yyyy")
        self.end_date_edit.setCalendarPopup(True)
        controls_layout.addWidget(QLabel("Hasta:"))
        controls_layout.addWidget(self.end_date_edit)
        controls_layout.addSpacing(10)
        self.view_activity_btn = QPushButton("Mostrar registro")
        self.export_activity_pdf_btn = QPushButton("Exportar PDF")
        self.export_activity_csv_btn = QPushButton("Exportar CSV")
        self.export_activity_delivery_btn = QPushButton("Hoja de entrega")
        self.delete_activity_btn = QPushButton("Eliminar selección")
        self.delete_activity_btn.setStyleSheet(
            "QPushButton { background-color: #ffe8e6; color: #c0392b; border-radius: 10px; border: 1px solid #c0392b; }"
            "QPushButton:hover:!disabled { background-color: #fbd1ce; }"
        )
        controls_layout.addWidget(self.view_activity_btn)
        controls_layout.addWidget(self.export_activity_pdf_btn)
        controls_layout.addWidget(self.export_activity_csv_btn)
        controls_layout.addWidget(self.export_activity_delivery_btn)
        controls_layout.addWidget(self.delete_activity_btn)
        controls_layout.addStretch()
        activity_layout.addLayout(controls_layout)

        activity_filter_layout = QHBoxLayout()
        activity_filter_layout.addWidget(QLabel("Búsqueda por muestras:"))
        self.activity_search_input = QLineEdit()
        self.activity_search_input.setPlaceholderText("Filtrar por prueba, paciente o estado de muestra")
        self.activity_search_input.setClearButtonEnabled(True)
        activity_filter_layout.addWidget(self.activity_search_input)
        activity_filter_layout.addStretch()
        activity_layout.addLayout(activity_filter_layout)

        self.activity_caption = QLabel()
        self.activity_caption.setStyleSheet("font-weight: bold;")
        activity_layout.addWidget(self.activity_caption)
        self.activity_table = QTableWidget(0, 8)
        self.activity_table.setHorizontalHeaderLabels([
            "F. muestra / Registro",
            "Orden",
            "Paciente",
            "Documento",
            "Edad",
            "Prueba",
            "Estado",
            "Resultado"
        ])
        self.activity_table.setAlternatingRowColors(True)
        self.activity_table.horizontalHeader().setStretchLastSection(True)
        self.activity_table.setSelectionMode(QTableWidget.MultiSelection)
        activity_layout.addWidget(self.activity_table)
        self.analysis_tabs.addTab(activity_tab, "Registro de pruebas")

        history_tab = QWidget()
        history_tab_layout = QVBoxLayout(history_tab)
        history_group = QGroupBox("Historial de pacientes")
        history_layout = QVBoxLayout(history_group)
        history_search_layout = QHBoxLayout()
        history_search_layout.addWidget(QLabel("DNI:"))
        self.history_doc_input = QLineEdit()
        self.history_doc_input.setPlaceholderText("Ingrese DNI")
        history_search_layout.addWidget(self.history_doc_input)
        history_search_layout.addWidget(QLabel("Apellidos:"))
        self.history_lastname_input = QLineEdit()
        self.history_lastname_input.setPlaceholderText("Ej. PEREZ / PEREZ GARCIA")
        history_search_layout.addWidget(self.history_lastname_input)
        self.history_search_btn = QPushButton("Buscar")
        history_search_layout.addWidget(self.history_search_btn)
        self.history_open_btn = QPushButton("Ver en emisión")
        self.history_open_btn.setEnabled(False)
        history_search_layout.addWidget(self.history_open_btn)
        self.history_fua_btn = QPushButton("Registrar FUA")
        self.history_fua_btn.setEnabled(False)
        history_search_layout.addWidget(self.history_fua_btn)
        self.history_window_btn = QPushButton("Ventana de historial")
        self.history_window_btn.setEnabled(False)
        history_search_layout.addWidget(self.history_window_btn)
        history_search_layout.addStretch()
        history_layout.addLayout(history_search_layout)
        history_headers = [
            "F. muestra / Registro",
            "Orden",
            "Paciente",
            "Documento",
            "F. Nacimiento",
            "Edad",
            "Gestación",
            "Sexo",
            "Procedencia",
            "HCL",
            "Tipo de seguro",
            "FUA",
            "Seguimiento",
            "Exámenes de la orden",
            "Hematología",
            "Bioquímica",
            "Micro/Parasitología",
            "Otros exámenes",
            "Emitido"
        ]
        self.history_table = QTableWidget(0, len(history_headers))
        self.history_table.setHorizontalHeaderLabels(history_headers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setSelectionMode(QTableWidget.SingleSelection)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setWordWrap(True)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_headers = history_headers
        self.history_column_map = {header: idx for idx, header in enumerate(history_headers)}
        history_layout.addWidget(self.history_table)

        self.history_preview_group = QGroupBox("Vista previa detallada de la orden")
        preview_layout = QVBoxLayout(self.history_preview_group)
        self.history_preview_hint = QLabel("Seleccione una fila para ver los exámenes y datos completos de la orden.")
        self.history_preview_hint.setStyleSheet("color: #555;")
        preview_layout.addWidget(self.history_preview_hint)
        self.history_preview_text = QTextEdit()
        self.history_preview_text.setReadOnly(True)
        self.history_preview_text.setMinimumHeight(200)
        self.history_preview_text.setPlaceholderText("Sin selección. Busque y seleccione una orden para ver el detalle aquí.")
        preview_layout.addWidget(self.history_preview_text)
        history_layout.addWidget(self.history_preview_group)
        history_tab_layout.addWidget(history_group)
        self.analysis_tabs.addTab(history_tab, "Historial de pacientes")
        self._stats_controls_ready = False
        self.stats_mode_combo.currentIndexChanged.connect(self._update_stats_period_controls)
        self.stats_month_combo.currentIndexChanged.connect(lambda _: self.refresh_statistics())
        self.stats_quarter_combo.currentIndexChanged.connect(lambda _: self.refresh_statistics())
        self.stats_year_spin.valueChanged.connect(lambda _: self.refresh_statistics())
        self._history_results = []
        self.range_combo.currentIndexChanged.connect(self._update_range_controls)
        self.activity_search_input.textChanged.connect(self.apply_activity_filter)
        self.view_activity_btn.clicked.connect(self.load_activity_summary)
        self.export_activity_pdf_btn.clicked.connect(lambda: self.export_activity_record("pdf"))
        self.export_activity_csv_btn.clicked.connect(lambda: self.export_activity_record("csv"))
        self.export_activity_delivery_btn.clicked.connect(self.export_activity_delivery_sheet)
        self.delete_activity_btn.clicked.connect(self.delete_selected_activity_entries)
        self._update_range_controls()
        self._stats_controls_ready = True
        self._update_stats_period_controls()
        self.history_doc_input.returnPressed.connect(self.search_patient_history)
        self.history_lastname_input.returnPressed.connect(self.search_patient_history)
        self.history_search_btn.clicked.connect(self.search_patient_history)
        self.history_open_btn.clicked.connect(self.open_history_order_from_analysis)
        self.history_table.itemSelectionChanged.connect(self._on_history_selection_changed)
        self.history_fua_btn.clicked.connect(self.edit_history_fua)
        self.history_window_btn.clicked.connect(self.open_history_window)
    def refresh_statistics(self):
        if not getattr(self, '_stats_controls_ready', False):
            return
        period = self._get_statistics_period()
        start_dt = datetime.datetime.combine(period['start'], datetime.time(0, 0, 0))
        end_dt = datetime.datetime.combine(period['end'], datetime.time(23, 59, 59))
        stats = self.labdb.get_statistics(start_dt.isoformat(sep=' '), end_dt.isoformat(sep=' '))
        summary_lines = [
            f"Período: {period['label']}",
            f"Pacientes atendidos: {stats['total_patients']}",
            f"Órdenes realizadas: {stats['total_orders']}",
            f"Pruebas realizadas: {stats['total_tests_conducted']}"
        ]
        self.stats_label.setText("\n".join(summary_lines))
        self.stats_table.setRowCount(0)
        detail = stats.get('by_category_detail', OrderedDict())
        ordered_categories = [cat for cat in CATEGORY_DISPLAY_ORDER if cat in detail]
        remaining = [cat for cat in detail.keys() if cat not in ordered_categories]
        categories = ordered_categories + remaining
        header_font = QFont()
        header_font.setBold(True)
        highlight_color = QColor(230, 242, 235)
        for category in categories:
            data = detail.get(category, {})
            total = data.get('total', 0)
            tests = data.get('tests', [])
            header_row = self.stats_table.rowCount()
            self.stats_table.insertRow(header_row)
            area_item = QTableWidgetItem(category)
            area_item.setFont(header_font)
            area_item.setBackground(highlight_color)
            self.stats_table.setItem(header_row, 0, area_item)
            total_label_item = QTableWidgetItem("Total del área")
            total_label_item.setFont(header_font)
            total_label_item.setBackground(highlight_color)
            self.stats_table.setItem(header_row, 1, total_label_item)
            total_item = QTableWidgetItem(str(total))
            total_item.setFont(header_font)
            total_item.setBackground(highlight_color)
            total_item.setTextAlignment(Qt.AlignCenter)
            self.stats_table.setItem(header_row, 2, total_item)
            for test_name, count in tests:
                row = self.stats_table.rowCount()
                self.stats_table.insertRow(row)
                self.stats_table.setItem(row, 0, QTableWidgetItem(""))
                exam_item = QTableWidgetItem(f"• {test_name}")
                self.stats_table.setItem(row, 1, exam_item)
                count_item = QTableWidgetItem(str(count))
                count_item.setTextAlignment(Qt.AlignCenter)
                self.stats_table.setItem(row, 2, count_item)
        self.load_activity_summary()

    def _update_stats_period_controls(self):
        if not hasattr(self, 'stats_mode_combo'):
            return
        is_month = self.stats_mode_combo.currentIndex() == 0
        self.stats_month_label.setVisible(is_month)
        self.stats_month_combo.setVisible(is_month)
        self.stats_quarter_label.setVisible(not is_month)
        self.stats_quarter_combo.setVisible(not is_month)
        if getattr(self, '_stats_controls_ready', False):
            self.refresh_statistics()

    def _get_statistics_period(self):
        year = self.stats_year_spin.value() if hasattr(self, 'stats_year_spin') else datetime.date.today().year
        if self.stats_mode_combo.currentIndex() == 0:
            month = max(1, self.stats_month_combo.currentIndex() + 1)
            start = datetime.date(year, month, 1)
            if month == 12:
                next_month_start = datetime.date(year + 1, 1, 1)
            else:
                next_month_start = datetime.date(year, month + 1, 1)
            end = next_month_start - datetime.timedelta(days=1)
            label = f"{MONTH_NAMES_ES[month - 1]} {year}"
        else:
            quarter = max(1, self.stats_quarter_combo.currentIndex() + 1)
            start_month = 3 * (quarter - 1) + 1
            start = datetime.date(year, start_month, 1)
            end_month = start_month + 2
            if end_month >= 12:
                next_start = datetime.date(year + 1, 1, 1)
            else:
                next_start = datetime.date(year, end_month + 1, 1)
            end = next_start - datetime.timedelta(days=1)
            label = (f"Trimestre {quarter} ({MONTH_NAMES_ES[start_month - 1]} - "
                     f"{MONTH_NAMES_ES[end_month - 1]} {year})")
        return {"start": start, "end": end, "label": label}

    def _update_range_controls(self):
        if not hasattr(self, 'range_combo'):
            return
        is_custom = self.range_combo.currentIndex() == 4
        if hasattr(self, 'start_date_edit'):
            self.start_date_edit.setEnabled(is_custom)
        if hasattr(self, 'end_date_edit'):
            self.end_date_edit.setEnabled(is_custom)
        if not is_custom and hasattr(self, 'start_date_edit') and hasattr(self, 'end_date_edit'):
            today = QDate.currentDate()
            self.start_date_edit.blockSignals(True)
            self.end_date_edit.blockSignals(True)
            self.start_date_edit.setDate(today)
            self.end_date_edit.setDate(today)
            self.start_date_edit.blockSignals(False)
            self.end_date_edit.blockSignals(False)

    def _get_selected_range(self):
        today = datetime.date.today()
        start_date = today
        end_date = today
        description = today.strftime("%d/%m/%Y")
        idx = self.range_combo.currentIndex() if hasattr(self, 'range_combo') else 0
        if idx == 0:  # Hoy
            description = f"Hoy ({today.strftime('%d/%m/%Y')})"
        elif idx == 1:  # Esta semana
            start_date = today - datetime.timedelta(days=today.weekday())
            end_date = start_date + datetime.timedelta(days=6)
            description = f"Semana del {start_date.strftime('%d/%m/%Y')} al {end_date.strftime('%d/%m/%Y')}"
        elif idx == 2:  # Este mes
            start_date = today.replace(day=1)
            if start_date.month == 12:
                next_month = datetime.date(start_date.year + 1, 1, 1)
            else:
                next_month = datetime.date(start_date.year, start_date.month + 1, 1)
            end_date = next_month - datetime.timedelta(days=1)
            description = f"Mes del {start_date.strftime('%d/%m/%Y')} al {end_date.strftime('%d/%m/%Y')}"
        elif idx == 3:  # Últimos 30 días
            start_date = today - datetime.timedelta(days=29)
            end_date = today
            description = f"Últimos 30 días ({start_date.strftime('%d/%m/%Y')} al {end_date.strftime('%d/%m/%Y')})"
        else:  # Rango personalizado
            if hasattr(self, 'start_date_edit') and hasattr(self, 'end_date_edit'):
                start_q = self.start_date_edit.date()
                end_q = self.end_date_edit.date()
                if start_q.isValid():
                    start_date = datetime.date(start_q.year(), start_q.month(), start_q.day())
                if end_q.isValid():
                    end_date = datetime.date(end_q.year(), end_q.month(), end_q.day())
            if end_date < start_date:
                start_date, end_date = end_date, start_date
            description = f"Del {start_date.strftime('%d/%m/%Y')} al {end_date.strftime('%d/%m/%Y')}"
        start_dt = datetime.datetime.combine(start_date, datetime.time.min)
        end_dt = datetime.datetime.combine(end_date, datetime.time.max)
        return start_dt, end_dt, description


    def _render_activity_rows(self, activity_data, description, total_count=None):
        if not hasattr(self, 'activity_table'):
            return
        self.activity_table.setRowCount(len(activity_data))
        for row_idx, item in enumerate(activity_data):
            self.activity_table.setItem(row_idx, 0, QTableWidgetItem(item.get("date", "")))
            order_item = QTableWidgetItem(str(item.get("order_id", "")))
            order_item.setTextAlignment(Qt.AlignCenter)
            self.activity_table.setItem(row_idx, 1, order_item)
            self.activity_table.setItem(row_idx, 2, QTableWidgetItem(item.get("patient", "")))
            self.activity_table.setItem(row_idx, 3, QTableWidgetItem(item.get("document", "")))
            age_item = QTableWidgetItem(item.get("age", ""))
            age_item.setTextAlignment(Qt.AlignCenter)
            self.activity_table.setItem(row_idx, 4, age_item)
            self.activity_table.setItem(row_idx, 5, QTableWidgetItem(item.get("test", "")))
            status_text = self._format_sample_status_text(item.get("sample_status"), item.get("sample_issue"))
            self.activity_table.setItem(row_idx, 6, QTableWidgetItem(status_text or "-"))
            self.activity_table.setItem(row_idx, 7, QTableWidgetItem(item.get("result", "")))
        if hasattr(self, 'activity_caption'):
            query = self.activity_search_input.text().strip() if hasattr(self, 'activity_search_input') else ""
            filtered_count = len(activity_data)
            base_total = total_count if total_count is not None else filtered_count
            if query and base_total != filtered_count:
                count_text = f"{filtered_count} coincidencia(s) de {base_total}" + (f" (filtro: \"{query}\")" if query else "")
            else:
                count_text = f"{filtered_count} resultado(s)"
            self.activity_caption.setText(
                f"Registro de pruebas: {description} - {count_text}"
            )


    def apply_activity_filter(self):
        cache = getattr(self, '_activity_cache', {}) if hasattr(self, '_activity_cache') else {}
        data = cache.get("data", [])
        description = cache.get("description", "")
        query = self.activity_search_input.text().strip().lower() if hasattr(self, 'activity_search_input') else ""
        if not query:
            filtered = data
        else:
            def matches(item):
                haystacks = [
                    item.get("patient", ""),
                    item.get("document", ""),
                    item.get("test", ""),
                    self._format_sample_status_text(item.get("sample_status"), item.get("sample_issue")) or "",
                    item.get("result", ""),
                ]
                haystacks = [h for h in haystacks if h not in (None, "")]
                return any(query in str(value).lower() for value in haystacks)
            filtered = [item for item in data if matches(item)]
        self._render_activity_rows(filtered, description, total_count=len(data))


    def load_activity_summary(self):
        if not hasattr(self, 'activity_table'):
            return
        start_dt, end_dt, description = self._get_selected_range()
        rows = self.labdb.get_results_in_range(
            start_dt.strftime("%Y-%m-%d %H:%M:%S"),
            end_dt.strftime("%Y-%m-%d %H:%M:%S")
        )
        activity_data = []
        for (
            test_entry_id,
            order_id,
            date_str,
            sample_date_str,
            first,
            last,
            doc_type,
            doc_number,
            sex,
            birth_date,
            hcl,
            origin,
            is_pregnant,
            gest_age_weeks,
            expected_delivery,
            age_years,
            order_obs,
            insurance_type,
            fua_number,
            test_name,
            category,
            result,
            sample_status,
            sample_issue,
            observation
        ) in rows:
            display_date = self._format_date_display(sample_date_str, "-")
            if display_date == "-":
                display_date = self._format_datetime_display(date_str, date_str or "-")
            patient_name = " ".join(part for part in [(first or "").upper(), (last or "").upper()] if part).strip() or "-"
            doc_text = " ".join(part for part in (doc_type, doc_number) if part).strip() or "-"
            age_display = str(age_years) if age_years not in (None, "") else "-"
            context = {
                "patient": {"sex": sex, "birth_date": birth_date},
                "order": {"age_years": age_years}
            }
            summary_items = self._build_registry_summary(test_name, result, context=context)
            if not summary_items:
                continue
            result_text = "; ".join(summary_items)
            activity_data.append({
                "entry_id": test_entry_id,
                "order_id": order_id,
                "date": display_date,
                "order_date_raw": date_str,
                "sample_date_raw": sample_date_str,
                "patient": patient_name,
                "document": doc_text,
                "doc_type": doc_type,
                "doc_number": doc_number,
                "birth_date": birth_date,
                "hcl": hcl,
                "sex": sex,
                "origin": origin,
                "is_pregnant": is_pregnant,
                "gestational_age_weeks": gest_age_weeks,
                "expected_delivery_date": expected_delivery,
                "age": age_display,
                "test": test_name,
                "result": result_text,
                "summary_items": summary_items,
                "category": category,
                "order_observations": order_obs,
                "insurance_type": insurance_type,
                "fua_number": fua_number,
                "emitted": None,
                "emitted_at": None,
                "first_name": first,
                "last_name": last,
                "sample_status": sample_status,
                "sample_issue": sample_issue,
                "observation": observation
            })
        self._activity_cache = {
            "data": activity_data,
            "description": description,
            "start": start_dt,
            "end": end_dt
        }
        if hasattr(self, 'activity_search_input'):
            self.apply_activity_filter()
        else:
            self._render_activity_rows(activity_data, description)


    def delete_selected_activity_entries(self):
        if not hasattr(self, 'activity_table'):
            return
        selected = self.activity_table.selectionModel().selectedRows() if self.activity_table.selectionModel() else []
        if not selected:
            QMessageBox.information(self, "Sin selección", "Seleccione al menos un resultado para eliminar.")
            return
        if not getattr(self, '_activity_cache', None):
            self.load_activity_summary()
        cache = getattr(self, '_activity_cache', {"data": []})
        entries = cache.get("data", [])
        selected_ids = []
        for model_index in selected:
            row = model_index.row()
            if 0 <= row < len(entries):
                entry = entries[row]
                entry_id = entry.get("entry_id")
                if entry_id:
                    selected_ids.append(entry_id)
        if not selected_ids:
            QMessageBox.warning(self, "Sin datos", "No se pudo identificar los registros seleccionados.")
            return
        dialog = ReasonDialog(
            "Eliminar resultados",
            "Indique el motivo de eliminación de los resultados seleccionados.",
            self,
            placeholder="Motivo (ej. duplicidad, prueba, corrección)"
        )
        dialog.text_edit.setPlainText("Duplicidad de registro")
        if dialog.exec_() != QDialog.Accepted:
            return
        reason = dialog.get_reason() or "Sin motivo"
        removed = 0
        for entry_id in selected_ids:
            if self.labdb.delete_order_test(entry_id, reason, self.user.get('id')):
                removed += 1
        if removed:
            QMessageBox.information(self, "Resultados eliminados", f"Se eliminaron {removed} resultado(s) del registro.")
            self.load_activity_summary()
            self.populate_pending_orders()
            self.populate_completed_orders()
        else:
            QMessageBox.warning(self, "Sin cambios", "No se eliminaron registros. Verifique el estado de las órdenes seleccionadas.")

    def export_activity_record(self, fmt):
        if fmt not in {"pdf", "csv"}:
            return
        if not getattr(self, '_activity_cache', None):
            self.load_activity_summary()
        cache = getattr(self, '_activity_cache', {"data": [], "description": ""})
        data = cache.get("data", [])
        if not data:
            QMessageBox.information(self, "Sin datos", "No hay registros para el período seleccionado.")
            return
        description = cache.get("description", "")
        if fmt == "csv":
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Exportar registro",
                self._ensure_output_directory("registros", "registro.csv"),
                "Archivo CSV (*.csv)"
            )
            if not file_path:
                return
            if not file_path.lower().endswith(".csv"):
                file_path += ".csv"
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("Fecha,Orden,Paciente,Documento,Edad,Prueba,Resultado\n")
                    for item in data:
                        result_clean = item["result"].replace('"', "'")
                        line = (
                            f"{item['date']},{item['order_id']},\"{item['patient']}\"," \
                            f"{item['document']},{item['age']},\"{item['test']}\",\"{result_clean}\"\n"
                        )
                        f.write(line)
            except Exception as exc:
                QMessageBox.warning(self, "Error", f"No se pudo exportar el archivo CSV:\n{exc}")
                return
            QMessageBox.information(self, "Exportado", f"Registro guardado en:\n{file_path}")
            return
        aggregated = self._aggregate_results_by_order(data)
        if not aggregated:
            QMessageBox.information(self, "Sin datos", "No hay resultados con información para exportar en PDF.")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar registro",
            self._ensure_output_directory("registros", "registro.pdf"),
            "Archivos PDF (*.pdf)"
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".pdf"):
            file_path += ".pdf"
        pdf = FPDF('L', 'mm', 'A4')
        pdf.set_margins(12, 12, 12)
        pdf.set_auto_page_break(True, margin=14)
        pdf.add_page()
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 8, self._ensure_latin1(LAB_TITLE), ln=1, align='C')
        pdf.set_font("Arial", '', 9)
        pdf.cell(0, 6, self._ensure_latin1(f"Registro de resultados - {description}"), ln=1, align='C')
        pdf.ln(2)
        headers = [
            "Fecha",
            "Datos del paciente (Apellidos y nombres / Documento / F. Nac. / HCL)",
            "Hematología",
            "Bioquímica",
            "Microbiología y Parasitología",
            "Otros exámenes / Observaciones"
        ]
        column_widths = [24, 74, 50, 45, 45, 35]
        line_height = 3.0
        padding_x = 1.2
        padding_y = 0.8

        def wrap_cell_text(text, available_width):
            sanitized = self._ensure_latin1(str(text) if text not in (None, "") else "-")
            segments = []
            for part in sanitized.split('\n'):
                part = part.strip()
                if part:
                    segments.append(part)
            if not segments:
                segments = [sanitized.strip() or "-"]
            lines = []
            for segment in segments:
                words = segment.split()
                if not words:
                    lines.append("-")
                    continue
                current = words[0]
                for word in words[1:]:
                    candidate = f"{current} {word}"
                    if pdf.get_string_width(candidate) <= max(available_width, 1):
                        current = candidate
                    else:
                        lines.append(current)
                        current = word
                lines.append(current)
            return lines or ["-"]

        def draw_header():
            pdf.set_fill_color(220, 220, 220)
            pdf.set_font("Arial", 'B', 7.8)
            cell_lines = []
            max_lines = 1
            for idx, header in enumerate(headers):
                available = max(column_widths[idx] - 2 * padding_x, 1)
                lines = wrap_cell_text(header, available)
                cell_lines.append(lines)
                if len(lines) > max_lines:
                    max_lines = len(lines)
            row_height = max_lines * line_height + 2 * padding_y
            x_start = pdf.l_margin
            y_start = pdf.get_y()
            pdf.set_draw_color(180, 180, 180)
            pdf.set_line_width(0.25)
            for idx, lines in enumerate(cell_lines):
                cell_width = column_widths[idx]
                x_pos = x_start + sum(column_widths[:idx])
                pdf.rect(x_pos, y_start, cell_width, row_height, style='DF')
                text_y = y_start + padding_y
                for line in lines:
                    pdf.set_xy(x_pos + padding_x, text_y)
                    pdf.cell(cell_width - 2 * padding_x, line_height, line, border=0, align='C')
                    text_y += line_height
            pdf.set_xy(pdf.l_margin, y_start + row_height)
            pdf.set_font("Arial", '', 6.4)

        def ensure_space(required_height):
            if pdf.get_y() + required_height > pdf.h - pdf.b_margin:
                pdf.add_page()
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(0, 8, self._ensure_latin1(LAB_TITLE), ln=1, align='C')
                pdf.set_font("Arial", '', 9)
                pdf.cell(0, 6, self._ensure_latin1(f"Registro de resultados - {description}"), ln=1, align='C')
                pdf.ln(2)
                draw_header()
                return True
            return False

        def render_row(texts):
            cell_lines = []
            max_lines = 1
            for idx, text in enumerate(texts):
                available = max(column_widths[idx] - 2 * padding_x, 1)
                lines = wrap_cell_text(text, available)
                cell_lines.append(lines)
                if len(lines) > max_lines:
                    max_lines = len(lines)
            row_height = max_lines * line_height + 2 * padding_y
            ensure_space(row_height)
            x_start = pdf.l_margin
            y_start = pdf.get_y()
            pdf.set_draw_color(210, 215, 226)
            pdf.set_line_width(0.2)
            for idx, lines in enumerate(cell_lines):
                cell_width = column_widths[idx]
                x_pos = x_start + sum(column_widths[:idx])
                pdf.rect(x_pos, y_start, cell_width, row_height)
                text_y = y_start + padding_y
                for line in lines:
                    pdf.set_xy(x_pos + padding_x, text_y)
                    pdf.cell(cell_width - 2 * padding_x, line_height, line, border=0)
                    text_y += line_height
            pdf.set_xy(pdf.l_margin, y_start + row_height)

        draw_header()

        def group_text(entry, key):
            values = entry.get("groups", {}).get(key, [])
            cleaned = [" ".join(str(val).split()) for val in values if str(val).strip()]
            return "\n".join(cleaned) if cleaned else "-"

        for entry in aggregated:
            ordered_cells = [
                self._format_date_for_registry(entry),
                self._format_patient_block_for_registry(entry),
                group_text(entry, "hematology"),
                group_text(entry, "biochemistry"),
                group_text(entry, "micro_parasito"),
                group_text(entry, "others")
            ]
            render_row(ordered_cells)
        try:
            pdf.output(file_path)
        except Exception as exc:
            QMessageBox.warning(self, "Error", f"No se pudo generar el PDF:\n{exc}")
            return
        QMessageBox.information(self, "Exportado", f"Registro guardado en:\n{file_path}")

    def export_activity_delivery_sheet(self):
        if not getattr(self, '_activity_cache', None):
            self.load_activity_summary()
        cache = getattr(self, '_activity_cache', {"data": [], "start": None, "end": None})
        data = cache.get("data", [])
        if not data:
            QMessageBox.information(self, "Sin datos", "No hay registros para el período seleccionado.")
            return
        aggregated = self._aggregate_results_by_order(data)
        if not aggregated:
            QMessageBox.information(self, "Sin datos", "No hay resultados con información para la hoja de entrega.")
            return
        report_start = cache.get("start")
        report_end = cache.get("end")
        try:
            start_date = report_start.date() if isinstance(report_start, datetime.datetime) else report_start
            end_date = report_end.date() if isinstance(report_end, datetime.datetime) else report_end
        except AttributeError:
            start_date = end_date = None
        if not (start_date and end_date and start_date == end_date):
            QMessageBox.information(
                self,
                "Rango no válido",
                "La hoja de entrega solo se puede generar cuando el rango seleccionado corresponde a un único día."
            )
            return
        base_date = start_date
        default_path = self._ensure_output_directory("registros", "hoja_entrega.pdf")
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar hoja de entrega",
            default_path,
            "Archivos PDF (*.pdf)"
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".pdf"):
            file_path += ".pdf"
        pdf = FPDF('L', 'mm', 'A5')
        pdf.set_margins(10, 14, 10)
        pdf.set_auto_page_break(True, margin=12)
        self._append_delivery_sheet(pdf, aggregated, base_date, page_format='A5')
        try:
            pdf.output(file_path)
        except Exception as exc:
            QMessageBox.warning(self, "Error", f"No se pudo generar la hoja de entrega:\n{exc}")
            return
        QMessageBox.information(self, "Exportado", f"Hoja de entrega guardada en:\n{file_path}")

    def _append_delivery_sheet(self, pdf, aggregated, report_date, page_format='A4'):
        if not aggregated:
            return
        prev_left, prev_top, prev_right, prev_bottom = pdf.l_margin, pdf.t_margin, pdf.r_margin, pdf.b_margin
        prev_auto = pdf.auto_page_break
        pdf.set_margins(10, 14, 10)
        pdf.set_auto_page_break(True, margin=12)
        self._add_pdf_page(pdf, orientation='L', page_format=page_format)
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(0, 6, self._ensure_latin1("Entrega de resultados"), ln=1, align='C')
        base_date = report_date
        if isinstance(base_date, datetime.datetime):
            base_date = base_date.date()
        if not base_date:
            base_date = datetime.date.today()
        pdf.set_font("Arial", '', 9)
        pdf.cell(
            0,
            5,
            self._ensure_latin1(f"Listado de pacientes - {base_date.strftime('%d/%m/%Y')}"),
            ln=1,
            align='C'
        )
        pdf.ln(1.5)
        available_width = max(pdf.w - pdf.l_margin - pdf.r_margin, 0)
        columns = [
            {"title": "Fecha de entrega", "ratio": 0.16, "min_lines": 1},
            {"title": "Paciente", "ratio": 0.22, "min_lines": 2},
            {"title": "Pruebas entregadas", "ratio": 0.26, "min_lines": 2},
            {"title": "Entregado por", "ratio": 0.16, "min_lines": 2},
            {"title": "Personal que recibe / Observaciones", "ratio": 0.20, "min_lines": 3},
        ]
        column_widths = [
            max(available_width * column["ratio"], 22) for column in columns
        ]
        padding_x = 1.2
        padding_y = 1.0
        line_height = 4.0

        def wrap_text(value, available_width, min_lines=1):
            base_text = ""
            if value not in (None, ""):
                base_text = self._ensure_latin1(str(value))
            segments = [seg.strip() for seg in base_text.split('\n') if seg.strip()]
            if not segments:
                segments = [""]
            lines = []
            for segment in segments:
                words = segment.split()
                if not words:
                    lines.append("")
                    continue
                current = words[0]
                for word in words[1:]:
                    candidate = f"{current} {word}"
                    if pdf.get_string_width(candidate) <= max(available_width, 1):
                        current = candidate
                    else:
                        lines.append(current)
                        current = word
                lines.append(current)
            if not lines:
                lines = [""]
            while len(lines) < min_lines:
                lines.append("")
            return lines

        pdf.set_draw_color(180, 180, 180)
        pdf.set_line_width(0.2)
        pdf.set_font("Arial", 'B', 7.6)
        header_lines = []
        max_header_lines = 1
        for idx, column in enumerate(columns):
            column_width = column_widths[idx]
            text_lines = wrap_text(column["title"], column_width - 2 * padding_x, 1)
            header_lines.append(text_lines)
            if len(text_lines) > max_header_lines:
                max_header_lines = len(text_lines)
        header_height = max_header_lines * line_height + 2 * padding_y
        start_x = pdf.l_margin
        start_y = pdf.get_y()
        pdf.set_fill_color(210, 210, 210)
        for idx, column in enumerate(columns):
            width = column_widths[idx]
            pdf.rect(start_x, start_y, width, header_height, style='DF')
            text_y = start_y + padding_y
            for line in header_lines[idx]:
                pdf.set_xy(start_x + padding_x, text_y)
                pdf.cell(width - 2 * padding_x, line_height, line, border=0)
                text_y += line_height
            start_x += width
        pdf.set_xy(pdf.l_margin, start_y + header_height)
        pdf.set_font("Arial", '', 7.2)
        deliverer_info = self._format_user_identity_for_delivery()
        for entry in aggregated:
            cell_values = [
                entry.get("date") or base_date.strftime("%d/%m/%Y"),
                entry.get("patient", "-"),
                "\n".join(entry.get("tests", [])) if entry.get("tests") else "-",
                deliverer_info,
                ""
            ]
            wrapped = []
            max_lines = 1
            for column, width, value in zip(columns, column_widths, cell_values):
                lines = wrap_text(value, width - 2 * padding_x, column["min_lines"])
                wrapped.append(lines)
                if len(lines) > max_lines:
                    max_lines = len(lines)
            row_height = max_lines * line_height + 2 * padding_y
            if pdf.get_y() + row_height > pdf.h - pdf.b_margin:
                self._add_pdf_page(pdf, orientation='L', page_format='A4')
                pdf.set_font("Arial", 'B', 11)
                pdf.cell(0, 6, self._ensure_latin1("Entrega de resultados"), ln=1, align='C')
                pdf.set_font("Arial", '', 9)
                pdf.cell(
                    0,
                    5,
                    self._ensure_latin1(f"Listado de pacientes - {base_date.strftime('%d/%m/%Y')}"),
                    ln=1,
                    align='C'
                )
                pdf.ln(1.5)
                pdf.set_font("Arial", 'B', 7.6)
                start_x = pdf.l_margin
                start_y = pdf.get_y()
                for idx, column in enumerate(columns):
                    width = column_widths[idx]
                    pdf.rect(start_x, start_y, width, header_height, style='DF')
                    text_y = start_y + padding_y
                    for line in header_lines[idx]:
                        pdf.set_xy(start_x + padding_x, text_y)
                        pdf.cell(width - 2 * padding_x, line_height, line, border=0)
                        text_y += line_height
                    start_x += width
                pdf.set_xy(pdf.l_margin, start_y + header_height)
                pdf.set_font("Arial", '', 7.2)
            row_start_x = pdf.l_margin
            row_start_y = pdf.get_y()
            for idx, column in enumerate(columns):
                width = column_widths[idx]
                pdf.rect(row_start_x, row_start_y, width, row_height)
                text_y = row_start_y + padding_y
                for line in wrapped[idx]:
                    pdf.set_xy(row_start_x + padding_x, text_y)
                    pdf.cell(width - 2 * padding_x, line_height, line, border=0)
                    text_y += line_height
                row_start_x += width
            pdf.set_xy(pdf.l_margin, row_start_y + row_height)
        pdf.set_margins(prev_left, prev_top, prev_right)
        pdf.set_auto_page_break(prev_auto, margin=prev_bottom)

    def _clear_history_table(self):
        if hasattr(self, 'history_table'):
            self.history_table.setRowCount(0)
        self._history_results = []
        if hasattr(self, 'history_open_btn'):
            self.history_open_btn.setEnabled(False)
        if hasattr(self, 'history_window_btn'):
            self.history_window_btn.setEnabled(False)
        self._render_history_preview(None)

    def _render_history_preview(self, entry):
        if not hasattr(self, 'history_preview_text'):
            return
        if not entry:
            self.history_preview_text.setPlainText(
                "Seleccione una orden para ver aquí un resumen completo de exámenes y datos del paciente."
            )
            return

        def add_section(title, content_lines):
            clean_lines = [line for line in content_lines if str(line).strip()]
            if not clean_lines:
                return
            lines.append(title)
            for line in clean_lines:
                lines.append(f"  {line}")
            lines.append("")

        lines = []
        header_date = self._format_date_for_registry(entry)
        emitted_text = self._format_emission_status(entry.get("emitted"), entry.get("emitted_at"))
        insurance_text = self._format_insurance_display(entry.get("insurance_type"))
        fua_text = self._format_fua_display(entry)
        lines.append(f"Orden #{entry.get('order_id', '-')}: {header_date or '-'}")
        lines.append(f"Seguro: {insurance_text} | FUA: {fua_text} | Emitido: {emitted_text}")
        lines.append("")

        patient_block = self._format_patient_block_for_registry(entry)
        add_section("Datos del paciente", patient_block.splitlines())

        sample_status_text = self._format_history_sample_status(entry)
        add_section("Estado de muestras", sample_status_text.split("\n"))

        observations = entry.get("observations")
        if observations:
            obs_clean = " ".join(str(observations).split())
            add_section("Observaciones de la orden", [obs_clean])

        groups = entry.get("groups", {})
        category_labels = [
            ("Hematología", "hematology"),
            ("Bioquímica", "biochemistry"),
            ("Micro/Parasitología", "micro_parasito"),
            ("Otros exámenes", "others")
        ]
        for label, key in category_labels:
            items = groups.get(key, []) if isinstance(groups, dict) else []
            add_section(label, [f"• {item}" for item in items])

        tests = entry.get("tests", [])
        add_section("Exámenes en la orden", [f"• {test}" for test in sorted(set(tests))])

        self.history_preview_text.setPlainText("\n".join(lines).rstrip())

    def _on_history_selection_changed(self):
        if not hasattr(self, 'history_table'):
            return
        selection = self.history_table.selectionModel()
        has_selection = bool(selection.selectedRows()) if selection else False
        if hasattr(self, 'history_open_btn'):
            self.history_open_btn.setEnabled(has_selection)
        if hasattr(self, 'history_fua_btn'):
            enable_fua = False
            tooltip = ""
            if has_selection and selection:
                indexes = selection.selectedRows()
                if indexes:
                    row = indexes[0].row()
                    history_items = getattr(self, '_history_results', [])
                    if 0 <= row < len(history_items):
                        entry = history_items[row]
                        insurance = (entry.get("insurance_type") or "").strip().lower()
                        if insurance == "particular":
                            tooltip = "Las atenciones particulares no requieren FUA."
                        else:
                            enable_fua = True
            self.history_fua_btn.setEnabled(enable_fua)
            self.history_fua_btn.setToolTip(tooltip)
        self._update_history_preview_from_selection()

    def _update_history_preview_from_selection(self):
        if not hasattr(self, 'history_table'):
            return
        selection = self.history_table.selectionModel()
        if not selection or not selection.selectedRows():
            self._render_history_preview(None)
            return
        row = selection.selectedRows()[0].row()
        history_items = getattr(self, '_history_results', [])
        entry = history_items[row] if 0 <= row < len(history_items) else None
        self._render_history_preview(entry)


    def search_patient_history(self):
        if not hasattr(self, 'history_table'):
            return
        doc_number = self.history_doc_input.text().strip() if hasattr(self, 'history_doc_input') else ""
        last_name = self.history_lastname_input.text().strip() if hasattr(self, 'history_lastname_input') else ""
        if doc_number == "" and last_name == "":
            QMessageBox.warning(self, "Filtro requerido", "Ingrese un DNI o apellidos para realizar la búsqueda.")
            return
        if doc_number and not doc_number.isdigit():
            QMessageBox.warning(self, "Formato inválido", "El DNI debe contener solo números.")
            return
        self._clear_history_table()
        rows = self.labdb.get_patient_history(doc_number=doc_number or None, doc_type="DNI" if doc_number else None, last_name=last_name or None)
        records = []
        for row in rows:
            (
                order_id,
                date_str,
                sample_date_str,
                test_name,
                raw_result,
                category,
                first_name,
                patient_last_name,
                doc_type,
                doc_value,
                sex,
                birth_date,
                hcl,
                origin,
                is_pregnant,
                gest_age_weeks,
                expected_delivery,
                age_years,
                order_obs,
                insurance_type,
                fua_number,
                emitted,
                emitted_at,
                sample_status,
                sample_issue,
                observation,
                pending_since,
                entry_id
            ) = row
            display_date = self._format_date_display(sample_date_str, "-")
            if display_date == "-":
                display_date = self._format_datetime_display(date_str, date_str or "-")
            patient_name = " ".join(part for part in [(first_name or "").upper(), (patient_last_name or "").upper()] if part).strip() or "-"
            doc_text = " ".join(part for part in (doc_type, doc_value) if part).strip() or "-"
            age_display = str(age_years) if age_years not in (None, "") else "-"
            context = {
                "patient": {"sex": sex, "birth_date": birth_date},
                "order": {"age_years": age_years}
            }
            summary_items = self._build_registry_summary(test_name, raw_result, context=context)
            if not summary_items:
                continue
            result_text = "; ".join(summary_items)
            records.append({
                "entry_id": entry_id,
                "order_id": order_id,
                "date": display_date,
                "order_date_raw": date_str,
                "sample_date_raw": sample_date_str,
                "patient": patient_name,
                "document": doc_text,
                "doc_type": doc_type,
                "doc_number": doc_value,
                "birth_date": birth_date,
                "hcl": hcl,
                "sex": sex,
                "origin": origin,
                "is_pregnant": is_pregnant,
                "gestational_age_weeks": gest_age_weeks,
                "expected_delivery_date": expected_delivery,
                "age": age_display,
                "test": test_name,
                "result": result_text,
                "summary_items": summary_items,
                "category": category,
                "order_observations": order_obs,
                "insurance_type": insurance_type,
                "fua_number": fua_number,
                "emitted": emitted,
                "emitted_at": emitted_at,
                "first_name": first_name,
                "last_name": patient_last_name,
                "sample_status": sample_status,
                "sample_issue": sample_issue,
                "observation": observation,
                "pending_since": pending_since
            })
        aggregated = self._aggregate_results_by_order(records)
        self._history_results = aggregated
        self._populate_history_table_widget(self.history_table, aggregated)
        if not aggregated:
            QMessageBox.information(self, "Sin resultados", "No se encontró historial con resultados registrados para los filtros ingresados.")
            self._render_history_preview(None)
        else:
            self.history_table.selectRow(0)
        self._on_history_selection_changed()
        if hasattr(self, 'history_window_btn'):
            self.history_window_btn.setEnabled(bool(aggregated))

    def open_history_window(self):
        aggregated = getattr(self, '_history_results', [])
        if not aggregated:
            QMessageBox.information(self, "Sin resultados", "Primero realice una búsqueda en el historial.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Historial detallado de pacientes")
        layout = QVBoxLayout(dialog)
        filters = []
        if hasattr(self, 'history_doc_input'):
            doc_value = self.history_doc_input.text().strip()
            if doc_value:
                filters.append(f"DNI: {doc_value}")
        if hasattr(self, 'history_lastname_input'):
            last_value = self.history_lastname_input.text().strip()
            if last_value:
                filters.append(f"Apellidos: {last_value}")
        filter_text = ", ".join(filters) if filters else "Sin filtros adicionales"
        layout.addWidget(QLabel(f"Filtros aplicados: {filter_text}"))
        table = QTableWidget(0, len(getattr(self, 'history_headers', [])))
        table.setHorizontalHeaderLabels(getattr(self, 'history_headers', []))
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setStretchLastSection(True)
        table.setWordWrap(True)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        self._populate_history_table_widget(table, aggregated)
        layout.addWidget(table)
        dialog.resize(1150, 650)
        dialog.exec_()

    def open_history_order_from_analysis(self):
        if not hasattr(self, 'history_table'):
            return
        selection = self.history_table.selectionModel()
        if not selection:
            return
        indexes = selection.selectedRows()
        if not indexes:
            QMessageBox.information(self, "Sin selección", "Seleccione una orden para abrirla en la emisión.")
            return
        row = indexes[0].row()
        history_items = getattr(self, '_history_results', [])
        if row >= len(history_items):
            return
        order_id = history_items[row].get("order_id")
        if not order_id:
            QMessageBox.warning(self, "Orden no disponible", "No se pudo determinar el número de orden seleccionado.")
            return
        if hasattr(self, 'include_emitted_checkbox'):
            self.include_emitted_checkbox.setChecked(True)
        self.populate_completed_orders()
        self._select_order_in_combo(self.combo_completed, order_id)
        self.display_selected_result()
        self.stack.setCurrentWidget(self.page_emitir)

    def edit_history_fua(self):
        if not hasattr(self, 'history_table'):
            return
        selection = self.history_table.selectionModel()
        if not selection or not selection.selectedRows():
            QMessageBox.information(self, "Sin selección", "Seleccione una orden para registrar su FUA.")
            return
        row = selection.selectedRows()[0].row()
        history_items = getattr(self, '_history_results', [])
        if row >= len(history_items):
            return
        entry = history_items[row]
        insurance = (entry.get("insurance_type") or "").strip().lower()
        if insurance == "particular":
            QMessageBox.information(self, "FUA no requerido", "Esta atención es Particular, no requiere FUA.")
            return
        order_id = entry.get("order_id")
        if not order_id:
            QMessageBox.warning(self, "Orden no disponible", "No se pudo identificar la orden seleccionada.")
            return
        current_value = entry.get("fua_number") or ""
        text, ok = QInputDialog.getText(
            self,
            "Registrar FUA",
            f"Ingrese el número de FUA para la orden #{order_id}:",
            QLineEdit.Normal,
            current_value
        )
        if not ok:
            return
        new_value = text.strip()
        updated = self.labdb.update_order_fua(order_id, new_value)
        if not updated:
            QMessageBox.warning(self, "Sin cambios", "No se pudo actualizar el número de FUA.")
            return
        entry["fua_number"] = new_value
        fua_text = self._format_fua_display(entry)
        fua_col = getattr(self, 'history_column_map', {}).get("FUA") if hasattr(self, 'history_column_map') else None
        if fua_col is not None:
            item = QTableWidgetItem(fua_text)
            item.setTextAlignment(Qt.AlignCenter)
            self.history_table.setItem(row, fua_col, item)
        QMessageBox.information(self, "FUA actualizado", "El número de FUA se registró correctamente.")
        self._on_history_selection_changed()
    def init_config_page(self):
        layout = QVBoxLayout(self.page_config)
        profile_group = QGroupBox("Datos del usuario actual")
        profile_layout = QFormLayout(profile_group)
        self.profile_full_name_input = QLineEdit()
        profile_layout.addRow("Nombre completo:", self.profile_full_name_input)
        self.profile_profession_input = QLineEdit()
        profile_layout.addRow("Profesión / Cargo:", self.profile_profession_input)
        self.profile_license_input = QLineEdit()
        profile_layout.addRow("Colegiatura / Registro:", self.profile_license_input)
        btn_save_profile = QPushButton("Guardar perfil")
        btn_save_profile.clicked.connect(self.save_user_profile)
        profile_layout.addRow(btn_save_profile)
        layout.addWidget(profile_group)
        self._populate_profile_fields()
        info_label = QLabel("Crear nuevo usuario:")
        layout.addWidget(info_label)
        form_layout = QFormLayout()
        self.new_user_input = QLineEdit(); form_layout.addRow("Usuario:", self.new_user_input)
        self.new_pass_input = QLineEdit(); self.new_pass_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Contraseña:", self.new_pass_input)
        self.new_user_full_name = QLineEdit(); form_layout.addRow("Nombre completo:", self.new_user_full_name)
        self.new_user_profession = QLineEdit(); form_layout.addRow("Profesión / Cargo:", self.new_user_profession)
        self.new_user_license = QLineEdit(); form_layout.addRow("Colegiatura / Registro:", self.new_user_license)
        self.role_input = QComboBox(); self.role_input.addItems(["Administrador", "Superusuario"])
        form_layout.addRow("Rol:", self.role_input)
        layout.addLayout(form_layout)
        btn_create = QPushButton("Crear Usuario")
        layout.addWidget(btn_create)
        btn_create.clicked.connect(self.create_user)

    def _populate_profile_fields(self):
        if not hasattr(self, 'profile_full_name_input'):
            return
        self.profile_full_name_input.setText(self.user.get('full_name', ''))
        self.profile_profession_input.setText(self.user.get('profession', ''))
        self.profile_license_input.setText(self.user.get('license', ''))

    def save_user_profile(self):
        if not hasattr(self, 'profile_full_name_input'):
            return
        full_name = self.profile_full_name_input.text().strip()
        profession = self.profile_profession_input.text().strip()
        license_code = self.profile_license_input.text().strip()
        success = self.labdb.update_user_profile(self.user.get('id'), full_name, profession, license_code)
        if success:
            self.user['full_name'] = full_name
            self.user['profession'] = profession
            self.user['license'] = license_code
            QMessageBox.information(self, "Perfil actualizado", "Los datos del usuario fueron guardados.")
        else:
            QMessageBox.warning(self, "Sin cambios", "No se pudieron actualizar los datos del usuario.")
    def create_user(self):
        username = self.new_user_input.text().strip()
        password = self.new_pass_input.text().strip()
        role_text = self.role_input.currentText()
        role = "admin" if role_text == "Administrador" else "super"
        if username == "" or password == "":
            QMessageBox.warning(self, "Campos vacíos", "Ingrese nombre de usuario y contraseña.")
            return
        full_name = self.new_user_full_name.text().strip()
        profession = self.new_user_profession.text().strip()
        license_code = self.new_user_license.text().strip()
        success = self.labdb.create_user(username, password, role, full_name, profession, license_code)
        if success:
            QMessageBox.information(self, "Usuario creado", f"Usuario '{username}' creado exitosamente.")
            self.new_user_input.clear(); self.new_pass_input.clear()
            self.new_user_full_name.clear(); self.new_user_profession.clear(); self.new_user_license.clear()
        else:
            QMessageBox.warning(self, "Error", "No se pudo crear el usuario. ¿Nombre ya existe?")
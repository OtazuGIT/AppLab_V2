# Laboratorio P.S. Iñapari — App Web

Aplicación web de gestión de resultados y reportes para un laboratorio clínico de primer nivel.

## Requisitos

- **Python 3.11 o superior** (32-bit o 64-bit según la PC)
- **Git** (solo si quieres recibir actualizaciones automáticas)

## Instalación rápida (PC de usuario final)

### 1. Clonar el repositorio

```cmd
cd C:\
git clone https://github.com/OtazuGIT/AppLab_V2.git laboratorio
cd laboratorio
```

### 2. Iniciar la app

Doble clic en **`Iniciar_Laboratorio.bat`**.

La primera vez instalará las dependencias automáticamente (fpdf y openpyxl). En los siguientes inicios solo arranca el servidor.

Se abrirá el navegador en **http://localhost:8000**.

### 3. Actualizar la app cuando haya cambios

Doble clic en **`Actualizar_App.bat`**. Esto descarga los cambios desde GitHub sin tocar tu base de datos local.

## Estructura del proyecto

```
laboratorio/
├── web_app.py              # Servidor HTTP + rutas
├── database.py             # Capa de acceso a SQLite
├── pdf_generator.py        # Generación de PDF (órdenes, lotes, registro)
├── test_definitions.py     # Plantillas de exámenes y categorías
├── templates/              # HTML (login, dashboard)
├── static/                 # CSS
├── img/                    # Logo del laboratorio
├── requirements.txt        # Dependencias Python
├── Iniciar_Laboratorio.bat # Lanzador de la app
├── Actualizar_App.bat      # Actualiza desde GitHub
└── lab_db.sqlite           # Base de datos local (se crea automáticamente)
```

> La base de datos `lab_db.sqlite` **no se sube a GitHub** — cada PC tiene su propia copia con su data.

## Instalación manual (desarrolladores)

```cmd
python -m pip install -r requirements.txt
python web_app.py
```

Abrir navegador en http://localhost:8000.

## Notas

- Para cerrar la app: cerrar la ventana negra (CMD) que abre el launcher.
- La app funciona en Windows 7/8/10/11 con Python 3.11+.
- Compatible con 32-bit y 64-bit.

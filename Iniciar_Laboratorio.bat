@echo off
REM =============================================================
REM  Laboratorio P.S. Iñapari - Lanzador
REM  Inicia el servidor web y abre el navegador automaticamente
REM =============================================================
title Laboratorio P.S. Inapari
cd /d "%~dp0"

echo.
echo ================================================
echo   LABORATORIO P.S. INAPARI - Iniciando...
echo ================================================
echo.

REM Verificar que Python esta instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python no esta instalado o no esta en el PATH.
    echo.
    echo Por favor instala Python 3.11 o superior desde:
    echo   https://www.python.org/downloads/windows/
    echo.
    echo Al instalar, MARCA la casilla "Add python.exe to PATH"
    echo.
    pause
    exit /b 1
)

REM Verificar dependencias (fpdf y openpyxl)
python -c "import fpdf, openpyxl" >nul 2>&1
if errorlevel 1 (
    echo Instalando dependencias por primera vez, por favor espere...
    echo.
    python -m pip install --quiet --disable-pip-version-check -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] No se pudieron instalar las dependencias.
        echo Verifica tu conexion a internet e intentalo de nuevo.
        pause
        exit /b 1
    )
    echo Dependencias instaladas correctamente.
    echo.
)

echo Servidor iniciando en: http://localhost:8000
echo.
echo Para cerrar la app, cierra esta ventana o presiona Ctrl+C
echo.

REM Abrir el navegador tras 2 segundos (para dar tiempo al servidor)
start "" /B cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:8000"

REM Arrancar el servidor (bloquea hasta que se cierre)
python web_app.py

echo.
echo Servidor detenido.
pause

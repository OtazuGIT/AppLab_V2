@echo off
REM =============================================================
REM  Laboratorio P.S. Iñapari - Actualizador
REM  Descarga la ultima version desde GitHub (sin tocar la BD)
REM =============================================================
title Actualizar Laboratorio
cd /d "%~dp0"

echo.
echo ================================================
echo   ACTUALIZANDO LABORATORIO DESDE GITHUB...
echo ================================================
echo.

REM Verificar git
git --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git no esta instalado.
    echo Descargalo desde: https://git-scm.com/download/win
    pause
    exit /b 1
)

echo Descargando cambios...
git pull
if errorlevel 1 (
    echo.
    echo [ERROR] No se pudo actualizar. Revisa tu conexion.
    pause
    exit /b 1
)

echo.
echo ================================================
echo   APP ACTUALIZADA CORRECTAMENTE
echo ================================================
echo.
echo Actualizando dependencias (si hay nuevas)...
python -m pip install --quiet --disable-pip-version-check -r requirements.txt >nul 2>&1

echo.
echo Listo. Ya puedes iniciar la app con "Iniciar_Laboratorio.bat"
echo.
pause

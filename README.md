# App_lab_clinic

Aplicación de escritorio en PyQt5 para gestionar resultados y reportes de un laboratorio clínico.

## Requisitos

* Python 3.9 o superior.
* Dependencias listadas en [`requirements.txt`](requirements.txt).
* (Opcional) PyInstaller para generar ejecutables auto-contenidos.

## Configurar el entorno de desarrollo

```bash
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

La base de datos `lab_db.sqlite` se crea y migra automáticamente al iniciar la aplicación.

## Crear un instalador/ejecutable con PyInstaller

1. Activa tu entorno virtual y asegúrate de tener las dependencias instaladas (`pip install -r requirements.txt`).
2. Ejecuta PyInstaller utilizando el archivo de especificación incluido:
   ```bash
   pyinstaller --clean --noconfirm pyinstaller.spec
   ```
3. El ejecutable sin consola se generará dentro de `dist/AppLabClinic`. Copia esa carpeta completa a la computadora destino.
4. En la máquina de destino, ejecuta `AppLabClinic/AppLabClinic.exe` (Windows) o el binario correspondiente según el sistema operativo.

El archivo `pyinstaller.spec` ya incluye los recursos necesarios (`lab_db.sqlite`, `registro.csv` e imágenes). Si agregas nuevos archivos estáticos, actualiza la sección `datas` del spec para que se incluyan en el empaquetado.

## Distribuir con instaladores nativos (opcional)

Para una experiencia más pulida puedes envolver la carpeta `dist/AppLabClinic` con herramientas específicas del sistema operativo:

* **Windows:** utilizar Inno Setup o NSIS para crear un instalador `.exe` tradicional.
* **Linux:** generar paquetes `.deb` o `.rpm` a partir de la carpeta de distribución, o crear un AppImage usando `appimagetool`.
* **macOS:** firmar y empaquetar el contenido en un `.app` utilizando `create-dmg` o `productbuild`.

En todos los casos incluye la carpeta completa generada por PyInstaller para mantener los recursos y la base de datos inicial.

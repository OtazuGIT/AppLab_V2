# main.py
import sys
from PyQt5.QtWidgets import QApplication
from database import LabDB
from login_dialog import LoginDialog
from main_window import MainWindow
if __name__ == "__main__":
    app = QApplication(sys.argv)
    db = LabDB("lab_db.sqlite")
    db.connect(); db.init_db()
    login = LoginDialog(db)
    if login.exec_() == LoginDialog.Accepted:
        main_win = MainWindow(db, login.user_data)
        main_win.showFullScreen()
        sys.exit(app.exec_())

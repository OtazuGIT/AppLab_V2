# login_dialog.py
from PyQt5.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QGridLayout,
    QMessageBox,
    QFrame,
)
from PyQt5.QtCore import QDateTime, Qt, QTimer

LAB_TITLE = "Laboratorio P.S. Iñapari - 002789"

class LoginDialog(QDialog):
    def __init__(self, labdb):
        super().__init__()
        self.labdb = labdb
        self.setWindowTitle(LAB_TITLE)
        self.setModal(True)
        self.showFullScreen()        # pantalla completa
        self.setObjectName("LoginDialog")
        self.setStyleSheet(
            """
            QDialog#LoginDialog {
                background-color: #e8f0f7;
            }
            QFrame#LoginCard {
                background-color: #ffffff;
                border-radius: 18px;
                border: 1px solid #d0dceb;
            }
            QFrame#LoginCard QLabel {
                color: #1f2d3d;
            }
            QLabel#LoginTitle {
                font-size: 20px;
                font-weight: 700;
            }
            QLabel#LoginSubtitle {
                font-size: 13px;
                color: #52606d;
            }
            QLineEdit {
                border: 1px solid #c2d0e4;
                border-radius: 8px;
                padding: 10px 12px;
                background-color: #f9fbff;
            }
            QLineEdit:focus {
                border-color: #3584e4;
                background-color: #ffffff;
            }
            QPushButton#LoginButton {
                background-color: #1E8449;
                color: white;
                border-radius: 10px;
                padding: 12px 18px;
                font-weight: 600;
            }
            QPushButton#LoginButton:hover {
                background-color: #176b3a;
            }
            QLabel#LoginClock {
                font-size: 18px;
                color: #0a84ff;
            }
            """
        )
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(80, 60, 80, 60)
        outer_layout.setSpacing(0)
        outer_layout.addStretch()

        card = QFrame()
        card.setObjectName("LoginCard")
        card.setMaximumWidth(460)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(40, 32, 40, 32)
        card_layout.setSpacing(24)

        title = QLabel(LAB_TITLE)
        title.setObjectName("LoginTitle")
        title.setAlignment(Qt.AlignCenter)
        title.setWordWrap(True)
        card_layout.addWidget(title)

        subtitle = QLabel("Sistema de gestión de laboratorio")
        subtitle.setObjectName("LoginSubtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)
        card_layout.addWidget(subtitle)

        form_layout = QGridLayout()
        form_layout.setVerticalSpacing(14)
        form_layout.setHorizontalSpacing(12)
        label_user = QLabel("Usuario:")
        self.input_user = QLineEdit()
        self.input_user.setPlaceholderText("Ingrese su usuario")
        label_pass = QLabel("Contraseña:")
        self.input_pass = QLineEdit()
        self.input_pass.setEchoMode(QLineEdit.Password)
        self.input_pass.setPlaceholderText("Ingrese su contraseña")
        form_layout.addWidget(label_user, 0, 0)
        form_layout.addWidget(self.input_user, 0, 1)
        form_layout.addWidget(label_pass, 1, 0)
        form_layout.addWidget(self.input_pass, 1, 1)
        card_layout.addLayout(form_layout)

        btn_login = QPushButton("Ingresar")
        btn_login.setObjectName("LoginButton")
        btn_login.setCursor(Qt.PointingHandCursor)
        btn_login.setDefault(True)
        card_layout.addWidget(btn_login)

        # Reloj en vivo
        self.lbl_time = QLabel("", self)
        self.lbl_time.setObjectName("LoginClock")
        self.lbl_time.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self.lbl_time)

        outer_layout.addWidget(card, alignment=Qt.AlignHCenter)
        outer_layout.addStretch()

        # timer para reloj
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._tick()

        btn_login.clicked.connect(self.check_login)
        self.user_data = None

    def _tick(self):
        self.lbl_time.setText(QDateTime.currentDateTime().toString("dd/MM/yyyy HH:mm:ss"))

    def check_login(self):
        username = self.input_user.text().strip(); password = self.input_pass.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Campos vacíos", "Por favor ingrese nombre de usuario y contraseña.")
            return
        user = self.labdb.authenticate_user(username, password)
        if user:
            self.user_data = user
            self.accept()
        else:
            QMessageBox.warning(self, "Credenciales inválidas", "Usuario o contraseña incorrectos. Inténtelo de nuevo.")


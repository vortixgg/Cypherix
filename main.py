import sys
import os
import json
import string
import random
import time
from pathlib import Path
import ctypes
from ctypes import wintypes
import shutil
from datetime import datetime
from pathlib import Path
# Cryptography imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# PyQt6 imports
import hashlib
import urllib.request

from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl, Qt, QSize, QTimer, QTime, QEvent
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QPushButton,
    QLabel,
    QTabWidget,
    QInputDialog,
    QFileDialog,
    QMessageBox,
    QLineEdit,
    QSlider,
    QProgressDialog,
    QTableWidget,
    QTableWidgetItem,
    QCheckBox
)
import threading
import secrets
# constants
VAULT_FILE = "vault.cypheria"
MAGIC = b"AESGCM1"

# streamproofing
WDA_EXCLUDEFROMCAPTURE = 0x00000011

# globals
vault = None
master_password = None
streamproof_enabled = False
def add_card_entry():
    global vault

    dialog = QDialog()
    dialog.setWindowTitle("Add Card")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(300, 280)

    layout = QVBoxLayout()

    layout.addWidget(QLabel("Card Nickname:"))
    nickname_input = QLineEdit()
    layout.addWidget(nickname_input)

    layout.addWidget(QLabel("Cardholder Name:"))
    cardholder_input = QLineEdit()
    layout.addWidget(cardholder_input)

    layout.addWidget(QLabel("Card Number:"))
    number_input = QLineEdit()
    number_input.setMaxLength(19)
    layout.addWidget(number_input)

    layout.addWidget(QLabel("Expiry (MM/YY):"))
    expiry_input = QLineEdit()
    expiry_input.setMaxLength(5)
    layout.addWidget(expiry_input)

    layout.addWidget(QLabel("CVV:"))
    cvv_input = QLineEdit()
    cvv_input.setMaxLength(4)
    layout.addWidget(cvv_input)

    save_btn = QPushButton("Save")
    layout.addWidget(save_btn)

    def detect_card_type(number):
        if number.startswith("4"): return "Visa"
        elif number.startswith("5"): return "Mastercard"
        elif number.startswith("34") or number.startswith("37"): return "Amex"
        else: return "Card"

    def save_card():
        nickname = nickname_input.text().strip()
        cardholder = cardholder_input.text().strip()
        number = number_input.text().strip().replace(" ", "")
        expiry = expiry_input.text().strip()
        cvv = cvv_input.text().strip()

        if not all([nickname, cardholder, number, expiry, cvv]):
            QMessageBox.warning(dialog, "Error", "All fields are required!")
            return

        card_type = detect_card_type(number)
        masked = "**** **** **** " + number[-4:]

        vault[nickname] = {
            "type": "card",
            "cardholder": cardholder,
            "number": number,
            "masked": masked,
            "expiry": expiry,
            "cvv": cvv,
            "card_type": card_type
        }

        try:
            save_vault()
            dialog.accept()
            QMessageBox.information(None, "Saved", f"{card_type} card '{nickname}' added!")
        except Exception as e:
            QMessageBox.critical(dialog, "Error", f"Failed to save: {str(e)}")
            vault.pop(nickname)

    save_btn.clicked.connect(save_card)
    dialog.setLayout(layout)
    apply_streamproof(dialog)
    dialog.exec()
def show_cards():
    global vault

    cards = {k: v for k, v in vault.items() if v.get("type") == "card"}

    if not cards:
        QMessageBox.information(None, "Cards", "No saved cards yet!")
        return

    dialog = QDialog()
    dialog.setWindowTitle("Saved Cards")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(400, 300)

    layout = QVBoxLayout()

    for nickname, data in cards.items():
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel(f"💳 {nickname}  ({data['masked']})"))

        view_btn = QPushButton()
        view_btn.setIcon(QIcon("images/eye.png"))
        view_btn.setFixedSize(25, 25)

        def make_view_func(name=nickname, d=data):
            def view_card():
                dlg = QDialog()
                dlg.setWindowTitle(name)
                dlg.setWindowIcon(QIcon("images/icon.ico"))
                dlg.setFixedSize(300, 200)

                dlg_layout = QVBoxLayout()
                dlg_layout.addWidget(QLabel(f"Type: {d['card_type']}"))
                dlg_layout.addWidget(QLabel(f"Cardholder: {d['cardholder']}"))
                dlg_layout.addWidget(QLabel(f"Number: {d['number']}"))
                dlg_layout.addWidget(QLabel(f"Expiry: {d['expiry']}"))

                cvv_field = QLineEdit()
                cvv_field.setText(d['cvv'])
                cvv_field.setEchoMode(QLineEdit.EchoMode.Normal)
                cvv_field.setReadOnly(True)
                dlg_layout.addWidget(QLabel("CVV:"))
                dlg_layout.addWidget(cvv_field)

                dlg.setLayout(dlg_layout)
                dlg.show()
                apply_streamproof(dlg)
                dlg.exec()
            return view_card

        view_btn.clicked.connect(make_view_func())
        h_layout.addWidget(view_btn)

        del_btn = QPushButton()
        del_btn.setIcon(QIcon("images/bin.png"))
        del_btn.setFixedSize(25, 25)

        def make_delete_func(name=nickname):
            def delete_card():
                confirm = QMessageBox.question(None, "Confirm Delete",
                                               f"Delete {name}?",
                                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if confirm == QMessageBox.StandardButton.Yes:
                    vault.pop(name)
                    save_vault()
                    show_cards()
                    dialog.close()
            return delete_card

        del_btn.clicked.connect(make_delete_func())
        h_layout.addWidget(del_btn)
        layout.addLayout(h_layout)

    dialog.setLayout(layout)
    dialog.show()
    apply_streamproof(dialog)
    dialog.exec()
    
    

def password_health(parent=None):
    from PyQt6.QtGui import QColor
    from PyQt6.QtWidgets import QAbstractItemView

    if not vault:
        QMessageBox.information(parent, "Password Health", "Your vault is empty!")
        return

    dialog = QDialog()
    dialog.setWindowTitle("Password Health")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(500, 400)

    layout = QVBoxLayout()

    table = QTableWidget()
    table.setColumnCount(3)
    table.setHorizontalHeaderLabels(["Entry", "User", "Health"])
    table.setColumnWidth(0, 150)
    table.setColumnWidth(1, 150)
    table.setColumnWidth(2, 150)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    table.horizontalHeader().setHighlightSections(False)
    table.verticalHeader().setVisible(False)
    table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    table.setStyleSheet("""
        QTableWidget {
            background: #111;
            border: 1px solid #333;
            border-radius: 6px;
            gridline-color: #222;
        }
        QHeaderView::section {
            background: #6a0dad;
            color: white;
            padding: 6px;
            border: none;
            font-weight: bold;
        }
        QTableWidget::item {
            padding: 4px;
        }
        QScrollBar:vertical {
            background: #1a1a1a;
            width: 10px;
            border-radius: 5px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6a0dad, stop:1 #8e2de2);
            border-radius: 5px;
            min-height: 30px;
        }
        QScrollBar::handle:vertical:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8e2de2, stop:1 #b44fff);
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
            background: none;
        }
        QScrollBar:horizontal {
            background: #1a1a1a;
            height: 10px;
            border-radius: 5px;
            margin: 0px;
        }
        QScrollBar::handle:horizontal {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #6a0dad, stop:1 #8e2de2);
            border-radius: 5px;
            min-width: 30px;
        }
        QScrollBar::handle:horizontal:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #8e2de2, stop:1 #b44fff);
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
        }
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
            background: none;
        }
    """)

    layout.addWidget(table)
    dialog.setLayout(layout)

    def check_health(password: str):
        score = 0
        if len(password) >= 12: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in string.punctuation for c in password): score += 1

        if score >= 4: return "🟢 Strong", QColor("#00FF00")
        elif score >= 3: return "🟡 Medium", QColor("#FFD700")
        else: return "🔴 Weak", QColor("#FF4444")

    def run_checks():
        entries = {k: v for k, v in vault.items() if v.get("type") != "card"}
        table.setRowCount(len(entries))
        for row, (entry_name, entry_data) in enumerate(entries.items()):
            password = entry_data.get("password", "")
            label, color = check_health(password)

            table.setItem(row, 0, QTableWidgetItem(entry_name))
            table.setItem(row, 1, QTableWidgetItem(entry_data.get("username", "")))

            health_item = QTableWidgetItem(label)
            health_item.setForeground(color)
            table.setItem(row, 2, health_item)

        table.resizeColumnToContents(2)

    apply_streamproof(dialog)
    threading.Thread(target=run_checks, daemon=True).start()
    dialog.exec()
    
def breach_checker(parent=None):
    import hashlib
    import urllib.request
    from PyQt6.QtGui import QColor

    if not vault:
        QMessageBox.information(parent, "Breach Checker", "Your vault is empty!")
        return

    dialog = QDialog()
    dialog.setWindowTitle("Breach Checker")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(500, 400)

    layout = QVBoxLayout()

    table = QTableWidget()
    table.setColumnCount(3)
    table.setHorizontalHeaderLabels(["Entry", "User", "Password Status"])
    table.setColumnWidth(0, 150)
    table.setColumnWidth(1, 150)
    table.setColumnWidth(2, 150)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setStyleSheet("""
        QTableWidget {
            background: #111;
            border: 1px solid #333;
            border-radius: 6px;
            gridline-color: #222;
        }
        QHeaderView::section {
            background: #6a0dad;
            color: white;
            padding: 6px;
            border: none;
            font-weight: bold;
        }
        QTableWidget::item {
            padding: 4px;
        }
        QScrollBar:vertical {
            background: #1a1a1a;
            width: 10px;
            border-radius: 5px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6a0dad, stop:1 #8e2de2);
            border-radius: 5px;
            min-height: 30px;
        }
        QScrollBar::handle:vertical:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8e2de2, stop:1 #b44fff);
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
            background: none;
        }
        QScrollBar:horizontal {
            background: #1a1a1a;
            height: 10px;
            border-radius: 5px;
            margin: 0px;
        }
        QScrollBar::handle:horizontal {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #6a0dad, stop:1 #8e2de2);
            border-radius: 5px;
            min-width: 30px;
        }
        QScrollBar::handle:horizontal:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #8e2de2, stop:1 #b44fff);
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
        }
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
            background: none;
        }
    """)
    
    from PyQt6.QtWidgets import QAbstractItemView

    table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    table.horizontalHeader().setHighlightSections(False)
    table.verticalHeader().setVisible(False)
    table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    layout.addWidget(table)
    dialog.setLayout(layout)

    def check_password_pwned(password: str) -> int:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            req = urllib.request.Request(url, headers={"User-Agent": "CypheriaPasswordManager"})
            with urllib.request.urlopen(req, timeout=5) as response:
                hashes = response.read().decode()
            for line in hashes.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return int(count)
            return 0
        except Exception:
            return -1

    def run_checks():
        entries = {k: v for k, v in vault.items() if v.get("type") != "card"}
        table.setRowCount(len(entries))
        for row, (entry_name, entry_data) in enumerate(entries.items()):
            password = entry_data.get("password", "")
            count = check_password_pwned(password)

            table.setItem(row, 0, QTableWidgetItem(entry_name))
            table.setItem(row, 1, QTableWidgetItem(entry_data.get("username", "")))

            if count == -1:
                status_item = QTableWidgetItem("⚠ Network Error")
                status_item.setForeground(QColor("#FFA500"))
            elif count == 0:
                status_item = QTableWidgetItem("✔ Safe")
                status_item.setForeground(QColor("#00FF00"))
            else:
                status_item = QTableWidgetItem(f"✘ Breached ({count:,} times)")
                status_item.setForeground(QColor("#FF4444"))

            table.setItem(row, 2, status_item)
            QApplication.processEvents()

    apply_streamproof(dialog)
    threading.Thread(target=run_checks, daemon=True).start()
    dialog.exec()
def streamproof(hwnd, affinity):
    try:
        user32 = ctypes.windll.user32
        user32.SetWindowDisplayAffinity(wintypes.HWND(hwnd), wintypes.DWORD(affinity))
    except Exception as e:
        print(f"Could not set display affinity: {e}")

def apply_streamproof(widget):
    global streamproof_enabled
    if streamproof_enabled and sys.platform == 'win32':
        hwnd = widget.winId().__int__()
        streamproof(hwnd, WDA_EXCLUDEFROMCAPTURE)

def secure_shredder(parent=None):
    choice, ok = QFileDialog.getOpenFileName(parent, "Select File or Folder to Shred", "", "All Files (*)")
    if not choice:
        return

    if os.path.isfile(choice):
        paths = [choice]
    else:
        paths = []
        for root, dirs, files in os.walk(choice):
            for f in files:
                paths.append(os.path.join(root, f))

    try:
        for path in paths:
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(path)

        if os.path.isdir(choice):
            for root, dirs, _ in os.walk(choice, topdown=False):
                for d in dirs:
                    os.rmdir(os.path.join(root, d))
            os.rmdir(choice)

        QMessageBox.information(parent, "Shredder", "Selected files/folders have been securely shredded.")
    except Exception as e:
        QMessageBox.critical(parent, "Shredder Error", f"An error occurred:\n{e}")

def file_encryptor(parent=None):
    choice, ok = QInputDialog.getItem(parent or None, "File Encryptor", "Choose action:", ["Encrypt", "Decrypt"], 0, False)
    if not ok or choice not in ("Encrypt", "Decrypt"):
        return

    password, ok = QInputDialog.getText(parent or None, choice, f"Enter password for {choice.lower()}:", QLineEdit.EchoMode.Password)
    if not ok or not password:
        return

    file_path, _ = QFileDialog.getOpenFileName(parent or None, f"Select file to {choice.lower()}")
    if not file_path:
        return

    try:
        if choice == "Encrypt":
            with open(file_path, "rb") as f:
                data = f.read()
            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = derive_key(password, salt)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            tmp_path = file_path + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(MAGIC + salt + nonce + ciphertext)
            os.replace(tmp_path, file_path)
            QMessageBox.information(None, "Success", f"File encrypted successfully:\n{file_path}")
        else:
            with open(file_path, "rb") as f:
                raw = f.read()
            if not raw.startswith(MAGIC):
                raise ValueError("File is not encrypted or corrupted")
            salt = raw[7:23]
            nonce = raw[23:35]
            ciphertext = raw[35:]
            key = derive_key(password, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            tmp_path = file_path + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(plaintext)
            os.replace(tmp_path, file_path)
            QMessageBox.information(None, "Success", f"File decrypted successfully:\n{file_path}")
    except Exception as e:
        QMessageBox.critical(None, "Error", f"An error occurred:\n{e}")

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode())

def save_vault():
    global vault, master_password, VAULT_FILE, MAGIC
    if vault is None or master_password is None:
        QMessageBox.critical(None, "Error", "Vault not loaded. Cannot save.")
        return

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    data = json.dumps(vault).encode()
    ciphertext = aesgcm.encrypt(nonce, data, None)

    with open(VAULT_FILE, "wb") as f:
        f.write(MAGIC + salt + nonce + ciphertext)

def delete_entry(entry_name):
    global vault

    if vault is None:
        QMessageBox.critical(None, "Error", "Vault not loaded. Cannot delete.")
        return

    if entry_name in vault:
        confirm = QMessageBox.question(
            None, "Confirm Delete",
            f"Delete {entry_name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            del vault[entry_name]
            save_vault()

def show_saved():
    global vault
    
    password_entries = {k: v for k, v in vault.items() if v.get("type") != "card"}
    
    if not password_entries:
        QMessageBox.information(None, "Vault Empty", "No saved passwords yet!")
        return

    loading = QProgressDialog("Decrypting...", None, 0, 0)
    loading.setWindowTitle("Please wait")
    loading.setWindowModality(Qt.WindowModality.ApplicationModal)
    loading.setCancelButton(None)
    loading.setMinimumDuration(0)
    loading.show()
    QApplication.processEvents()
    time.sleep(0.5)
    loading.close()

    dialog = QDialog()
    dialog.setWindowTitle("Saved Passwords")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(400, 300)
    
    layout = QVBoxLayout()
    for entry_name, entry_data in password_entries.items():
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel(entry_name))

        view_btn = QPushButton()
        view_btn.setIcon(QIcon("images/eye.png"))
        view_btn.setFixedSize(25, 25)

        def make_view_func(name=entry_name, data=entry_data):
            def view_entry():
                dlg = QDialog()
                dlg.setWindowTitle(name)
                dlg.setWindowIcon(QIcon("images/icon.ico"))
                dlg.setFixedSize(300, 150)
                
                dlg_layout = QVBoxLayout()
                dlg_layout.addWidget(QLabel(f"Username: {data['username']}"))
                password_field = QLineEdit()
                password_field.setText(data['password'])
                password_field.setEchoMode(QLineEdit.EchoMode.Normal)
                password_field.setReadOnly(True)
                dlg_layout.addWidget(QLabel("Password:"))
                dlg_layout.addWidget(password_field)
                dlg.setLayout(dlg_layout)
                
                dlg.show()
                apply_streamproof(dlg)
                dlg.exec()
            return view_entry

        view_btn.clicked.connect(make_view_func())
        h_layout.addWidget(view_btn)

        del_btn = QPushButton()
        del_btn.setIcon(QIcon("images/bin.png"))
        del_btn.setFixedSize(25, 25)

        def make_delete_func(name=entry_name):
            def delete_entry():
                confirm = QMessageBox.question(None, "Confirm Delete",
                                               f"Delete {name}?", 
                                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if confirm == QMessageBox.StandardButton.Yes:
                    vault.pop(name)
                    save_vault()
                    show_saved()
                    dialog.close()
            return delete_entry

        del_btn.clicked.connect(make_delete_func())
        h_layout.addWidget(del_btn)
        layout.addLayout(h_layout)

    dialog.setLayout(layout)
    dialog.show()
    apply_streamproof(dialog)
    dialog.exec()

def add_password_entry():
    global vault

    dialog = QDialog()
    dialog.setWindowTitle("Add Password Entry")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(300, 200)

    layout = QVBoxLayout()
    layout.addWidget(QLabel("Entry Name:"))
    name_input = QLineEdit()
    layout.addWidget(name_input)

    layout.addWidget(QLabel("Username:"))
    username_input = QLineEdit()
    layout.addWidget(username_input)

    layout.addWidget(QLabel("Password:"))
    password_input = QLineEdit()
    layout.addWidget(password_input)

    save_btn = QPushButton("Save")
    layout.addWidget(save_btn)

    def save_entry():
        name = name_input.text().strip()
        username = username_input.text().strip()
        password = password_input.text().strip()

        if not name or not username or not password:
            QMessageBox.warning(dialog, "Error", "All fields are required!")
            return

        vault[name] = {"username": username, "password": password}

        try:
            save_vault()
            dialog.accept()
            QMessageBox.information(None, "Saved", f"Entry '{name}' added successfully!")
        except Exception as e:
            QMessageBox.critical(dialog, "Error", f"Failed to save vault: {str(e)}")
            vault.pop(name)
            return

    save_btn.clicked.connect(save_entry)
    dialog.setLayout(layout)
    apply_streamproof(dialog)
    dialog.exec()

def generate_pass():
    dialog = QDialog()
    dialog.setWindowTitle("Generate Passwords")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(400, 200)

    layout = QVBoxLayout()

    password_field = QLineEdit()
    password_field.setReadOnly(True)
    layout.addWidget(password_field)

    generate_btn = QPushButton("Generate")
    layout.addWidget(generate_btn)

    label = QLabel("Password length: 16")
    layout.addWidget(label)

    slider = QSlider(Qt.Orientation.Horizontal)
    slider.setMinimum(8)
    slider.setMaximum(64)
    slider.setValue(16)
    slider.setStyleSheet("""
    QSlider::groove:horizontal {
        border: 1px solid #222;
        height: 8px;
        background: #1a1a1a;
        border-radius: 4px;
    }
    QSlider::handle:horizontal {
        background: #6a0dad;
        border: 1px solid #8e2de2;
        width: 18px; height: 18px; margin: -5px 0; border-radius: 9px; 
    }
    QSlider::sub-page:horizontal { background: #6a0dad; border-radius:4px; }
    QSlider::add-page:horizontal { background: #333; border-radius:4px; }
    """)
    layout.addWidget(slider)

    copy_btn = QPushButton("Copy")
    layout.addWidget(copy_btn)

    def generate_password():
        length = slider.value()
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(chars) for _ in range(length))
        password_field.setText(password)

    def copy_password():
        QApplication.clipboard().setText(password_field.text())

    slider.valueChanged.connect(lambda val: label.setText(f"Password length: {val}"))
    generate_btn.clicked.connect(generate_password)
    copy_btn.clicked.connect(copy_password)

    dialog.setLayout(layout)
    dialog.show()
    apply_streamproof(dialog)
    dialog.exec()



#makes new account / vault file
def create_account(file_path):
    global vault, master_password
    
    dialog = QDialog()
    dialog.setWindowTitle("Create Account")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(300, 180)
    layout = QVBoxLayout()
    layout.addWidget(QLabel("Enter Master Password:"))
    password_input = QLineEdit()
    password_input.setEchoMode(QLineEdit.EchoMode.Password)
    layout.addWidget(password_input)
    save_btn = QPushButton("Save")
    layout.addWidget(save_btn)
    dialog.setLayout(layout)

    def save_credentials():
        global vault, master_password
        password = password_input.text().strip()
        if not password:
            QMessageBox.warning(dialog, "Error", "Password cannot be empty!")
            return
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        data = json.dumps({}).encode()
        ciphertext = aesgcm.encrypt(nonce, data, None)
        with open(file_path, "wb") as f:
            f.write(b"AESGCM1" + salt + nonce + ciphertext)
        
        # Initialize vault and master_password after account creation
        vault = {}
        master_password = password
        
        dialog.accept()
    save_btn.clicked.connect(save_credentials)
    dialog.exec()


def login(file_path):
    with open(file_path, "rb") as f:
        raw = f.read()
    if not raw.startswith(b"AESGCM1"):
        QMessageBox.critical(None, "Error", "Vault corrupted")
        return None, None
    salt = raw[7:23]
    nonce = raw[23:35]
    ciphertext = raw[35:]
    dialog = QDialog()
    dialog.setWindowTitle("Login")
    dialog.setWindowIcon(QIcon("images/icon.ico"))
    dialog.setFixedSize(300, 180)
    layout = QVBoxLayout()
    layout.addWidget(QLabel("Enter Password:"))
    password_input = QLineEdit()
    password_input.setEchoMode(QLineEdit.EchoMode.Password)
    layout.addWidget(password_input)
    login_btn = QPushButton("Login")
    layout.addWidget(login_btn)
    dialog.setLayout(layout)
    result = {"vault": None, "password": None}

    def try_login():
        password = password_input.text().strip()
        if not password:
            QMessageBox.warning(dialog, "Error", "Password cannot be empty!")
            return
        try:
            key = derive_key(password, salt)
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            vault = json.loads(decrypted)
            result["vault"] = vault
            result["password"] = password
            dialog.accept()
        except Exception:
            QMessageBox.critical(dialog, "Error", "Incorrect password!")
    login_btn.clicked.connect(try_login)
    dialog.exec()
    return result["vault"], result["password"]


def apply_dark_purple_theme(app):
    #used ai cuh
    app.setStyleSheet("""
        QWidget { 
            background-color:#0f0f0f; 
            color:#e6e6e6; 
            font-family:Segoe UI; 
        }
        QTabWidget::pane { 
            border:1px solid #222; 
            background:#121212; 
        }
        QTabBar::tab { 
            background:#1b1b1b; 
            padding:8px; 
            margin:2px; 
            border-radius:6px; 
        }
        QTabBar::tab:selected { 
            background:#6a0dad; 
            color:white; 
        }
        QPushButton { 
            background:#6a0dad; 
            border:none; 
            padding:8px; 
            border-radius:8px; 
            color:white; 
        }
        QPushButton:hover { 
            background:#8e2de2; 
        }
        QPushButton:pressed { 
            background:#4b0082; 
        }
        QListWidget { 
            background:#111; 
            border:1px solid #222; 
            border-radius:6px; 
        }
        QListWidget::item:selected { 
            background:#6a0dad; 
            color:white; 
        }
        QListWidget::item:focus { 
            outline: none; 
        }
        QComboBox, QLineEdit { 
            background:#1a1a1a; 
            border:1px solid #333; 
            padding:5px; 
            border-radius:6px; 
        }
        QLabel { 
            color:white; 
        }
        QCheckBox {
            color: #e6e6e6;
            spacing: 8px;
        }
        QCheckBox::indicator {
            width: 20px;
            height: 20px;
            border-radius: 10px;
            border: 2px solid #6a0dad;
            background: #1a1a1a;
        }
        QCheckBox::indicator:checked {
            background: #6a0dad;
            border: 2px solid #8e2de2;
        }
        QCheckBox::indicator:hover {
            border: 2px solid #8e2de2;
        }
    """)

def create_vault_tab():
    
    tab = QWidget()
    layout = QVBoxLayout()

    top_layout = QHBoxLayout()

    create_btn = QPushButton("Add Password")
    create_btn.setIcon(QIcon("images/create.png"))
    create_btn.setFixedSize(150, 40)
    create_btn.setIconSize(QSize(30, 30))
    create_btn.clicked.connect(add_password_entry)
    top_layout.addWidget(create_btn)

    add_btn = QPushButton()
    add_btn.setIcon(QIcon("images/add.png"))
    add_btn.setFixedSize(40, 40)
    add_btn.setIconSize(QSize(35, 35))
    add_btn.clicked.connect(show_saved)
    top_layout.addWidget(add_btn)

    top_layout.addStretch()

    clock_label = QLabel()
    clock_label.setStyleSheet("font-size: 16px; color: #6a0dad; font-weight: bold;")
    clock_label.setAlignment(Qt.AlignmentFlag.AlignRight)
    top_layout.addWidget(clock_label)

    icon_label = QLabel()
    icon_pixmap = QPixmap("images/icon.ico")
    icon_label.setPixmap(icon_pixmap.scaled(40, 40, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
    top_layout.addWidget(icon_label)

    layout.addLayout(top_layout)

    row2_layout = QHBoxLayout()
    row2_layout.setSpacing(6)

    add_card_btn = QPushButton("Add Card")
    add_card_btn.setIcon(QIcon("images/addcard.png"))
    add_card_btn.setFixedSize(150, 40)
    add_card_btn.setIconSize(QSize(30, 30))
    add_card_btn.clicked.connect(add_card_entry)
    row2_layout.addWidget(add_card_btn)

    view_cards_btn = QPushButton()
    view_cards_btn.setIcon(QIcon("images/card.png"))
    view_cards_btn.setFixedSize(40, 40)
    view_cards_btn.setIconSize(QSize(35, 35))
    view_cards_btn.clicked.connect(show_cards)
    row2_layout.addWidget(view_cards_btn)

    row2_layout.addStretch()
    layout.addLayout(row2_layout)

    layout.addStretch()

    def update_clock_thread():
        while True:
            current_time = QTime.currentTime().toString("hh:mm:ss")
            clock_label.setText(current_time)
            time.sleep(1)

    clock_thread = threading.Thread(target=update_clock_thread, daemon=True)
    clock_thread.start()

    tab.setLayout(layout)
    return tab


def create_password_tab():  # password tab 
    global streamproof_enabled, vault
    
    tab = QWidget()
    main_layout = QVBoxLayout()
    main_layout.setContentsMargins(0, 0, 0, 0)
    main_layout.setSpacing(5)

    top_layout = QHBoxLayout()
    top_layout.setContentsMargins(0, 0, 0, 0)
    top_layout.setSpacing(10)
    top_layout.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

    generate_btn = QPushButton("Generate Passwords")
    generate_btn.setIcon(QIcon("images/generate.png"))
    generate_btn.setFixedSize(150, 40)
    generate_btn.setIconSize(QSize(30, 30))
    generate_btn.clicked.connect(generate_pass)
    top_layout.addWidget(generate_btn)

    streamproof_checkbox = QCheckBox("Streamproof")
    def toggle_streamproof(state):
        global streamproof_enabled
        streamproof_enabled = (state == Qt.CheckState.Checked.value)
    streamproof_checkbox.stateChanged.connect(toggle_streamproof)
    top_layout.addWidget(streamproof_checkbox)

    main_layout.addLayout(top_layout)

    encrypt_btn = QPushButton("Encrypt/Decrypt Files")
    encrypt_btn.setIcon(QIcon("images/encrypt.png"))
    encrypt_btn.setFixedSize(150, 40)
    encrypt_btn.setIconSize(QSize(30, 30))
    encrypt_btn.clicked.connect(lambda: file_encryptor(tab))
    main_layout.addWidget(encrypt_btn, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

    shred_btn = QPushButton("Secure File Shredder")
    shred_btn.setIcon(QIcon("images/shred.png"))
    shred_btn.setFixedSize(150, 40)
    shred_btn.setIconSize(QSize(30, 30))
    shred_btn.clicked.connect(lambda: secure_shredder(tab))
    main_layout.addWidget(shred_btn, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    
    breach_btn = QPushButton("Pass Breach Check")
    breach_btn.setIcon(QIcon("images/breach.png"))
    breach_btn.setFixedSize(150, 40)
    breach_btn.setIconSize(QSize(30, 30))
    breach_btn.clicked.connect(lambda: breach_checker(tab))
    main_layout.addWidget(breach_btn, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    
    health_btn = QPushButton("Pass Health Check")
    health_btn.setIcon(QIcon("images/health.png"))
    health_btn.setFixedSize(150, 40)
    health_btn.setIconSize(QSize(30, 30))
    health_btn.clicked.connect(lambda: password_health(tab))
    main_layout.addWidget(health_btn, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

    main_layout.addStretch()
    
    tab.setLayout(main_layout)
    return tab






def main():
    #main 
    global vault
    global master_password
    
    app = QApplication(sys.argv)
    APP_ICON = QIcon("images/icon.ico")
    vault_path = Path(VAULT_FILE)
    apply_dark_purple_theme(app)

    #if vaylt file exists --------> add it to a backups folder incase program crash or corruption (does it every startup)
    if vault_path.exists():
        backups_dir = vault_path.parent / "backups"
        backups_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backups_dir / f"{vault_path.stem}_{timestamp}{vault_path.suffix}"

        shutil.copy2(vault_path, backup_file)
        print(f"Backup created at {backup_file}")

    #account logic 
    if not vault_path.exists():
        create_account(str(vault_path)) #calls create account for new vault file 
    else:
        vault, master_password = login(str(vault_path))
        if vault is None:
            sys.exit(1)

    window = QWidget()
    window.setWindowTitle("Cypheria Password manager")
    window.setGeometry(500, 500, 500, 400)
    window.setWindowIcon(APP_ICON)

    tabs = QTabWidget()
    tabs.addTab(create_vault_tab(), QIcon("images/vault.png"), "Saved Passwords")
    tabs.addTab(create_password_tab(), QIcon("images/password.png"), "Dashboard")

    layout = QVBoxLayout()
    layout.addWidget(tabs)
    window.setLayout(layout)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main() #call the main
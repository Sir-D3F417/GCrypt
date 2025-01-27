# CODED BY D3F417
# GUARDIRAN SECURITY TEAM
# https://github.com/Sir-D3F417
# https://d3f417.info
# https://t.me/hex_aa
# https://guardiran.org
import os
import sys
import json
import hashlib
import base64
import zlib
import lzma
import bz2
import time
import random
import webbrowser
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7  
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QMessageBox,
    QDialog, QProgressBar, QComboBox, QSpinBox, QTextEdit,
    QGroupBox, QRadioButton, QListWidget, QTableWidget,
    QMenuBar, QMenu, QStatusBar, QCheckBox, QTableWidgetItem,  
    QHeaderView, QProgressDialog, QTabWidget  
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import (
    QFont, QPalette, QColor, QIcon, 
    QDragEnterEvent, QDropEvent, QDragMoveEvent  
)
import logging
import tempfile
import psutil
import requests
import secrets
import string

ASCII_LOGO = """
═══════ GUARDIRAN SECURITY TOOLS ═══════
"""

STYLE_SHEET = """
/* Main Window */
QMainWindow {
    background-color: #0a0b14;
}

/* Card Containers */
.card-container {
    background-color: #12152d;
    border: 2px solid #00ff9d;
    border-radius: 10px;
    padding: 20px;
    margin: 10px;
}

/* Logo Container */
.logo-container {
    background-color: #12152d;
    border: 2px solid #00ff9d;
    border-radius: 10px;
    padding: 20px;
    margin: 10px 10px 20px 10px;
}

/* Section Headers */
.section-header {
    color: #00ff9d;
    font-size: 16px;
    font-weight: bold;
    text-transform: uppercase;
    padding: 5px 0;
}

/* Input Fields */
QLineEdit {
    background-color: #0a0b14;
    color: #ffffff;
    border: 2px solid #00ff9d;
    border-radius: 5px;
    padding: 8px;
    font-size: 13px;
}

QLineEdit:focus {
    border-color: #00ff9d;
    background-color: #12152d;
}

/* Buttons */
QPushButton {
    background-color: transparent;
    color: #00ff9d;
    border: 2px solid #00ff9d;
    border-radius: 5px;
    padding: 8px 15px;
    font-size: 13px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #00ff9d;
    color: #0a0b14;
}

QPushButton:pressed {
    background-color: #00cc7d;
}

/* Combo Boxes */
QComboBox {
    background-color: #0a0b14;
    color: #ffffff;
    border: 2px solid #00ff9d;
    border-radius: 5px;
    padding: 8px;
    font-size: 13px;
}

QComboBox:hover {
    border-color: #00ff9d;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: url(assets/dropdown.png);
    width: 12px;
    height: 12px;
}

/* Checkboxes */
QCheckBox {
    color: #ffffff;
    spacing: 5px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid #00ff9d;
    border-radius: 3px;
    background-color: #0a0b14;
}

QCheckBox::indicator:checked {
    background-color: #00ff9d;
    image: url(assets/checkmark.png);
}

/* Progress Bar */
QProgressBar {
    border: 2px solid #00ff9d;
    border-radius: 5px;
    text-align: center;
    color: #ffffff;
}

QProgressBar::chunk {
    background-color: #00ff9d;
}

/* Labels */
QLabel {
    color: #ffffff;
}

/* Title Bar */
#title-bar {
    background-color: #12152d;
    border-bottom: 2px solid #00ff9d;
}

.title-text {
    color: #00ff9d;
    font-size: 14px;
    font-weight: bold;
}

.subtitle-text {
    color: #00ff9d;
    font-family: 'Consolas', monospace;
    font-size: 12px;
}
"""

class EncryptionSettings:
    ALGORITHMS = {
        'AES-256-GCM': {'key_size': 32, 'mode': modes.GCM},
        'AES-256-CBC': {'key_size': 32, 'mode': modes.CBC},
        'AES-256-CFB': {'key_size': 32, 'mode': modes.CFB},
        'AES-256-OFB': {'key_size': 32, 'mode': modes.OFB},
        'ChaCha20-Poly1305': {'key_size': 32, 'mode': None},
        'Camellia-256': {'key_size': 32, 'mode': modes.CBC}
    }
    
    COMPRESSION_METHODS = {
        'None': None,
        'ZLIB': {'module': zlib, 'compress': lambda d, l: zlib.compress(d, level=l),
                 'decompress': lambda d: zlib.decompress(d)},
        'LZMA': {'module': lzma, 'compress': lambda d, l: lzma.compress(d, preset=l),
                 'decompress': lambda d: lzma.decompress(d)},
        'BZ2': {'module': bz2, 'compress': lambda d, l: bz2.compress(d, compresslevel=l),
                'decompress': lambda d: bz2.decompress(d)}
    }

class SecureFileHandler:
    def __init__(self):
        self.cipher = None
        self.key = None
        
    def generate_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_file(self, input_file, output_file, password, algorithm='AES-256-GCM', 
                    compression_method='ZLIB', compression_level=6):
        try:
            
            key, salt = self.generate_key(password)
            
            
            with open(input_file, 'rb') as f:
                data = f.read()
            
            
            if compression_method != 'None':
                if compression_method == 'ZLIB':
                    data = zlib.compress(data, compression_level)
                elif compression_method == 'LZMA':
                    data = lzma.compress(data, preset=compression_level)
                elif compression_method == 'BZ2':
                    data = bz2.compress(data, compresslevel=compression_level)
            
            
            nonce = os.urandom(12)
            
            
            cipher = Cipher(
                algorithms.AES(base64.b64decode(key)),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            
            metadata = {
                'algorithm': algorithm,
                'compression': compression_method,
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'tag': base64.b64encode(encryptor.tag).decode('utf-8')
            }
            
            
            with open(output_file, 'wb') as f:
                f.write(json.dumps(metadata).encode() + b'\n')
                f.write(ciphertext)
            
            return True, "File encrypted successfully"
            
        except Exception as e:
            return False, f"Encryption failed: {str(e)}"

    def decrypt_file(self, input_file, output_file, password):
        try:
            
            with open(input_file, 'rb') as f:
                
                metadata_line = b''
                while True:
                    byte = f.read(1)
                    if byte == b'\n':
                        break
                    metadata_line += byte
                
                try:
                    metadata = json.loads(metadata_line.decode('utf-8'))
                except json.JSONDecodeError:
                    return False, "Invalid file format or corrupted metadata"
                
                
                ciphertext = f.read()
            
            
            try:
                salt = base64.b64decode(metadata['salt'])
                nonce = base64.b64decode(metadata['nonce'])
                tag = base64.b64decode(metadata['tag'])
            except KeyError:
                return False, "Missing required metadata fields"
            except Exception:
                return False, "Invalid metadata format"
            
            
            key, _ = self.generate_key(password, salt)
            
            try:
                
                cipher = Cipher(
                    algorithms.AES(base64.b64decode(key)),
                    modes.GCM(nonce, tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                
                data = decryptor.update(ciphertext) + decryptor.finalize()
                
                
                if metadata.get('compression', 'None') != 'None':
                    try:
                        if metadata['compression'] == 'ZLIB':
                            data = zlib.decompress(data)
                        elif metadata['compression'] == 'LZMA':
                            data = lzma.decompress(data)
                        elif metadata['compression'] == 'BZ2':
                            data = bz2.decompress(data)
                    except Exception as e:
                        return False, f"Decompression failed: {str(e)}"
                
                
                with open(output_file, 'wb') as f:
                    f.write(data)
                
                return True, "File decrypted successfully"
                
            except Exception as e:
                return False, f"Decryption failed: {str(e)}"
                
        except Exception as e:
            return False, f"File reading failed: {str(e)}"

class CryptoWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)
    
    def __init__(self, mode, input_file, output_file, password, algorithm, use_compression=False, compression_method=None):
        super().__init__()
        self.mode = mode
        self.input_file = input_file
        self.output_file = output_file
        self.password = password
        self.algorithm = algorithm
        self.use_compression = use_compression
        self.compression_method = compression_method
    
    def run(self):
        try:
            
            with open(self.input_file, 'rb') as f:
                data = f.read()
            
            # Update progress
            self.progress.emit(20)
            
            # Compress if needed
            if self.use_compression and self.mode == 'encrypt':
                if self.compression_method == 'ZLIB':
                    data = zlib.compress(data)
                elif self.compression_method == 'LZMA':
                    data = lzma.compress(data)
                elif self.compression_method == 'BZIP2':
                    data = bz2.compress(data)
            
            # Update progress
            self.progress.emit(40)
            
            # Process data based on mode
            if self.mode == 'encrypt':
                # Generate salt
                salt = os.urandom(16)
                
                # Derive key
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(self.password.encode())
                
                # Encrypt
                cipher = Fernet(base64.urlsafe_b64encode(key))
                encrypted_data = cipher.encrypt(data)
                
                # Combine salt and encrypted data
                final_data = salt + encrypted_data
            else:
                # Extract salt
                salt = data[:16]
                encrypted_data = data[16:]
                
                # Derive key
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(self.password.encode())
                
                # Decrypt
                cipher = Fernet(base64.urlsafe_b64encode(key))
                final_data = cipher.decrypt(encrypted_data)
                
                # Decompress if needed
                if self.use_compression:
                    if self.compression_method == 'ZLIB':
                        final_data = zlib.decompress(final_data)
                    elif self.compression_method == 'LZMA':
                        final_data = lzma.decompress(final_data)
                    elif self.compression_method == 'BZIP2':
                        final_data = bz2.decompress(final_data)
            
            # Update progress
            self.progress.emit(80)
            
            # Write output file
            with open(self.output_file, 'wb') as f:
                f.write(final_data)
            
            # Complete
            self.progress.emit(100)
            self.finished.emit(True, "File processed successfully!")
            
        except Exception as e:
            self.finished.emit(False, str(e))

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About GCrypt")
        self.setMinimumSize(600, 400)
        self.setup_ui()
        
        # Apply cyberpunk theme
        self.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
            }
            QLabel[class="title-label"] {
                color: #00ff9d;
                font-size: 24px;
                font-weight: bold;
            }
            QLabel[class="section-label"] {
                color: #00ff9d;
                font-size: 16px;
                font-weight: bold;
                padding-top: 10px;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QTextEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
            }
        """)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        # Title and Version
        title = QLabel("GCrypt")
        title.setProperty("class", "title-label")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        version = QLabel("Version 1.0.0")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)

        # Description
        desc = QTextEdit()
        desc.setReadOnly(True)
        desc.setMinimumHeight(150)  # Increased height
        desc.setHtml("""
            <p style='color: #ffffff; margin: 10px;'>
            GCrypt is a state-of-the-art file encryption tool developed by GuardIran Security Team. 
            It implements industry-standard encryption algorithms and compression methods to ensure 
            the highest level of security for your files.
            </p>
            
            <p style='color: #ffffff; margin: 10px;'>
            This tool is part of the GuardIran Security Tools suite, designed to provide robust 
            security solutions for both personal and professional use.
            </p>
        """)
        layout.addWidget(desc)

        # Features
        features_label = QLabel("Key Features")
        features_label.setProperty("class", "section-label")
        layout.addWidget(features_label)

        features = QLabel("""
• Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305)
• Various compression methods (ZLIB, LZMA, BZ2)
• File integrity verification
• Password generator
• Hash checker
• File analyzer
• Secure file deletion
• Batch processing support
• Drag and drop support
• Command-line interface
        """)
        features.setWordWrap(True)  # Enable word wrap
        layout.addWidget(features)

        # Links section
        links_label = QLabel("Important Links")
        links_label.setProperty("class", "section-label")
        layout.addWidget(links_label)

        # Use horizontal layout for links
        links_layout = QHBoxLayout()
        
        # Left column
        left_links = QVBoxLayout()
        website_link = QLabel("<a href='https://guardiran.org' style='color: #00ff9d;'>Official Website</a>")
        website_link.setOpenExternalLinks(True)
        docs_link = QLabel("<a href='https://t.me/d3f417ir' style='color: #00ff9d;'>Telegram Channel</a>")
        docs_link.setOpenExternalLinks(True)
        left_links.addWidget(website_link)
        left_links.addWidget(docs_link)
        
        # Right column
        right_links = QVBoxLayout()
        github_link = QLabel("<a href='https://github.com/Sir-D3F417/GCrypt' style='color: #00ff9d;'>GitHub Repository</a>")
        github_link.setOpenExternalLinks(True)
        issues_link = QLabel("<a href='https://github.com/Sir-D3F417/GCrypt/issues' style='color: #00ff9d;'>Report Issues</a>")
        issues_link.setOpenExternalLinks(True)
        right_links.addWidget(github_link)
        right_links.addWidget(issues_link)
        
        links_layout.addLayout(left_links)
        links_layout.addLayout(right_links)
        layout.addLayout(links_layout)

        # Contact Information
        contact_label = QLabel("Contact Information")
        contact_label.setProperty("class", "section-label")
        layout.addWidget(contact_label)

        contact_info = QLabel("""
Email: info@d3f417.ir
Telegram: @hex_aa
Instagram: @theguardiran
        """)
        layout.addWidget(contact_info)

        # License
        license_label = QLabel("License")
        license_label.setProperty("class", "section-label")
        layout.addWidget(license_label)

        license_text = QLabel("This software is released under the GNU General Public License v3.0")
        license_text.setWordWrap(True)
        layout.addWidget(license_text)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # Set fixed width for the dialog
        self.setFixedWidth(600)

    def open_link(self, url):
        webbrowser.open(url)

class PasswordGenerator(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Generator")
        self.setMinimumSize(400, 350)  # Adjusted size
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)  # Increased spacing
        layout.setContentsMargins(20, 20, 20, 20)  # Added margins
        
        # Generated Password Label
        password_label = QLabel("Generated Password:")
        password_label.setStyleSheet("color: #ffffff; font-size: 13px;")
        layout.addWidget(password_label)
        
        # Password display
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setMinimumHeight(35)  # Increased height
        layout.addWidget(self.password_display)
        
        # Options Group
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        options_layout.setSpacing(10)  # Adjusted spacing
        
        # Length with spinbox
        length_layout = QHBoxLayout()
        length_label = QLabel("Length:")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 64)
        self.length_spin.setValue(16)
        self.length_spin.setMinimumHeight(25)  # Adjusted height
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_spin)
        options_layout.addLayout(length_layout)
        
        # Character types
        self.uppercase = QCheckBox("Uppercase (A-Z)")
        self.uppercase.setChecked(True)
        self.lowercase = QCheckBox("Lowercase (a-z)")
        self.lowercase.setChecked(True)
        self.numbers = QCheckBox("Numbers (0-9)")
        self.numbers.setChecked(True)
        self.special = QCheckBox("Special (!@#$%^&*)")
        self.special.setChecked(True)
        
        options_layout.addWidget(self.uppercase)
        options_layout.addWidget(self.lowercase)
        options_layout.addWidget(self.numbers)
        options_layout.addWidget(self.special)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)  # Added spacing between buttons
        
        generate_btn = QPushButton("Generate")
        generate_btn.setMinimumHeight(35)  # Increased height
        generate_btn.clicked.connect(self.generate_password)
        
        copy_btn = QPushButton("Copy")
        copy_btn.setMinimumHeight(35)  # Increased height
        copy_btn.clicked.connect(self.copy_password)
        
        button_layout.addWidget(generate_btn)
        button_layout.addWidget(copy_btn)
        layout.addLayout(button_layout)
        
        # Apply the updated style
        self.apply_style()
        
        # Generate initial password
        self.generate_password()
    
    def apply_style(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #12152d;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
                selection-background-color: #00ff9d;
                selection-color: #0a0b14;
            }
            QPushButton {
                background-color: #0a0b14;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QGroupBox {
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                margin-top: 1em;
                padding: 15px;
                font-size: 13px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #00ff9d;
            }
            QCheckBox {
                color: #ffffff;
                spacing: 8px;
                font-size: 13px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #00ff9d;
                border-radius: 3px;
                background-color: #0a0b14;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff9d;
                image: url(assets/checkmark.png);
            }
            QSpinBox {
                background-color: #12152d;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 5px;
                min-width: 80px;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                border: none;
                background-color: #00ff9d;
                color: #0a0b14;
                width: 15px;
            }
            QSpinBox::up-button:hover, QSpinBox::down-button:hover {
                background-color: #00cc7a;
            }
        """)
    
    def generate_password(self):
        length = self.length_spin.value()
        chars = ''
        
        if not any([self.uppercase.isChecked(), self.lowercase.isChecked(),
                   self.numbers.isChecked(), self.special.isChecked()]):
            QMessageBox.warning(self, "Error", "Please select at least one character type!")
            return
        
        if self.uppercase.isChecked():
            chars += string.ascii_uppercase
        if self.lowercase.isChecked():
            chars += string.ascii_lowercase
        if self.numbers.isChecked():
            chars += string.digits
        if self.special.isChecked():
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        while True:
            password = ''.join(secrets.choice(chars) for _ in range(length))
            
            # Verify password meets requirements
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
            
            if ((not self.uppercase.isChecked() or has_upper) and
                (not self.lowercase.isChecked() or has_lower) and
                (not self.numbers.isChecked() or has_digit) and
                (not self.special.isChecked() or has_special)):
                break
        
        self.password_display.setText(password)
    
    def copy_password(self):
        password = self.password_display.text()
        if password:
            clipboard = QApplication.clipboard()
            clipboard.setText(password)
            QMessageBox.information(self, "Success", "Password copied to clipboard!")

class HashChecker(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hash Checker")
        self.setMinimumSize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select file to check")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        layout.addWidget(QLabel("File:"))
        layout.addLayout(file_layout)
        
        # Hash type selection
        hash_layout = QHBoxLayout()
        self.hash_combo = QComboBox()
        self.hash_combo.addItems(['MD5', 'SHA1', 'SHA256', 'SHA512'])
        hash_layout.addWidget(QLabel("Hash Type:"))
        hash_layout.addWidget(self.hash_combo)
        layout.addLayout(hash_layout)
        
        # Hash input
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter hash to verify")
        layout.addWidget(QLabel("Expected Hash:"))
        layout.addWidget(self.hash_input)
        
        # Results
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.results)
        
        # Buttons
        button_layout = QHBoxLayout()
        calculate_btn = QPushButton("Calculate Hash")
        calculate_btn.clicked.connect(self.calculate_hash)
        verify_btn = QPushButton("Verify Hash")
        verify_btn.clicked.connect(self.verify_hash)
        button_layout.addWidget(calculate_btn)
        button_layout.addWidget(verify_btn)
        layout.addLayout(button_layout)
        
        self.apply_style()
    
    def apply_style(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
            QTextEdit {
                background-color: #12152d;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Courier New', monospace;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QComboBox {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: url(assets/down_arrow.png);
                width: 12px;
                height: 12px;
            }
        """)
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path.setText(file_path)
    
    def calculate_hash(self):
        file_path = self.file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file!")
            return
        
        try:
            hash_type = self.hash_combo.currentText().lower()
            hasher = getattr(hashlib, hash_type)()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            
            hash_value = hasher.hexdigest()
            self.results.setPlainText(f"File: {os.path.basename(file_path)}\n"
                                    f"Hash Type: {hash_type.upper()}\n"
                                    f"Hash: {hash_value}")
            
            # Copy hash to clipboard
            clipboard = QApplication.clipboard()
            clipboard.setText(hash_value)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Hash calculation failed: {str(e)}")
    
    def verify_hash(self):
        file_path = self.file_path.text()
        expected_hash = self.hash_input.text().lower()
        
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file!")
            return
        
        if not expected_hash:
            QMessageBox.warning(self, "Error", "Please enter the expected hash!")
            return
        
        try:
            hash_type = self.hash_combo.currentText().lower()
            hasher = getattr(hashlib, hash_type)()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            
            calculated_hash = hasher.hexdigest()
            
            if calculated_hash == expected_hash:
                self.results.setPlainText("✅ Hash verification successful!\n\n"
                                        f"File: {os.path.basename(file_path)}\n"
                                        f"Hash Type: {hash_type.upper()}\n"
                                        f"Calculated Hash: {calculated_hash}\n"
                                        f"Expected Hash: {expected_hash}")
                self.results.setStyleSheet("color: #00ff9d;")
            else:
                self.results.setPlainText("❌ Hash verification failed!\n\n"
                                        f"File: {os.path.basename(file_path)}\n"
                                        f"Hash Type: {hash_type.upper()}\n"
                                        f"Calculated Hash: {calculated_hash}\n"
                                        f"Expected Hash: {expected_hash}")
                self.results.setStyleSheet("color: #ff4444;")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Hash verification failed: {str(e)}")

class FileAnalyzer(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("File Analyzer")
        self.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(self)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select file to analyze")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        layout.addWidget(QLabel("File:"))
        layout.addLayout(file_layout)
        
        # Results area
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        layout.addWidget(QLabel("Analysis Results:"))
        layout.addWidget(self.results)
        
        # Analyze button
        analyze_btn = QPushButton("Analyze")
        analyze_btn.clicked.connect(self.analyze_file)
        layout.addWidget(analyze_btn)
        
        self.apply_style()
    
    def apply_style(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
            QTextEdit {
                background-color: #12152d;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Courier New', monospace;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
        """)
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path.setText(file_path)
    
    def analyze_file(self):
        file_path = self.file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file!")
            return
        
        try:
            stats = os.stat(file_path)
            
            # Basic file info
            info = []
            info.append(f"File Name: {os.path.basename(file_path)}")
            info.append(f"Size: {self.format_size(stats.st_size)}")
            info.append(f"Created: {datetime.fromtimestamp(stats.st_ctime)}")
            info.append(f"Modified: {datetime.fromtimestamp(stats.st_mtime)}")
            info.append(f"Accessed: {datetime.fromtimestamp(stats.st_atime)}")
            
            # Calculate hashes
            info.append("\nFile Hashes:")
            with open(file_path, 'rb') as f:
                data = f.read()
                info.append(f"MD5: {hashlib.md5(data).hexdigest()}")
                info.append(f"SHA1: {hashlib.sha1(data).hexdigest()}")
                info.append(f"SHA256: {hashlib.sha256(data).hexdigest()}")
            
            # File type detection
            import magic
            try:
                file_type = magic.from_file(file_path)
                info.append(f"\nFile Type: {file_type}")
            except ImportError:
                info.append("\nFile Type: python-magic library not installed")
            
            # Compression analysis
            info.append("\nCompression Analysis:")
            original_size = len(data)
            for method in ['zlib', 'lzma', 'bz2']:
                try:
                    compressed = getattr(globals()[method], 'compress')(data)
                    ratio = (len(compressed) / original_size) * 100
                    info.append(f"{method.upper()}: {ratio:.1f}% of original size")
                except Exception as e:
                    info.append(f"{method.upper()}: Error - {str(e)}")
            
            self.results.setPlainText('\n'.join(info))
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Analysis failed: {str(e)}")
    
    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

class CryptoGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GCrypt - Secure File Encryption")
        self.setMinimumSize(800, 600)
        self.is_maximized = False
        
        # Initialize settings
        self.settings = self.load_settings()
        
        # Set window icon
        icon = QIcon("assets/guardiran.ico")
        self.setWindowIcon(icon)
        
        # Create main widget and layout
        self.main_widget = QWidget()
        self.main_layout = QVBoxLayout(self.main_widget)
        self.setCentralWidget(self.main_widget)
        
        # Setup window controls first
        self.setup_window_controls()
        
        # Setup menubar
        self.setup_menubar()  # Add this line back
        
        # Setup rest of UI
        self.setup_ui()
        
        # Set window flags for frameless window
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)
        
        # Add new features
        self.recent_files = []
        self.max_recent_files = 10
        self.setup_recent_files()
        self.setup_file_monitoring()
        self.setup_batch_processing()
        self.setup_logging()
        
        # Clean up on close
        self.destroyed.connect(self.cleanup_resources)

    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = os.path.join(tempfile.gettempdir(), 'GCrypt')
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f'cryptovault_{datetime.now().strftime("%Y%m%d")}.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def setup_menubar(self):
        menubar = QMenuBar()
        self.setMenuBar(menubar)
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #0a0b14;
                color: #00ff9d;
                border-bottom: 2px solid #00ff9d;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 8px 12px;
            }
            QMenuBar::item:selected {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QMenu {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                color: #00ff9d;
            }
            QMenu::item:selected {
                background-color: #00ff9d;
                color: #0a0b14;
            }
        """)

        # File menu
        file_menu = menubar.addMenu("File")
        file_menu.addAction("Open", self.browse_file)
        file_menu.addAction("Exit", self.close)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        tools_menu.addAction("Password Generator", self.show_password_generator)
        tools_menu.addAction("Hash Checker", self.show_hash_checker)
        tools_menu.addAction("File Analyzer", self.show_file_analyzer)
        tools_menu.addSeparator()
        tools_menu.addAction("Secure Delete", self.secure_delete)
        tools_menu.addAction("File Splitter", self.show_file_splitter)
        tools_menu.addAction("Batch Processing", self.show_batch_processor)
        tools_menu.addAction("Compare Files", self.show_file_comparison)
        tools_menu.addSeparator()
        tools_menu.addAction("Compression Analysis", self.show_compression_analysis)
        tools_menu.addAction("File Monitor", self.show_file_monitor)

        # Help menu
        help_menu = menubar.addMenu("Help")
        help_menu.addAction("About", self.show_about)
        help_menu.addAction("Help", self.show_help)

    def setup_window_controls(self):
        """Setup custom window control buttons"""
        # Create title bar widget
        title_bar = QWidget()
        title_bar.setObjectName("title-bar")
        title_bar_layout = QHBoxLayout(title_bar)
        title_bar_layout.setContentsMargins(10, 0, 10, 0)
        title_bar_layout.setSpacing(0)  # Remove spacing between buttons
        
        # Add title
        title = QLabel("GCrypt")
        title.setStyleSheet("color: #00ff9d; font-size: 14px; font-weight: bold;")
        
        # Create control buttons
        min_btn = QPushButton("−")
        min_btn.setFixedSize(45, 30)  # Adjusted size
        min_btn.clicked.connect(self.showMinimized)
        min_btn.setProperty("class", "window-control")
        
        max_btn = QPushButton("□")
        max_btn.setFixedSize(45, 30)  # Adjusted size
        max_btn.clicked.connect(self.toggle_maximize)
        max_btn.setProperty("class", "window-control")
        
        close_btn = QPushButton("×")
        close_btn.setFixedSize(45, 30)  # Adjusted size
        close_btn.clicked.connect(self.close)
        close_btn.setProperty("class", "window-control")
        close_btn.setObjectName("close-btn")
        
        # Add widgets to title bar
        title_bar_layout.addWidget(title)
        title_bar_layout.addStretch()
        title_bar_layout.addWidget(min_btn)
        title_bar_layout.addWidget(max_btn)
        title_bar_layout.addWidget(close_btn)
        
        # Add title bar to main layout
        self.main_layout.addWidget(title_bar)
        
        # Style the window controls
        self.setStyleSheet(self.styleSheet() + """
            #title-bar {
                background-color: #1a1b26;
                border-bottom: 1px solid #2d2d2d;
                height: 30px;
            }
            
            QPushButton.window-control {
                background: transparent;
                border: none;
                color: #ffffff;
                font-size: 16px;
                font-family: Arial;
            }
            
            QPushButton.window-control:hover {
                background-color: #2d2d2d;
            }
            
            #close-btn:hover {
                background-color: #ff0000;
            }
        """)

    def toggle_maximize(self):
        """Toggle between maximized and normal window state"""
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def mousePressEvent(self, event):
        """Handle mouse press events for window dragging"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.drag_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        """Handle mouse move events for window dragging"""
        if hasattr(self, 'drag_pos'):
            diff = event.globalPosition().toPoint() - self.drag_pos
            new_pos = self.pos() + diff
            self.move(new_pos)
            self.drag_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        """Handle mouse release events for window dragging"""
        if hasattr(self, 'drag_pos'):
            del self.drag_pos

    def setup_ui(self):
        # Create main container
        main_container = QWidget()
        main_layout = QVBoxLayout(main_container)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Header with title (replacing the logo with text for now)
        header_container = QWidget()
        header_layout = QVBoxLayout(header_container)
        
        title_label = QLabel("======== GUARDIRAN SECURITY TOOLS ========")
        title_label.setStyleSheet("""
            color: #00ff9d; 
            font-family: 'Consolas', monospace;
            font-size: 14px;
            padding: 10px;
            border-top: 2px solid #00ff9d;
            border-bottom: 2px solid #00ff9d;
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(title_label)
        main_layout.addWidget(header_container)

        # File selection section
        file_section = QWidget()
        file_layout = QVBoxLayout(file_section)
        file_layout.setSpacing(10)
        
        # File selection header
        file_header = QLabel("FILE SELECTION")
        file_header.setStyleSheet("color: #00ff9d; font-size: 16px; font-weight: bold;")
        file_layout.addWidget(file_header)
        
        # File selection input area
        file_input_container = QWidget()
        file_input_layout = QHBoxLayout(file_input_container)
        file_input_layout.setSpacing(10)
        
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select file or drag and drop here")
        self.file_path.setStyleSheet("""
            QLineEdit {
                background-color: #0a0b14;
                color: white;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
        """)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
        """)
        browse_btn.clicked.connect(self.browse_file)
        
        file_input_layout.addWidget(self.file_path)
        file_input_layout.addWidget(browse_btn)
        file_layout.addWidget(file_input_container)
        main_layout.addWidget(file_section)

        # Encryption settings section
        encryption_section = QWidget()
        encryption_layout = QVBoxLayout(encryption_section)
        encryption_layout.setSpacing(15)
        
        # Encryption settings header
        encryption_header = QLabel("ENCRYPTION SETTINGS")
        encryption_header.setStyleSheet("color: #00ff9d; font-size: 16px; font-weight: bold;")
        encryption_layout.addWidget(encryption_header)
        
        # Mode selection
        mode_label = QLabel("Mode:")
        mode_label.setStyleSheet("color: white;")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Encrypt", "Decrypt"])
        self.mode_combo.setStyleSheet("""
            QComboBox {
                background-color: #0a0b14;
                color: white;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
        """)
        encryption_layout.addWidget(mode_label)
        encryption_layout.addWidget(self.mode_combo)
        
        # Password input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter encryption password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: #0a0b14;
                color: white;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
        """)
        encryption_layout.addWidget(self.password_input)
        
        # Compression checkbox
        self.compress_check = QCheckBox("Enable Compression")
        self.compress_check.setStyleSheet("""
            QCheckBox {
                color: white;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #00ff9d;
                border-radius: 3px;
                background-color: #0a0b14;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff9d;
            }
        """)
        encryption_layout.addWidget(self.compress_check)
        
        # Algorithm selection
        algo_label = QLabel("Encryption Algorithm:")
        algo_label.setStyleSheet("color: white;")
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(list(EncryptionSettings.ALGORITHMS.keys()))
        self.algo_combo.setStyleSheet("""
            QComboBox {
                background-color: #0a0b14;
                color: white;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
        """)
        encryption_layout.addWidget(algo_label)
        encryption_layout.addWidget(self.algo_combo)
        
        # Compression method
        comp_label = QLabel("Compression Method:")
        comp_label.setStyleSheet("color: white;")
        self.compression_combo = QComboBox()
        self.compression_combo.addItems(list(EncryptionSettings.COMPRESSION_METHODS.keys()))
        self.compression_combo.setStyleSheet("""
            QComboBox {
                background-color: #0a0b14;
                color: white;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
        """)
        encryption_layout.addWidget(comp_label)
        encryption_layout.addWidget(self.compression_combo)
        
        # Encrypt button
        self.action_btn = QPushButton("Encrypt File")
        self.action_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
                margin-top: 10px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
        """)
        self.action_btn.clicked.connect(self.process_file)
        encryption_layout.addWidget(self.action_btn)
        
        main_layout.addWidget(encryption_section)
        self.setCentralWidget(main_container)

        # Set window style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0b14;
            }
            QWidget {
                border-radius: 10px;
            }
        """)

    def create_file_controls(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select file or drag and drop here")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        return container

    def create_encryption_controls(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        
        # Mode selection
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Encrypt", "Decrypt"])
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        layout.addLayout(mode_layout)
        
        # Password input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter encryption password")
        layout.addWidget(self.password_input)
        
        # Compression checkbox
        self.compress_check = QCheckBox("Enable Compression")
        self.compress_check.setChecked(True)
        layout.addWidget(self.compress_check)
        
        # Encryption algorithm selection
        layout.addWidget(QLabel("Encryption Algorithm:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(EncryptionSettings.ALGORITHMS.keys())
        layout.addWidget(self.algo_combo)
        
        # Compression method selection
        layout.addWidget(QLabel("Compression Method:"))
        self.compression_combo = QComboBox()
        self.compression_combo.addItems(EncryptionSettings.COMPRESSION_METHODS.keys())
        layout.addWidget(self.compression_combo)
        
        # Action button
        self.action_btn = QPushButton("Encrypt File")
        self.action_btn.clicked.connect(self.process_file)
        self.action_btn.setProperty("class", "primary-button")
        layout.addWidget(self.action_btn)
        
        return container

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            self.file_path.setText(files[0])

    def browse_file(self):
        if self.mode_combo.currentText() == "Encrypt":
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        else:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt",
                                                     filter="Encrypted Files (*.encrypted)")
        if file_path:
            self.file_path.setText(file_path)

    def process_file(self):
        """Process (encrypt/decrypt) the selected file"""
        try:
            input_file = self.file_path.text()
            if not input_file:
                QMessageBox.warning(self, "Error", "Please select a file!")
                return
            
            if not os.path.exists(input_file):
                QMessageBox.warning(self, "Error", "Selected file does not exist!")
                return
            
            # Check file size
            file_size = os.path.getsize(input_file)
            if file_size > 2 * 1024 * 1024 * 1024:  # 2GB limit
                response = QMessageBox.warning(
                    self, 
                    "Large File Warning",
                    "The selected file is larger than 2GB. Processing may take a while. Continue?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if response == QMessageBox.StandardButton.No:
                    return
            
            # Check write permissions
            output_dir = os.path.dirname(input_file)
            if not os.access(output_dir, os.W_OK):
                QMessageBox.critical(self, "Error", "No write permission in the output directory!")
                return
            
            password = self.password_input.text()
            if not password:
                QMessageBox.warning(self, "Error", "Please enter a password!")
                return
            
            # Determine mode based on file extension
            mode = 'decrypt' if input_file.endswith('.encrypted') else 'encrypt'
            
            # Create output filename
            if mode == 'encrypt':
                output_file = input_file + '.encrypted'
            else:
                output_file = input_file[:-10]  # Remove .encrypted extension
            
            # Create progress dialog
            self.progress = QProgressDialog("Processing file...", "Cancel", 0, 100, self)
            self.progress.setWindowModality(Qt.WindowModality.WindowModal)
            self.progress.setWindowTitle("Processing")
            self.progress.setMinimumDuration(0)
            self.progress.setStyleSheet("""
                QProgressDialog {
                    background-color: #0a0b14;
                    color: #ffffff;
                }
                QProgressBar {
                    border: 2px solid #00ff9d;
                    border-radius: 5px;
                    text-align: center;
                    color: #ffffff;
                    background-color: #12152d;
                }
                QProgressBar::chunk {
                    background-color: #00ff9d;
                }
                QPushButton {
                    background-color: transparent;
                    color: #00ff9d;
                    border: 2px solid #00ff9d;
                    border-radius: 5px;
                    padding: 8px 15px;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: #00ff9d;
                    color: #0a0b14;
                }
            """)
            
            # Create and start worker
            self.worker = CryptoWorker(
                mode=mode,
                input_file=input_file,
                output_file=output_file,
                password=password,
                algorithm=self.algo_combo.currentText(),
                use_compression=self.compress_check.isChecked(),
                compression_method=self.compression_combo.currentText() if self.compress_check.isChecked() else None
            )
            
            # Connect signals
            self.worker.progress.connect(self.progress.setValue)
            self.worker.finished.connect(self.process_complete)
            
            # Start processing
            self.worker.start()
            
        except Exception as e:
            self.handle_encryption_error(e, input_file)

    def handle_encryption_error(self, error, input_file):
        """Handle encryption errors gracefully"""
        logging.error(f"Encryption error: {str(error)}")
        
        # Restore from backup if available
        if input_file in self.backups:
            if self.restore_from_backup(self.backups[input_file], input_file):
                QMessageBox.warning(self, "Error Recovery", 
                    "Encryption failed, but original file was restored from backup.")
                return
        
        QMessageBox.critical(self, "Error", 
            f"Encryption failed: {str(error)}\nPlease try again.")

    def process_complete(self, success, message):
        """Handle process completion"""
        self.progress.close()
        
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", f"Processing failed: {message}")

    def show_password_generator(self):
        dialog = PasswordGenerator(self)
        dialog.exec()

    def show_hash_checker(self):
        dialog = HashChecker(self)
        dialog.exec()

    def show_file_analyzer(self):
        dialog = FileAnalyzer(self)
        dialog.exec()

    def show_about(self):
        dialog = AboutDialog(self)
        dialog.exec()

    def show_help(self):
        dialog = HelpDialog(self)
        dialog.exec()

    def show_compression_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Compression Settings")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Method selection
        method_label = QLabel("Compression Method:")
        layout.addWidget(method_label)
        
        method_combo = QComboBox()
        method_combo.addItems(list(EncryptionSettings.COMPRESSION_METHODS.keys()))
        method_combo.setCurrentText(self.settings.get('compression_method', 'ZLIB'))
        layout.addWidget(method_combo)

        # Level selection
        level_label = QLabel("Compression Level:")
        layout.addWidget(level_label)
        
        level_spin = QSpinBox()
        level_spin.setRange(0, 9)
        level_spin.setValue(self.settings.get('compression_level', 6))
        layout.addWidget(level_spin)

        # Info label
        info_label = QLabel(
            "Higher compression levels result in smaller files but slower processing.\n"
            "Recommended level: 6"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        def save_settings():
            self.settings['compression_method'] = method_combo.currentText()
            self.settings['compression_level'] = level_spin.value()
            self.save_settings()
            dialog.accept()

        # Save button
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(save_settings)
        layout.addWidget(save_btn)

        # Apply cyberpunk theme
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
            }
            QComboBox, QSpinBox {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
        """)

        dialog.exec()

    def show_algorithm_info(self):
        """Show information about encryption algorithms and compression methods"""
        info_text = """
        Encryption Algorithms
        ====================
        
        AES-256-GCM:
        - Advanced Encryption Standard with 256-bit key
        - Galois/Counter Mode (GCM) provides authentication
        - Best choice for general use
        - Provides both confidentiality and authenticity
        
        AES-256-CBC:
        - Classic Cipher Block Chaining mode
        - Good for large files
        - Requires padding
        
        AES-256-CFB:
        - Cipher Feedback mode
        - Stream cipher-like operation
        - No padding required
        
        AES-256-OFB:
        - Output Feedback mode
        - Stream cipher-like operation
        - Good for noisy channels
        
        ChaCha20-Poly1305:
        - Modern stream cipher
        - Very fast on software implementations
        - Includes authentication
        - Good for mobile/low-power devices
        
        Camellia-256:
        - Alternative to AES
        - Similar security level
        - Different internal structure
        
        Compression Methods
        ==================
        
        ZLIB:
        - Fast and reliable
        - Good general-purpose compression
        - Balanced speed/compression ratio
        - Compression levels: 0 (none) to 9 (best)
        - Best for: General use, good balance of speed and compression
        - Use when: You need reliable, fast compression
        
        LZMA:
        - Better compression ratio than ZLIB
        - Slower compression
        - Best for archival purposes
        - Compression presets: 0 (fast) to 9 (best)
        - Best for: Achieving smallest file size
        - Use when: Storage space is premium, compression time not critical
        
        BZ2:
        - Good compression ratio
        - Slower than ZLIB
        - Better for text files
        - Compression levels: 1 (fast) to 9 (best)
        - Best for: Text file compression
        - Use when: Compressing text-based files
        
        None:
        - No compression
        - Fastest option
        - Best for already compressed files
        - Best for very small files
        - Use when: Files are already compressed (zip, jpg, mp3, etc.)
        
        Security Recommendations
        ======================
        
        1. For maximum security:
           - Use AES-256-GCM
           - Enable compression
           - Use strong passwords
           - Regular key rotation
           - Verify file hashes
        
        2. For best performance:
           - Use ChaCha20-Poly1305
           - Use ZLIB compression
           - Adjust compression level as needed
           - Balance security vs speed
        
        3. For best compression:
           - Any encryption algorithm
           - Use LZMA compression
           - Use maximum compression level
           - Expect slower processing
        
        4. For compatibility:
           - Use AES-256-CBC
           - Use ZLIB compression
           - Use moderate compression level
           - Standard file formats
        
        Best Practices
        =============
        
        1. Password Security:
           - Use long, random passwords
           - Mix characters, numbers, symbols
           - Never reuse passwords
           - Consider using password manager
        
        2. File Handling:
           - Keep backups of original files
           - Verify file integrity after operations
           - Use appropriate compression for file type
           - Test decryption after encryption
        
        3. Performance Tips:
           - Choose compression based on file type
           - Adjust compression level as needed
           - Consider file size vs. processing time
           - Use appropriate algorithm for your needs
        """

        dialog = QDialog(self)
        dialog.setWindowTitle("Encryption & Compression Information")
        dialog.setMinimumSize(600, 400)
        layout = QVBoxLayout(dialog)

        # Create text display
        text_display = QTextEdit()
        text_display.setPlainText(info_text)
        text_display.setReadOnly(True)
        layout.addWidget(text_display)

        # Add close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)

        dialog.exec()

    def load_settings(self):
        """Load application settings from file"""
        default_settings = {
            'algorithm': 'AES-256-GCM',
            'compression_method': 'ZLIB',
            'compression_level': 6,
            'max_recent_files': 10,
            'theme': 'dark',
            'auto_clear_password': True,
            'show_file_extensions': True
        }
        
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r') as f:
                    loaded_settings = json.load(f)
                    # Update default settings with loaded values
                    default_settings.update(loaded_settings)
        except Exception as e:
            print(f"Error loading settings: {e}")
        
        return default_settings

    def save_settings(self):
        """Save user settings"""
        settings = {
            'last_directory': os.path.dirname(self.file_path.text()) if self.file_path.text() else "",
            'algorithm': self.algo_combo.currentText(),
            'use_compression': self.compress_check.isChecked(),
            'compression_method': self.compression_combo.currentText(),
            'recent_files': self.recent_files[:10]  # Keep last 10 files
        }
        
        try:
            with open('settings.json', 'w') as f:
                json.dump(settings, f)
        except Exception as e:
            logging.error(f"Failed to save settings: {e}")

    def setup_recent_files(self):
        # Implementation of setup_recent_files method
        pass

    def setup_file_monitoring(self):
        # Implementation of setup_file_monitoring method
        pass

    def setup_batch_processing(self):
        # Implementation of setup_batch_processing method
        pass

    def secure_delete(self):
        """Securely delete files by overwriting with random data"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Delete")
        if file_path:
            try:
                # Overwrite file multiple times
                file_size = os.path.getsize(file_path)
                for _ in range(3):  # 3 passes
                    with open(file_path, 'wb') as f:
                        f.write(os.urandom(file_size))
                os.remove(file_path)
                QMessageBox.information(self, "Success", "File securely deleted")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete file: {str(e)}")

    def show_file_splitter(self):
        """Split large files into smaller chunks"""
        dialog = QDialog(self)
        dialog.setWindowTitle("File Splitter")
        dialog.setMinimumSize(500, 300)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # File selection
        file_layout = QHBoxLayout()
        self.split_file_path = QLineEdit()
        self.split_file_path.setPlaceholderText("Select file to split")
        self.split_file_path.setMinimumHeight(35)
        browse_btn = QPushButton("Browse")
        browse_btn.setMinimumHeight(35)
        browse_btn.clicked.connect(self.browse_split_file)
        file_layout.addWidget(self.split_file_path)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        # Chunk size selection with improved styling
        size_layout = QHBoxLayout()
        size_label = QLabel("Chunk Size:")
        self.size_spin = QSpinBox()
        self.size_spin.setRange(1, 1000)
        self.size_spin.setValue(10)
        self.size_spin.setMinimumHeight(35)
        self.size_unit = QComboBox()
        self.size_unit.addItems(["MB", "GB"])
        self.size_unit.setMinimumHeight(35)
        size_layout.addWidget(size_label)
        size_layout.addWidget(self.size_spin)
        size_layout.addWidget(self.size_unit)
        size_layout.addStretch()
        layout.addLayout(size_layout)
        
        # Progress bar
        self.split_progress = QProgressBar()
        self.split_progress.setMinimumHeight(20)
        layout.addWidget(self.split_progress)
        
        # Split button
        split_btn = QPushButton("Split File")
        split_btn.setMinimumHeight(35)
        split_btn.clicked.connect(self.split_file)
        layout.addWidget(split_btn)
        
        # Add stretch to push everything up
        layout.addStretch()
        
        # Apply cyberpunk theme
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QSpinBox {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 5px;
                min-width: 80px;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                width: 20px;
                background-color: #12152d;
                border: none;
            }
            QSpinBox::up-button:hover, QSpinBox::down-button:hover {
                background-color: #00ff9d;
            }
            QSpinBox::up-arrow {
                image: url(assets/up_arrow.png);
                width: 12px;
                height: 12px;
            }
            QSpinBox::down-arrow {
                image: url(assets/down_arrow.png);
                width: 12px;
                height: 12px;
            }
            QComboBox {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 5px;
                min-width: 70px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: url(assets/down_arrow.png);
                width: 12px;
                height: 12px;
            }
            QComboBox QAbstractItemView {
                background-color: #12152d;
                color: #ffffff;
                selection-background-color: #00ff9d;
                selection-color: #0a0b14;
            }
            QProgressBar {
                border: 2px solid #00ff9d;
                border-radius: 5px;
                text-align: center;
                color: #ffffff;
                background-color: #12152d;
            }
            QProgressBar::chunk {
                background-color: #00ff9d;
            }
        """)
        
        dialog.exec()

    def show_compression_analysis(self):
        """Analyze compression ratios for different methods"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Compression Analysis")
        dialog.setMinimumSize(600, 400)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # File selection
        file_layout = QHBoxLayout()
        self.analysis_path = QLineEdit()
        self.analysis_path.setPlaceholderText("Select file to analyze")
        self.analysis_path.setMinimumHeight(35)
        browse_btn = QPushButton("Browse")
        browse_btn.setMinimumHeight(35)
        browse_btn.clicked.connect(self.browse_analysis_file)
        file_layout.addWidget(self.analysis_path)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Method", "Size", "Ratio", "Time"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.results_table)
        
        # Analyze button
        analyze_btn = QPushButton("Analyze")
        analyze_btn.setMinimumHeight(35)
        analyze_btn.clicked.connect(self.perform_analysis)
        layout.addWidget(analyze_btn)
        
        # Apply cyberpunk theme
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QTableWidget {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                gridline-color: #00ff9d;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #0a0b14;
                color: #00ff9d;
                border: 1px solid #00ff9d;
                padding: 5px;
            }
        """)
        
        dialog.exec()

    def browse_analysis_file(self):
        """Browse for file to analyze"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze")
        if file_path:
            self.analysis_path.setText(file_path)

    def perform_analysis(self):
        """Analyze file with different compression methods"""
        file_path = self.analysis_path.text()
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file to analyze!")
            return
        
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Selected file does not exist!")
            return
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            original_size = len(data)
            
            # Clear previous results
            self.results_table.setRowCount(0)
            
            # Test different compression methods
            methods = {
                'zlib': zlib.compress,
                'lzma': lzma.compress,
                'bz2': bz2.compress
            }
            
            for method_name, compress_func in methods.items():
                start_time = time.time()
                compressed = compress_func(data)
                end_time = time.time()
                
                compressed_size = len(compressed)
                ratio = (compressed_size / original_size) * 100
                process_time = (end_time - start_time) * 1000  # Convert to ms
                
                # Add result to table
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                
                # Create and set items
                method_item = QTableWidgetItem(method_name)
                size_item = QTableWidgetItem(f"{compressed_size:,} bytes")
                ratio_item = QTableWidgetItem(f"{ratio:.1f}%")
                time_item = QTableWidgetItem(f"{process_time:.1f} ms")
                
                # Set text alignment for numeric columns
                size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                ratio_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                time_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                
                # Add items to table
                self.results_table.setItem(row, 0, method_item)
                self.results_table.setItem(row, 1, size_item)
                self.results_table.setItem(row, 2, ratio_item)
                self.results_table.setItem(row, 3, time_item)
            
            # Add original file size row
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            self.results_table.setItem(row, 0, QTableWidgetItem("Original"))
            self.results_table.setItem(row, 1, QTableWidgetItem(f"{original_size:,} bytes"))
            self.results_table.setItem(row, 2, QTableWidgetItem("100%"))
            self.results_table.setItem(row, 3, QTableWidgetItem("-"))
            
            # Resize columns to content
            self.results_table.resizeColumnsToContents()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Analysis failed: {str(e)}")

    def show_file_monitor(self):
        """Monitor directory for file changes"""
        self.monitor_dialog = QDialog(self)  # Store dialog as instance variable
        self.monitor_dialog.setWindowTitle("File Monitor")
        self.monitor_dialog.setMinimumSize(500, 400)
        layout = QVBoxLayout(self.monitor_dialog)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Directory selection
        dir_layout = QHBoxLayout()
        self.monitor_path = QLineEdit()
        self.monitor_path.setPlaceholderText("Select directory to monitor")
        self.monitor_path.setMinimumHeight(35)
        browse_btn = QPushButton("Browse")
        browse_btn.setMinimumHeight(35)
        browse_btn.clicked.connect(self.browse_monitor_dir)
        dir_layout.addWidget(self.monitor_path)
        dir_layout.addWidget(browse_btn)
        layout.addLayout(dir_layout)
        
        # Event log
        self.monitor_log = QTextEdit()
        self.monitor_log.setReadOnly(True)
        self.monitor_log.setStyleSheet("""
            QTextEdit {
                background-color: #12152d;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Courier New', monospace;  /* Changed from Consolas */
            }
        """)
        layout.addWidget(self.monitor_log)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.setMinimumHeight(35)
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setMinimumHeight(35)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)
        
        # Connect dialog's finished signal to cleanup
        self.monitor_dialog.finished.connect(self.cleanup_monitor)
        
        # Apply cyberpunk theme
        self.monitor_dialog.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QPushButton:disabled {
                color: #4d5061;
                border-color: #4d5061;
            }
        """)
        
        self.monitor_dialog.exec()

    def cleanup_monitor(self):
        """Clean up monitoring resources when dialog closes"""
        if hasattr(self, 'monitor_worker'):
            self.stop_monitoring()
    
    def log_file_event(self, message):
        """Log file system events"""
        try:
            if hasattr(self, 'monitor_log') and not self.monitor_log.isHidden():
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.monitor_log.append(f"[{timestamp}] {message}")
        except RuntimeError:
            # Widget has been deleted, ignore the error
            pass

    def browse_monitor_dir(self):
        """Browse for directory to monitor"""
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory to Monitor")
        if dir_path:
            self.monitor_path.setText(dir_path)

    def start_monitoring(self):
        """Start monitoring the selected directory"""
        dir_path = self.monitor_path.text()
        if not dir_path:
            QMessageBox.warning(self, "Error", "Please select a directory to monitor!")
            return
        
        if not os.path.exists(dir_path):
            QMessageBox.warning(self, "Error", "Selected directory does not exist!")
            return
        
        self.monitor_active = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.monitor_path.setEnabled(False)
        
        # Start monitoring in a separate thread
        self.monitor_thread = QThread()
        self.monitor_worker = FileMonitorWorker(dir_path)
        self.monitor_worker.moveToThread(self.monitor_thread)
        
        # Connect signals
        self.monitor_thread.started.connect(self.monitor_worker.run)
        self.monitor_worker.file_changed.connect(self.log_file_event)
        self.monitor_worker.finished.connect(self.monitor_thread.quit)
        
        self.monitor_thread.start()
        self.log_file_event("Monitoring started...")

    def stop_monitoring(self):
        """Stop monitoring the directory"""
        if hasattr(self, 'monitor_worker'):
            self.monitor_worker.stop()
            self.monitor_thread.quit()
            self.monitor_thread.wait()
        
        self.monitor_active = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.monitor_path.setEnabled(True)
        self.log_file_event("Monitoring stopped.")

    def show_batch_processor(self):
        """Process multiple files in batch"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Batch Processing")
        dialog.setMinimumSize(600, 400)
        layout = QVBoxLayout(dialog)
        
        # File list
        self.batch_files = QListWidget()
        layout.addWidget(self.batch_files)
        
        # Add files button
        add_btn = QPushButton("Add Files")
        add_btn.clicked.connect(self.add_batch_files)
        layout.addWidget(add_btn)
        
        # Password field
        pass_layout = QHBoxLayout()
        self.batch_password = QLineEdit()
        self.batch_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.batch_password.setPlaceholderText("Enter password")
        pass_layout.addWidget(QLabel("Password:"))
        pass_layout.addWidget(self.batch_password)
        layout.addLayout(pass_layout)
        
        # Progress bar
        self.batch_progress = QProgressBar()
        layout.addWidget(self.batch_progress)
        
        # Start button
        start_btn = QPushButton("Start Processing")
        start_btn.clicked.connect(self.start_batch_processing)
        layout.addWidget(start_btn)
        
        # Apply cyberpunk theme
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
            }
            QListWidget {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
            }
            QLineEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QProgressBar {
                border: 2px solid #00ff9d;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #00ff9d;
            }
        """)
        
        dialog.exec()

    def add_batch_files(self):
        """Add files to batch processing list"""
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for file in files:
            self.batch_files.addItem(file)

    def start_batch_processing(self):
        if self.batch_files.count() == 0:
            QMessageBox.warning(self, "Error", "Please add files first!")
            return
        
        if not self.batch_password.text():
            QMessageBox.warning(self, "Error", "Please enter a password!")
            return
        
        total_files = self.batch_files.count()
        processed_files = 0
        failed_files = []
        
        try:
            for i in range(total_files):
                input_file = self.batch_files.item(i).text()
                
                # Determine mode based on file extension
                mode = 'decrypt' if input_file.endswith('.encrypted') else 'encrypt'
                
                # Generate output filename
                if mode == 'encrypt':
                    output_file = input_file + '.encrypted'
                else:
                    output_file = input_file[:-10]  # Remove .encrypted
                
                # Create worker
                worker = CryptoWorker(
                    mode=mode,
                    input_file=input_file,
                    output_file=output_file,
                    password=self.batch_password.text(),
                    algorithm=self.algo_combo.currentText(),
                    use_compression=self.compress_check.isChecked(),
                    compression_method=self.compression_combo.currentText() if self.compress_check.isChecked() else None
                )
                
                # Connect signals
                worker.progress.connect(lambda p: self.update_batch_progress(int(p)))
                worker.finished.connect(lambda success, msg, file=input_file: 
                    self.handle_batch_result(success, msg, file))
                
                # Process file
                worker.start()
                worker.wait()
                
                processed_files += 1
                progress = int((processed_files / total_files) * 100)
                self.batch_progress.setValue(progress)
            
            # Show final results
            if failed_files:
                error_msg = "The following files were skipped:\n"
                for file, reason in failed_files:
                    error_msg += f"\n{file}: {reason}"
                QMessageBox.warning(self, "Batch Processing Results", error_msg)
            
            if processed_files > 0:
                QMessageBox.information(self, "Success", 
                    f"Batch processing completed!\nProcessed {processed_files} files successfully.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Batch processing failed: {str(e)}")

    def update_batch_progress(self, value):
        """Update the batch progress bar with integer value"""
        try:
            self.batch_progress.setValue(int(value))
        except Exception as e:
            print(f"Progress update error: {e}")

    def handle_batch_result(self, success, message, file_name):
        """Handle the result of each file in batch processing"""
        if not success:
            QMessageBox.warning(self, "Warning", 
                f"Failed to process {file_name}\nReason: {message}")

    def show_file_comparison(self):
        """Compare two files for differences"""
        dialog = QDialog(self)
        dialog.setWindowTitle("File Comparison")
        dialog.setMinimumSize(600, 400)
        layout = QVBoxLayout(dialog)
        
        # File selection
        file_group = QGroupBox("Select Files")
        file_layout = QVBoxLayout()
        
        # File 1
        file1_layout = QHBoxLayout()
        self.file1_path = QLineEdit()
        file1_btn = QPushButton("Browse")
        file1_btn.clicked.connect(lambda: self.browse_comparison_file(self.file1_path))
        file1_layout.addWidget(QLabel("File 1:"))
        file1_layout.addWidget(self.file1_path)
        file1_layout.addWidget(file1_btn)
        file_layout.addLayout(file1_layout)
        
        # File 2
        file2_layout = QHBoxLayout()
        self.file2_path = QLineEdit()
        file2_btn = QPushButton("Browse")
        file2_btn.clicked.connect(lambda: self.browse_comparison_file(self.file2_path))
        file2_layout.addWidget(QLabel("File 2:"))
        file2_layout.addWidget(self.file2_path)
        file2_layout.addWidget(file2_btn)
        file_layout.addLayout(file2_layout)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Comparison options
        options_group = QGroupBox("Comparison Options")
        options_layout = QVBoxLayout()
        
        self.binary_compare = QCheckBox("Binary comparison")
        self.hash_compare = QCheckBox("Hash comparison (MD5, SHA-256)")
        self.content_compare = QCheckBox("Content comparison")
        self.content_compare.setChecked(True)
        
        options_layout.addWidget(self.binary_compare)
        options_layout.addWidget(self.hash_compare)
        options_layout.addWidget(self.content_compare)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Results
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        self.comparison_results = QTextEdit()
        self.comparison_results.setReadOnly(True)
        results_layout.addWidget(self.comparison_results)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Compare button
        compare_btn = QPushButton("Compare Files")
        compare_btn.clicked.connect(self.perform_comparison)
        layout.addWidget(compare_btn)
        
        # Apply cyberpunk theme
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton {
                background-color: transparent;
                color: #00ff9d;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #0a0b14;
            }
            QTextEdit {
                background-color: #12152d;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
            }
            QGroupBox {
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QCheckBox {
                color: #ffffff;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff9d;
            }
        """)
        
        dialog.exec()

    def browse_comparison_file(self, line_edit):
        """Browse for a file to compare"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            line_edit.setText(file_path)

    def compare_content(self, file1, file2):
        """Compare file contents line by line"""
        differences = []
        try:
            with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
                # Compare file sizes first
                size1 = os.path.getsize(file1)
                size2 = os.path.getsize(file2)
                if size1 != size2:
                    differences.append(f"File sizes differ: {size1} vs {size2} bytes\n")
                
                # Compare content in chunks
                chunk_size = 8192  # 8KB chunks
                while True:
                    chunk1 = f1.read(chunk_size)
                    chunk2 = f2.read(chunk_size)
                    
                    if chunk1 != chunk2:
                        differences.append("Files differ in content\n")
                        break
                    
                    if not chunk1:  # End of both files
                        break
            
            if not differences:
                differences.append("Files are identical")
                
            return differences
        except Exception as e:
            return [f"Error comparing files: {str(e)}"]

    def perform_comparison(self):
        """Perform file comparison based on selected options"""
        file1 = self.file1_path.text()
        file2 = self.file2_path.text()
        
        if not file1 or not file2:
            QMessageBox.warning(self, "Error", "Please select both files!")
            return
        
        if not os.path.exists(file1) or not os.path.exists(file2):
            QMessageBox.warning(self, "Error", "One or both files do not exist!")
            return
        
        results = []
        
        try:
            # Basic file info
            results.append("File Information:")
            results.append(f"File 1: {file1}")
            results.append(f"Size: {os.path.getsize(file1)} bytes")
            results.append(f"File 2: {file2}")
            results.append(f"Size: {os.path.getsize(file2)} bytes\n")
            
            # Hash comparison
            if self.hash_compare.isChecked():
                results.append("Hash Comparison:")
                for algorithm in ['md5', 'sha256']:
                    hash1 = self.calculate_file_hash(file1, algorithm)
                    hash2 = self.calculate_file_hash(file2, algorithm)
                    results.append(f"{algorithm.upper()}:")
                    results.append(f"File 1: {hash1}")
                    results.append(f"File 2: {hash2}")
                    results.append(f"Match: {hash1 == hash2}\n")
            
            # Binary comparison
            if self.binary_compare.isChecked():
                results.append("Binary Comparison:")
                binary_match = self.compare_binary(file1, file2)
                results.append(f"Files are {'identical' if binary_match else 'different'}\n")
            
            # Content comparison
            if self.content_compare.isChecked():
                results.append("Content Comparison:")
                differences = self.compare_content(file1, file2)
                results.extend(differences)
            
            self.comparison_results.setText('\n'.join(results))
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Comparison failed: {str(e)}")

    def calculate_file_hash(self, file_path, algorithm):
        """Calculate file hash using specified algorithm"""
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

    def compare_binary(self, file1, file2):
        """Compare files binary content"""
        if os.path.getsize(file1) != os.path.getsize(file2):
            return False
        
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            chunk_size = 8192  # 8KB chunks
            while True:
                chunk1 = f1.read(chunk_size)
                chunk2 = f2.read(chunk_size)
                if chunk1 != chunk2:
                    return False
                if not chunk1:  # End of both files
                    return True

    def browse_split_file(self):
        """Browse for file to split"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Split",
            "",
            "All Files (*.*)"
        )
        if file_path:
            self.split_file_path.setText(file_path)

    def split_file(self):
        """Split the selected file into chunks"""
        input_file = self.split_file_path.text()
        if not input_file:
            QMessageBox.warning(self, "Error", "Please select a file to split!")
            return
        
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "Error", "Selected file does not exist!")
            return
        
        # Calculate chunk size in bytes
        chunk_size = self.size_spin.value()
        if self.size_unit.currentText() == "GB":
            chunk_size *= 1024  # Convert to MB first
        chunk_size *= 1024 * 1024  # Convert to bytes
        
        try:
            # Create output directory
            base_name = os.path.basename(input_file)
            output_dir = os.path.join(os.path.dirname(input_file), f"{base_name}_splits")
            os.makedirs(output_dir, exist_ok=True)
            
            # Get total file size
            total_size = os.path.getsize(input_file)
            chunks = (total_size + chunk_size - 1) // chunk_size
            
            with open(input_file, 'rb') as f:
                for i in range(chunks):
                    chunk_data = f.read(chunk_size)
                    output_file = os.path.join(output_dir, f"{base_name}.part{i+1}")
                    
                    with open(output_file, 'wb') as chunk_file:
                        chunk_file.write(chunk_data)
                    
                    # Update progress
                    progress = int(((i + 1) / chunks) * 100)
                    self.split_progress.setValue(progress)
            
            QMessageBox.information(self, "Success", 
                f"File split into {chunks} parts\nLocation: {output_dir}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to split file: {str(e)}")

    def verify_file(self, file_path, data):
        """Verify file integrity using SHA-256"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            
            return sha256_hash.digest() == hashlib.sha256(data).digest()
        except Exception as e:
            logging.error(f"File verification error: {str(e)}", exc_info=True)
            return False

    def process_large_file(self, input_file, output_file, chunk_size=1024*1024):
        """Process large files in chunks to manage memory"""
        try:
            total_size = os.path.getsize(input_file)
            processed = 0
            
            with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
                while True:
                    chunk = in_file.read(chunk_size)
                    if not chunk:
                        break
                        
                    # Process chunk
                    processed_chunk = self.process_chunk(chunk)
                    out_file.write(processed_chunk)
                    
                    # Update progress
                    processed += len(chunk)
                    progress = int((processed / total_size) * 100)
                    self.progress.setValue(progress)
                    
        except Exception as e:
            logging.error(f"Large file processing error: {str(e)}", exc_info=True)
            raise

    def create_backup(self, file_path):
        """Create backup before processing"""
        try:
            backup_path = file_path + '.backup'
            with open(file_path, 'rb') as src, open(backup_path, 'wb') as dst:
                dst.write(src.read())
            return backup_path
        except Exception as e:
            logging.error(f"Backup creation error: {str(e)}", exc_info=True)
            return None

    def restore_from_backup(self, backup_path, original_path):
        """Restore file from backup if processing fails"""
        try:
            if os.path.exists(backup_path):
                with open(backup_path, 'rb') as src, open(original_path, 'wb') as dst:
                    dst.write(src.read())
                os.remove(backup_path)
                return True
        except Exception as e:
            logging.error(f"Backup restoration error: {str(e)}", exc_info=True)
        return False

    def cleanup_resources(self):
        """Clean up temporary files and backups"""
        try:
            # Clean temp files
            for temp_file in self.temp_files:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            
            # Clean backups
            for backup_file in self.backups.values():
                if os.path.exists(backup_file):
                    os.remove(backup_file)
                
        except Exception as e:
            logging.error(f"Cleanup error: {str(e)}", exc_info=True)

    def validate_password(self, password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            return False, "Password must contain uppercase, lowercase, numbers, and special characters"
        
        return True, "Password is strong"

    def show_password_strength(self):
        """Show password strength indicator"""
        password = self.password_input.text()
        is_valid, message = self.validate_password(password)
        
        if is_valid:
            self.password_strength.setStyleSheet("color: #00ff9d;")
        else:
            self.password_strength.setStyleSheet("color: #ff4444;")
        
        self.password_strength.setText(message)

    def check_system_resources(self, file_size):
        """Check if system has enough resources"""
        try:
            import psutil
            
            # Check available RAM (leave 1GB buffer)
            available_ram = psutil.virtual_memory().available
            if file_size > (available_ram - (1024 * 1024 * 1024)):
                return False, "Not enough memory available"
            
            # Check disk space
            disk = psutil.disk_usage(os.path.dirname(self.file_path.text()))
            if file_size > (disk.free - (1024 * 1024 * 1024)):
                return False, "Not enough disk space"
            
            return True, "System resources OK"
        except:
            # If psutil not available, just return True
            return True, "Resource check skipped"

    def update_status(self, message, error=False):
        """Update status bar with message"""
        if hasattr(self, 'statusBar'):
            color = "#ff4444" if error else "#00ff9d"
            self.statusBar().setStyleSheet(f"color: {color}")
            self.statusBar().showMessage(message, 5000)  # Show for 5 seconds

    def check_for_updates(self):
        """Check for new versions"""
        try:
            import requests
            
            response = requests.get('https://api.github.com/repos/guardiran/GCrypt/releases/latest')
            latest_version = response.json()['tag_name']
            
            if latest_version > "1.0-beta":
                QMessageBox.information(self, "Update Available", 
                    f"A new version ({latest_version}) is available!\n"
                    "Visit https://github.com/guardiran/GCrypt for updates.")
        except:
            logging.warning("Failed to check for updates")

class FileMonitorWorker(QThread):
    file_changed = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.active = True
        self.last_state = {}
    
    def run(self):
        while self.active:
            current_state = {}
            for root, dirs, files in os.walk(self.path):
                for file in files:
                    path = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(path)
                        current_state[path] = mtime
                    except:
                        continue
            
            # Check for changes
            for path, mtime in current_state.items():
                if path not in self.last_state:
                    self.file_changed.emit(f"New file: {os.path.basename(path)}")
                elif mtime != self.last_state[path]:
                    self.file_changed.emit(f"Modified: {os.path.basename(path)}")
            
            for path in self.last_state:
                if path not in current_state:
                    self.file_changed.emit(f"Deleted: {os.path.basename(path)}")
            
            self.last_state = current_state
            time.sleep(1)  # Check every second
        
        self.finished.emit()
    
    def stop(self):
        self.active = False

class HelpDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("GCrypt Help")
        self.setMinimumSize(800, 600)
        
        layout = QVBoxLayout(self)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Getting Started tab
        getting_started = QTextEdit()
        getting_started.setReadOnly(True)
        getting_started.setHtml("""
            <h2 style='color: #00ff9d;'>Getting Started with GCrypt</h2>
            
            <h3 style='color: #00ff9d;'>Basic Usage:</h3>
            <ol style='color: #ffffff;'>
                <li>Select a file using the 'Browse' button or drag and drop</li>
                <li>Enter a strong password (use the password generator if needed)</li>
                <li>Choose an encryption algorithm (AES-256-GCM recommended)</li>
                <li>Enable compression if desired</li>
                <li>Click 'Encrypt' or 'Decrypt' based on your needs</li>
            </ol>
            
            <h3 style='color: #00ff9d;'>File Extensions:</h3>
            <ul style='color: #ffffff;'>
                <li>.encrypted - Encrypted files</li>
                <li>.decrypted - Decrypted files (optional)</li>
            </ul>
        """)
        tabs.addTab(getting_started, "Getting Started")
        
        # Features tab
        features = QTextEdit()
        features.setReadOnly(True)
        features.setHtml("""
            <h2 style='color: #00ff9d;'>GCrypt Features</h2>
            
            <h3 style='color: #00ff9d;'>1. File Encryption/Decryption</h3>
            <ul style='color: #ffffff;'>
                <li><b>AES-256-GCM:</b> 
                    <ul>
                        <li>Military-grade encryption</li>
                        <li>Authenticated encryption with associated data (AEAD)</li>
                        <li>Perfect for sensitive data</li>
                    </ul>
                </li>
                <li><b>AES-256-CBC:</b>
                    <ul>
                        <li>Cipher Block Chaining mode</li>
                        <li>Traditional block cipher mode</li>
                        <li>Widely supported</li>
                    </ul>
                </li>
                <li><b>AES-256-CFB:</b>
                    <ul>
                        <li>Cipher Feedback mode</li>
                        <li>Stream cipher-like functionality</li>
                        <li>Good for real-time encryption</li>
                    </ul>
                </li>
                <li><b>AES-256-OFB:</b>
                    <ul>
                        <li>Output Feedback mode</li>
                        <li>Stream cipher operation</li>
                        <li>Resistant to transmission errors</li>
                    </ul>
                </li>
                <li><b>ChaCha20-Poly1305:</b>
                    <ul>
                        <li>Modern stream cipher</li>
                        <li>High performance on all platforms</li>
                        <li>Perfect for mobile devices</li>
                    </ul>
                </li>
                <li><b>Camellia-256:</b>
                    <ul>
                        <li>Alternative to AES</li>
                        <li>Developed by NTT and Mitsubishi</li>
                        <li>Approved by ISO/IEC</li>
                    </ul>
                </li>
            </ul>
            
            <h3 style='color: #00ff9d;'>2. File Compression</h3>
            <ul style='color: #ffffff;'>
                <li><b>ZLIB:</b> Fast compression, good ratio</li>
                <li><b>LZMA:</b> High compression ratio, slower</li>
                <li><b>BZ2:</b> Alternative compression method</li>
                <li>Adjustable compression levels (1-9)</li>
            </ul>
            
            <h3 style='color: #00ff9d;'>3. Password Generator</h3>
            <ul style='color: #ffffff;'>
                <li>Customizable length (8-64 characters)</li>
                <li>Character type selection</li>
                <li>Cryptographically secure generation</li>
                <li>One-click copy functionality</li>
            </ul>
            
            <h3 style='color: #00ff9d;'>4. Hash Checker</h3>
            <ul style='color: #ffffff;'>
                <li>Multiple hash algorithms:
                    <ul>
                        <li>MD5 (not recommended for security)</li>
                        <li>SHA-1</li>
                        <li>SHA-256</li>
                        <li>SHA-512</li>
                    </ul>
                </li>
                <li>Hash verification</li>
                <li>File integrity checking</li>
            </ul>
            
            <h3 style='color: #00ff9d;'>5. File Analyzer</h3>
            <ul style='color: #ffffff;'>
                <li>File metadata analysis</li>
                <li>Multiple hash calculations</li>
                <li>Compression ratio analysis</li>
                <li>File type detection</li>
                <li>Size and timestamp information</li>
            </ul>
            
            <h3 style='color: #00ff9d;'>6. Batch Processing</h3>
            <ul style='color: #ffffff;'>
                <li>Process multiple files simultaneously</li>
                <li>Bulk encryption/decryption</li>
                <li>Progress tracking for each file</li>
                <li>Error handling and reporting</li>
                <li>Consistent settings across files</li>
            </ul>
            
            <h3 style='color: #00ff9d;'>7. File Monitoring</h3>
            <ul style='color: #ffffff;'>
                <li>Real-time directory monitoring</li>
                <li>Automatic encryption of new files</li>
                <li>Event logging with timestamps</li>
                <li>Customizable monitoring rules</li>
                <li>Activity notifications</li>
            </ul>
            
            <h3 style='color: #00ff9d;'>8. Secure File Deletion</h3>
            <ul style='color: #ffffff;'>
                <li>Multiple overwrite passes</li>
                <li>DoD 5220.22-M compliant</li>
                <li>Verification after deletion</li>
                <li>Support for sensitive data removal</li>
                <li>Batch deletion capability</li>
            </ul>
            
            <h3 style='color: #00ff9d;'>Additional Features</h3>
            <ul style='color: #ffffff;'>
                <li>Drag and drop support</li>
                <li>Dark mode interface</li>
                <li>Progress tracking</li>
                <li>Error recovery</li>
                <li>Automatic backups</li>
                <li>Session logging</li>
            </ul>
        """)
        tabs.addTab(features, "Features")
        
        # Security tab
        security = QTextEdit()
        security.setReadOnly(True)
        security.setHtml("""
            <h2 style='color: #00ff9d;'>Security Information</h2>
            
            <h3 style='color: #00ff9d;'>Encryption Algorithms</h3>
            <ul style='color: #ffffff;'>
                <li><b>AES-256-GCM:</b>
                    <ul>
                        <li>256-bit key length</li>
                        <li>Galois/Counter Mode (GCM)</li>
                        <li>Authenticated encryption</li>
                        <li>Industry standard</li>
                    </ul>
                </li>
                <li><b>ChaCha20-Poly1305:</b>
                    <ul>
                        <li>Modern stream cipher</li>
                        <li>High performance on all platforms</li>
                        <li>Integrated authentication</li>
                        <li>Perfect for mobile/low-power devices</li>
                    </ul>
                </li>
            </ul>
            
            <h3 style='color: #00ff9d;'>Compression Methods</h3>
            <ul style='color: #ffffff;'>
                <li><b>ZLIB:</b>
                    <ul>
                        <li>Fast compression and decompression</li>
                        <li>Good compression ratio</li>
                        <li>Low memory usage</li>
                    </ul>
                </li>
                <li><b>LZMA:</b>
                    <ul>
                        <li>High compression ratio</li>
                        <li>Higher memory usage</li>
                        <li>Slower but more efficient</li>
                    </ul>
                </li>
                <li><b>BZ2:</b>
                    <ul>
                        <li>Block-sorting compression</li>
                        <li>Good for text files</li>
                        <li>Balanced performance</li>
                    </ul>
                </li>
            </ul>
            
            <h3 style='color: #00ff9d;'>Best Practices</h3>
            <ul style='color: #ffffff;'>
                <li>Use strong, unique passwords</li>
                <li>Keep backups of important files</li>
                <li>Verify file integrity after operations</li>
                <li>Use AES-256-GCM for maximum security</li>
                <li>Enable compression for large files</li>
            </ul>
        """)
        tabs.addTab(security, "Security")
        
        # Add tabs to layout
        layout.addWidget(tabs)
        
        # Apply cyberpunk theme
        self.setStyleSheet("""
            QDialog {
                background-color: #0a0b14;
                border: 2px solid #00ff9d;
                border-radius: 10px;
            }
            QTabWidget::pane {
                border: 2px solid #00ff9d;
                border-radius: 5px;
                background-color: #12152d;
            }
            QTabBar::tab {
                background-color: #0a0b14;
                color: #ffffff;
                border: 2px solid #00ff9d;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                padding: 8px 15px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #12152d;
                margin-bottom: -2px;
            }
            QTextEdit {
                background-color: #12152d;
                color: #ffffff;
                border: none;
                font-size: 13px;
            }
        """)

def main():
    app = QApplication(sys.argv)
    window = CryptoGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

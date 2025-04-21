import sys
import os
import json
from datetime import datetime, timedelta, UTC

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit,
    QFormLayout, QFileDialog, QListWidget, QHBoxLayout, QMessageBox, QLabel, QTableWidget, QTableWidgetItem, QHeaderView
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509 import NameOID

# ====== Paths ======
DATA_DIR = "data"
CERTS_DIR = os.path.join(DATA_DIR, "certs")
DB_PATH = os.path.join(DATA_DIR, "db.json")
CA_KEY_PATH = os.path.join(DATA_DIR, "ca.key")
CA_CERT_PATH = os.path.join(DATA_DIR, "ca.crt")
CRL_PATH = os.path.join(DATA_DIR, "crl.pem")

os.makedirs(CERTS_DIR, exist_ok=True)


# ====== Utility ======
def saveJson(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def loadJson(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"issued": [], "revoked": []}


# ====== CA ======
class CertificateAuthority:
    def __init__(self, subject_data=None):
        self.private_key = None
        self.cert = None
        self.db = loadJson(DB_PATH)

        if subject_data:
            self.createCa(subject_data)
        else:
            self.loadCa()

    def createCa(self, subject_data, valid_days=3650):
        # Private key
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject_data["Country"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_data["State"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject_data["Locality"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data["Organization name"]),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_data["Common Name (CN)"]),
        ])
        self.cert = x509.CertificateBuilder(
        ).subject_name(subject
        ).issuer_name(subject
        ).public_key(self.private_key.public_key()
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.now(UTC)
        ).not_valid_after(datetime.now(UTC) + timedelta(days=valid_days)
        ).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self.private_key, hashes.SHA256())

        # Save
        with open(CA_KEY_PATH, "wb") as f:
            f.write(self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(CA_CERT_PATH, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))

    def loadCa(self):
        with open(CA_KEY_PATH, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, "rb") as f:
            self.cert = x509.load_pem_x509_certificate(f.read())

    def issue_cert(self, subject_data, valid_days=365):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject_data["Country"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_data["State"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject_data["Locality"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data["Organization name"]),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_data["Common Name (CN)"]),
        ])

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = x509.CertificateBuilder(
        ).subject_name(subject
        ).issuer_name(self.cert.subject
        ).public_key(key.public_key()
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.now(UTC)
        ).not_valid_after(datetime.now(UTC) + timedelta(days=valid_days)
        ).sign(self.private_key, hashes.SHA256())

        filename = f"{subject_data['Common Name (CN)'].replace(' ', '_')}.crt"
        keyfile = filename.replace(".crt", ".key")
        cert_path = os.path.join(CERTS_DIR, filename)
        key_path = os.path.join(CERTS_DIR, keyfile)

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))

        self.db["issued"].append({
            "cn": subject_data["Common Name (CN)"],
            "path": cert_path,
            "serial": str(cert.serial_number),
            "revoked": False
        })
        saveJson(self.db, DB_PATH)

    def revoke_cert(self, serial):
        for cert in self.db["issued"]:
            if str(cert["serial"]) == serial:
                cert["revoked"] = True
                self.db["revoked"].append(cert)
        saveJson(self.db, DB_PATH)
        self.generate_crl()

    def generate_crl(self):
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            self.cert.subject
        ).last_update(datetime.now(UTC)).next_update(datetime.now(UTC) + timedelta(days=7))

        for revoked in self.db["revoked"]:
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                int(revoked["serial"])
            ).revocation_date(datetime.now(UTC)
            ).build()
            
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())
        with open(CRL_PATH, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))


# ====== GUI ======
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CA GUI")
        self.layout = QVBoxLayout()

        # Buttons
        self.btn_create_ca = QPushButton("Create CA")
        self.btn_reset = QPushButton("Reset")
        self.btn_issue_cert = QPushButton("Issue certificate")
        self.btn_revoke_cert = QPushButton("Revoke certificate")
        self.btn_show_details = QPushButton("Show details")
        self.log_label = QLabel("Log:")
        self.log = QTextEdit()
        self.log.setReadOnly(True)

        # Certificates table
        self.cert_table = QTableWidget()
        self.cert_table.setColumnCount(4)
        self.cert_table.setHorizontalHeaderLabels(["CN", "Serial number", "State", "Valid until"])
        self.cert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.cert_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.cert_table.setSelectionMode(QTableWidget.SingleSelection)
        # Column behavior
        self.cert_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.cert_table.horizontalHeader().setStretchLastSection(True)

        # Buttons layout
        btn_row_layout = QHBoxLayout()
        btn_row_layout.addWidget(self.btn_create_ca)
        btn_row_layout.addWidget(self.btn_reset)
        btn_row_layout.addWidget(self.btn_issue_cert)
        btn_row_layout.addWidget(self.btn_revoke_cert)
        btn_row_layout.addWidget(self.btn_show_details)
        btn_row_layout.addStretch()

        # Widget layout
        self.layout.addLayout(btn_row_layout)
        self.layout.addWidget(QLabel("Certificate list:"))
        self.layout.addWidget(self.cert_table)
        self.layout.addWidget(self.log_label)
        self.layout.addWidget(self.log)
        self.setLayout(self.layout)

        # Connect signals
        self.btn_create_ca.clicked.connect(self.createCa)
        self.btn_reset.clicked.connect(self.resetAll)
        self.btn_issue_cert.clicked.connect(self.issueCert)
        self.btn_revoke_cert.clicked.connect(self.revokeCert)
        self.btn_show_details.clicked.connect(self.showCertDetails)

        if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
            self.ca = CertificateAuthority()
            self.logMsg("CA loaded.")
            self.setCaButtonsState(ca_loaded=True)
            self.refreshTable()
        else:
            self.ca = None
            self.setCaButtonsState(ca_loaded=False)
            self.logMsg("No CA found, please create one.")
        

    def logMsg(self, msg):
        self.log.append(msg)

    def createCa(self):
        subject_data = self.getFormData()
        if subject_data:
            self.ca = CertificateAuthority(subject_data)
            self.logMsg("CA created.")
            self.setCaButtonsState(ca_loaded=True)
            self.refreshTable()
        else:
            raise ValueError("Invalid subject data.")
    
    def setCaButtonsState(self, ca_loaded=False):
        self.btn_create_ca.setEnabled(not ca_loaded)
        self.btn_reset.setEnabled(ca_loaded)
        self.btn_issue_cert.setEnabled(ca_loaded)
        self.btn_revoke_cert.setEnabled(ca_loaded)
        self.btn_show_details.setEnabled(ca_loaded)

    def resetAll(self):
        reply = QMessageBox.question(
            self,
            "Confirm Reset",
            "Are you sure you want to reset the CA? This will delete all certificates, the CA, and the database.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.No:
            self.logMsg("Reset canceled.")
            return
        
        # Delete CA key and cert
        if os.path.exists(CA_KEY_PATH):
            os.remove(CA_KEY_PATH)
        if os.path.exists(CA_CERT_PATH):
            os.remove(CA_CERT_PATH)

        # Delete all certificates
        for cert in os.listdir(CERTS_DIR):
            os.remove(os.path.join(CERTS_DIR, cert))

        # Delete CRL
        if os.path.exists(CRL_PATH):
            os.remove(CRL_PATH)
        
        # Delete database
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        self.cert_table.setRowCount(0)
        self.ca = None
        
        self.setCaButtonsState(ca_loaded=False)
        self.logMsg("CA, all certificates and database deleted.")

    def issueCert(self):
        if not self.ca.cert:
            QMessageBox.warning(self, "Error", "No CA loaded.")
            return

        form = self.getFormData()
        if form:
            if any(cert["cn"] == form["Common Name (CN)"] for cert in self.ca.db["issued"]):
                QMessageBox.warning(self, "Error", "Certificate with this CN already exists.")
                return
            self.ca.issue_cert(form)
            self.logMsg(f"Issued certificate for {form['Common Name (CN)']}.")
            self.refreshTable()

    def revokeCert(self):
        row = self.cert_table.currentRow()
        if row < 0:
            return
        if self.cert_table.item(row, 2).text() == "REVOKED":
            QMessageBox.warning(self, "Error", "Certificate already revoked.")
            return
        serial = self.cert_table.item(row, 1).text()
        self.ca.revoke_cert(serial)
        self.logMsg(f"Certicate {serial} revoked.")
        self.refreshTable()

    def refreshTable(self):
        self.cert_table.setRowCount(0)
        for cert in self.ca.db["issued"]:
            row = self.cert_table.rowCount()
            self.cert_table.insertRow(row)

            cn_item = QTableWidgetItem(cert["cn"])
            self.cert_table.setItem(row, 0, cn_item)

            serial_item = QTableWidgetItem(cert["serial"])
            self.cert_table.setItem(row, 1, serial_item)

            status = "REVOKED" if cert.get("revoked", False) else "VALID"
            status_item = QTableWidgetItem(status)
            self.cert_table.setItem(row, 2, status_item)

            try:
                with open(cert["path"], "rb") as f:
                    xcert = x509.load_pem_x509_certificate(f.read())
                    valid_to = xcert.not_valid_after_utc.strftime("%Y-%m-%d")
            except Exception:
                valid_to = "N/A"

            valid_item = QTableWidgetItem(valid_to)
            self.cert_table.setItem(row, 3, valid_item)

    def getFormData(self):
        dialog = QWidget()
        form = QFormLayout(dialog)

        inputs = {
            "Country": QLineEdit("CZ"),
            "State": QLineEdit("Ostrava"),
            "Locality": QLineEdit("Ostrava"),
            "Organization name": QLineEdit("VSB"),
            "Common Name (CN)": QLineEdit("www.example.com")
        }

        for label, widget in inputs.items():
            form.addRow(label, widget)

        btn = QPushButton("OK")
        btn.clicked.connect(dialog.close)
        form.addWidget(btn)

        dialog.setLayout(form)
        dialog.setWindowTitle("Zadej informace")
        dialog.setGeometry(300, 300, 300, 200)
        dialog.exec = lambda: None  # pro jednoduchost
        dialog.show()
        app.processEvents()
        while dialog.isVisible():
            app.processEvents()

        return {k: w.text() for k, w in inputs.items()}

    def showCertDetails(self):
        row = self.cert_table.currentRow()
        if row < 0:
            return

        serial = self.cert_table.item(row, 1).text()
        cert_info = next((c for c in self.ca.db["issued"] if c["serial"] == serial), None)
        if not cert_info:
            QMessageBox.warning(self, "Error", "Certificate not found.")
            return

        try:
            with open(cert_info["path"], "rb") as f:
                xcert = x509.load_pem_x509_certificate(f.read())

            info = {
                "CN": cert_info["cn"],
                "Serial number": xcert.serial_number,
                "Issued": xcert.not_valid_before_utc,
                "Valid until": xcert.not_valid_after_utc,
                "Issuer": xcert.issuer.rfc4514_string(),
                "Subject": xcert.subject.rfc4514_string()
            }
            info_str = "\n".join([f"{k}: {v}" for k, v in info.items()])

            QMessageBox.information(self, "Certificate details", info_str)
        except Exception as e:
            QMessageBox.critical(self, "Error while reading certificate", str(e))

# ====== launch ======
app = QApplication(sys.argv)
window = MainWindow()
window.resize(600, 500)
window.show()
sys.exit(app.exec())

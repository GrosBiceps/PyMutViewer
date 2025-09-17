import sys
import os
import re
import io
import json
import time
import hashlib
import tempfile
import webbrowser
import warnings
import shutil
import base64
import requests
import ipaddress
from typing import Dict, List, Optional, Union

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    yaml = None
    HAVE_YAML = False

# ----------------------------------------------------------------------------------------------------------------------
# Système de configuration externe (YAML)
# ----------------------------------------------------------------------------------------------------------------------

class ConfigError(Exception):
    """Exception personnalisée pour les erreurs de configuration"""
    pass


class AppConfig:
    """Gestionnaire de configuration de l'application via config.yaml"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.config: Dict = {}
        self.load_and_validate()
    
    def load_and_validate(self) -> None:
        """Charge et valide la configuration depuis le fichier YAML"""
        if not HAVE_YAML:
            raise ConfigError(
                "PyYAML n'est pas installé. Installez-le avec: pip install pyyaml"
            )
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            raise ConfigError(
                f"Fichier de configuration '{self.config_file}' introuvable. "
                f"Copiez 'config.example.yaml' vers '{self.config_file}' et adaptez-le."
            )
        except yaml.YAMLError as e:
            raise ConfigError(f"Erreur de parsing YAML dans '{self.config_file}': {e}")
        except Exception as e:
            raise ConfigError(f"Erreur lors de la lecture de '{self.config_file}': {e}")
        
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Valide la structure et les valeurs de la configuration"""
        errors = []
        
        proxy_config = self.config.get('proxy', {})
        if not isinstance(proxy_config, dict):
            errors.append("La section 'proxy' doit être un dictionnaire")
        else:
            use_proxy = proxy_config.get('use_chu_proxy', False)
            if not isinstance(use_proxy, bool):
                errors.append("'proxy.use_chu_proxy' doit être un booléen (true/false)")
            
            if use_proxy:
                proxy_selected = proxy_config.get('proxy_selected')
                if not proxy_selected or not isinstance(proxy_selected, str):
                    errors.append("'proxy.proxy_selected' est requis et doit être une chaîne quand use_chu_proxy=true")
                
                proxies = proxy_config.get('proxies', {})
                if not isinstance(proxies, dict):
                    errors.append("'proxy.proxies' doit être un dictionnaire")
                elif proxy_selected and proxy_selected not in proxies:
                    errors.append(f"Le proxy sélectionné '{proxy_selected}' n'existe pas dans 'proxy.proxies'")
                else:
                    for proxy_name, proxy_conf in proxies.items():
                        if not isinstance(proxy_conf, dict):
                            errors.append(f"La configuration du proxy '{proxy_name}' doit être un dictionnaire")
                            continue
                        
                        for protocol in ['http', 'https']:
                            url = proxy_conf.get(protocol)
                            if not url or not isinstance(url, str):
                                errors.append(f"'{protocol}' manquant ou invalide pour le proxy '{proxy_name}'")
                            elif not url.startswith(('http://', 'https://')):
                                errors.append(f"URL {protocol} invalide pour le proxy '{proxy_name}': doit commencer par http:// ou https://")
        
        server_config = self.config.get('server', {})
        if not isinstance(server_config, dict):
            errors.append("La section 'server' doit être un dictionnaire")
        else:
            ip = server_config.get('ip', '127.0.0.1')
            if not isinstance(ip, str):
                errors.append("'server.ip' doit être une chaîne")
            else:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    errors.append(f"'server.ip' n'est pas une adresse IP valide: {ip}")
            
            port = server_config.get('port', 8123)
            if not isinstance(port, int):
                errors.append("'server.port' doit être un entier")
            elif not (1 <= port <= 65535):
                errors.append(f"'server.port' doit être entre 1 et 65535, trouvé: {port}")
            
            allowed_ips = server_config.get('allowed_ips', [])
            if not isinstance(allowed_ips, list):
                errors.append("'server.allowed_ips' doit être une liste")
            else:
                for i, allowed_ip in enumerate(allowed_ips):
                    if not isinstance(allowed_ip, str):
                        errors.append(f"'server.allowed_ips[{i}]' doit être une chaîne")
                    else:
                        try:
                            ipaddress.ip_address(allowed_ip)
                        except ValueError:
                            errors.append(f"'server.allowed_ips[{i}]' n'est pas une adresse IP valide: {allowed_ip}")
        
        if errors:
            raise ConfigError("Erreurs de configuration:\n" + "\n".join(f"  - {error}" for error in errors))
    
    @property
    def use_chu_proxy(self) -> bool:
        """Retourne True si les proxies CHU doivent être utilisés"""
        return self.config.get('proxy', {}).get('use_chu_proxy', False)
    
    @property
    def proxy_selected(self) -> Optional[str]:
        """Retourne le nom du proxy sélectionné"""
        return self.config.get('proxy', {}).get('proxy_selected')
    
    @property
    def proxies(self) -> Dict[str, Dict[str, str]]:
        """Retourne le dictionnaire des proxies disponibles"""
        return self.config.get('proxy', {}).get('proxies', {})
    
    @property
    def server_ip(self) -> str:
        """Retourne l'IP du serveur"""
        return self.config.get('server', {}).get('ip', '127.0.0.1')
    
    @property
    def server_port(self) -> int:
        """Retourne le port du serveur"""
        return self.config.get('server', {}).get('port', 8123)
    
    @property
    def server_token(self) -> Optional[str]:
        """Retourne le token d'authentification du serveur"""
        return self.config.get('server', {}).get('token')
    
    @property
    def allowed_ips(self) -> List[str]:
        """Retourne la liste des IPs autorisées"""
        return self.config.get('server', {}).get('allowed_ips', ['127.0.0.1', '::1'])
    
    @property
    def http_timeout(self) -> int:
        """Retourne le timeout HTTP par défaut"""
        return self.config.get('application', {}).get('http_timeout', 180)
    
    @property
    def http_retries(self) -> int:
        """Retourne le nombre de tentatives de reconnexion"""
        return self.config.get('application', {}).get('http_retries', 3)
    
    @property
    def app_title(self) -> str:
        """Retourne le titre de l'application"""
        return self.config.get('application', {}).get('title', 'MutViewer - Visualiseur de mutations 3D')
    
    def get_proxy_config(self) -> Optional[Dict[str, str]]:
        """
        Retourne la configuration proxy à utiliser avec requests.
        None si les proxies ne doivent pas être utilisés.
        """
        if not self.use_chu_proxy:
            return None
        
        selected_proxy = self.proxies.get(self.proxy_selected)
        if not selected_proxy:
            raise ConfigError(f"Proxy sélectionné '{self.proxy_selected}' introuvable dans la configuration")
        
        return selected_proxy


try:
    APP_CONFIG = AppConfig()
    print(f"[Configuration] Chargée depuis '{APP_CONFIG.config_file}'")
    if APP_CONFIG.use_chu_proxy:
        print(f"[Configuration] Proxy CHU activé: {APP_CONFIG.proxy_selected}")
    else:
        print("[Configuration] Proxy CHU désactivé")
    print(f"[Configuration] Serveur: {APP_CONFIG.server_ip}:{APP_CONFIG.server_port}")
except ConfigError as e:
    print(f"ERREUR DE CONFIGURATION: {e}")
    print("\nVeuillez corriger la configuration avant de continuer.")
    print("Consultez 'config.example.yaml' pour un exemple de configuration valide.")
    sys.exit(1)
except Exception as e:
    print(f"ERREUR INATTENDUE lors du chargement de la configuration: {e}")
    sys.exit(1)

USE_CHU_PROXY = APP_CONFIG.use_chu_proxy
APP_TITLE = APP_CONFIG.app_title

try:
    import PyPDF2
    HAVE_PYPDF2 = True
except ImportError:
    PyPDF2 = None
    HAVE_PYPDF2 = False

try:
    import pandas as pd
except Exception:
    pd = None

# ----------------------------------------------------------------------------------------------------------------------
# Réglages Qt (environnement verrouillé)
# ----------------------------------------------------------------------------------------------------------------------
os.environ.setdefault('QT_OPENGL', 'software')
os.environ.setdefault('QTWEBENGINE_DISABLE_SANDBOX', '1')
os.environ.setdefault('QTWEBENGINE_CHROMIUM_FLAGS', '--disable-gpu --use-angle=swiftshader --ignore-gpu-blocklist --disable-software-rasterizer')

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from urllib.parse import quote, quote_plus
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt, QUrl, QSizeF
from PyQt5.QtWidgets import (
    QApplication, QWidget, QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox, QGroupBox, QCheckBox,
    QSizePolicy, QSplitter, QFrame, QComboBox, QProgressDialog, QFileDialog,
    QFormLayout, QTextEdit, QScrollArea, QDesktopWidget,
    QDoubleSpinBox, QRadioButton
)

# =====================================================================
# Modern UI theme (minimal, professional)
# =====================================================================

MODERN_QSS = """
/* ====== Base ====== */
QWidget {
  font-family: "Segoe UI", "Inter", "Roboto", "Helvetica Neue", Arial;
  font-size: 15px;
  color: #0f172a;
  background: #f6f8fb;
  selection-background-color: transparent !important;
  selection-color: #0f172a !important;
}

/* Override any system selection colors completely */
QApplication {
  selection-background-color: transparent !important;
}

/* Remove text selection highlighting globally */
* {
  selection-background-color: transparent !important;
  selection-color: #0f172a !important;
  outline: none !important;
}

/* Additional rules to prevent any blue backgrounds */
QWidget:focus {
  background: transparent !important;
  outline: none !important;
}
QWidget:selected {
  background: transparent !important;
  outline: none !important;
}

/* GroupBox = cards */
QGroupBox {
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  margin-top: 16px;
}
QGroupBox::title {
  subcontrol-origin: margin;
  subcontrol-position: top left;
  left: 12px;
  padding: 0 6px;
  color: %%PRIMARY_DARK%%;
  font-weight: 600;
  font-size: 16px;
  background: transparent;
}

/* Buttons */
QPushButton {
  background: #ffffff;
  border: 1px solid #d0d7de;
  border-radius: 6px;
  padding: 6px 12px;
  min-height: 28px;
  font-size: 14px;
  outline: none;
}
QPushButton:hover { background: #f6f8fa; }
QPushButton:pressed { background: #eef2f7; }
QPushButton:disabled { color: #94a3b8; border-color: #e2e8f0; }
QPushButton:focus { outline: none; }

/* Primary button via property: type="primary" */
QPushButton[type="primary"] {
  background: %%PRIMARY%%;
  color: #ffffff;
  border: 1px solid %%PRIMARY_DARK%%;
}
QPushButton[type="primary"]:hover   { background: %%PRIMARY_HOVER%%; }
QPushButton[type="primary"]:pressed { background: %%PRIMARY_PRESSED%%; }

/* Inputs */
QLineEdit, QComboBox, QTextEdit, QSpinBox, QDoubleSpinBox {
  background: #ffffff;
  border: 1px solid #d0d7de;
  border-radius: 8px;
  padding: 8px 10px;
  min-height: 32px;
  font-size: 15px;
  selection-background-color: rgba(44, 90, 160, 0.2);
  selection-color: #0f172a;
}
QLineEdit:focus, QComboBox:focus, QTextEdit:focus,
QSpinBox:focus, QDoubleSpinBox:focus {
  border: 1px solid %%PRIMARY%%;
  outline: none;
}

/* ComboBox */
QComboBox::drop-down { width: 26px; border: 0; }
QComboBox::down-arrow { width: 10px; height: 10px; }

/* ProgressBar */
QProgressBar {
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  background: #ffffff;
  text-align: center;
}
QProgressBar::chunk {
  background-color: %%PRIMARY%%;
  border-radius: 6px;
}

/* Subtle scrollbars */
QScrollBar:vertical   { width: 10px; background: transparent; margin: 4px; }
QScrollBar::handle:vertical   { background: #cbd5e1; min-height: 30px; border-radius: 5px; }
QScrollBar::handle:vertical:hover { background: #94a3b8; }
QScrollBar:horizontal { height: 10px; background: transparent; margin: 4px; }
QScrollBar::handle:horizontal { background: #cbd5e1; min-width: 30px; border-radius: 5px; }

/* ScrollArea styling */
QScrollArea {
  border: none;
  background: transparent;
}
QScrollArea > QWidget > QWidget {
  background: transparent;
}

/* Tables / lists - completely remove selection highlighting */
QTableView, QListView, QTreeView {
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  selection-background-color: transparent !important;
  selection-color: #0f172a !important;
  outline: none !important;
}
QTableView::item, QListView::item, QTreeView::item {
  selection-background-color: transparent !important;
  selection-color: #0f172a !important;
  outline: none !important;
  background: transparent !important;
}
QTableView::item:selected, QListView::item:selected, QTreeView::item:selected {
  background: transparent !important;
  color: #0f172a !important;
  outline: none !important;
}
QTableView::item:hover, QListView::item:hover, QTreeView::item:hover {
  background: #f6f8fa !important;
  color: #0f172a !important;
  outline: none !important;
}

/* Additional rules for text selection in all widgets */
QTextEdit, QPlainTextEdit, QLineEdit {
  selection-background-color: rgba(44, 90, 160, 0.15) !important;
  selection-color: #0f172a !important;
  background: #ffffff !important;
}
QTextEdit:focus, QPlainTextEdit:focus {
  background: #ffffff !important;
  outline: none !important;
}

/* Labels and other text elements */
QLabel {
  selection-background-color: transparent !important;
  selection-color: #0f172a !important;
  outline: none !important;
  font-size: 15px;
  background: transparent !important;
}
QLabel:focus {
  background: transparent !important;
  outline: none !important;
}
QLabel:selected {
  background: transparent !important;
  outline: none !important;
}

/* Tooltips */
QToolTip {
  background: #0f172a;
  color: #ffffff;
  padding: 6px 8px;
  border-radius: 6px;
}
"""

def _mix_color(hex1: str, hex2: str, a: float) -> str:
    """Mix two hex colors with alpha blending"""
    def hex_to_rgb(h): return tuple(int(h[i:i+2], 16) for i in (1, 3, 5))
    def rgb_to_hex(r, g, b): return f"#{r:02x}{g:02x}{b:02x}"
    r1, g1, b1 = hex_to_rgb(hex1)
    r2, g2, b2 = hex_to_rgb(hex2)
    return rgb_to_hex(int(r1*(1-a) + r2*a), int(g1*(1-a) + g2*a), int(b1*(1-a) + b2*a))

def apply_modern_theme(app, primary: str = "#2c5aa0"):
    """Apply modern theme with custom primary color"""
    app.setStyle('Fusion')
    
    primary_hover = _mix_color(primary, "#000000", 0.1)
    primary_pressed = _mix_color(primary, "#000000", 0.2)
    primary_dark = _mix_color(primary, "#000000", 0.3)
    primary_10 = _mix_color(primary, "#ffffff", 0.9)
    
    qss = MODERN_QSS.replace("%%PRIMARY%%", primary)\
                   .replace("%%PRIMARY_HOVER%%", primary_hover)\
                   .replace("%%PRIMARY_PRESSED%%", primary_pressed)\
                   .replace("%%PRIMARY_DARK%%", primary_dark)\
                   .replace("%%PRIMARY_10%%", primary_10)
    
    app.setStyleSheet(qss)

def set_tab_as_navrail(tabs):
    """Configure tabs as horizontal navigation rail"""
    tabs.setTabPosition(QTabWidget.North)
    
    tabs.setStyleSheet("""
        QTabWidget::pane {
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            background: #ffffff;
            margin-top: 0px;
        }
        QTabWidget::tab-bar {
            alignment: left;
        }
        QTabBar::tab {
            background: #f8f9fa;
            border: 1px solid #e5e7eb;
            border-bottom: none;
            border-radius: 10px 10px 0 0;
            padding: 12px 20px;
            margin-right: 3px;
            font-weight: 500;
            font-size: 15px;
            min-width: 120px;
            max-width: 200px;
            min-height: 18px;
            color: #6b7280;
            text-align: center;
        }
        QTabBar::tab:selected {
            background: #ffffff;
            color: #2c5aa0;
            border-color: #2c5aa0;
            font-weight: 600;
        }
        QTabBar::tab:hover:!selected {
            background: #f1f5f9;
            color: #374151;
        }
        QTabBar::tab:!selected {
            margin-top: 2px;
        }
    """)

def mark_primary(root_widget):
    """Mark primary buttons in a widget tree"""
    for child in root_widget.findChildren(QPushButton):
        if any(word in child.text().lower() for word in ['valider', 'exporter', 'lancer', 'générer']):
            child.setProperty("type", "primary")
    root_widget.style().unpolish(root_widget)
    root_widget.style().polish(root_widget)

# ----------------------------------------------------------------------------------------------------------------------
# py3Dmol offline local
# ----------------------------------------------------------------------------------------------------------------------
PY3DMOL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'Assets', '3Dmol.js-master', 'py3Dmol'))
if PY3DMOL_DIR not in sys.path:
    sys.path.insert(0, PY3DMOL_DIR)

THREEDMOL_JS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'Assets', '3Dmol.js-master', 'build', '3Dmol-min.js'))

try:
    import py3Dmol
    HAVE_PY3DMOL = True
except Exception as e:
    print("[Info] py3Dmol non disponible en local:", e)
    HAVE_PY3DMOL = False

def inject_3dmol_tag(html: str) -> str:
    placeholder = '{THREEDMOL_TAG}'
    if placeholder not in html:
        return html

    local_js = THREEDMOL_JS_PATH
    if os.path.exists(local_js):
        try:
            with open(local_js, 'r', encoding='utf-8') as f:
                js_code = f.read()
            return html.replace(placeholder, '<script>' + js_code + '</script>')
        except Exception as e:
            print('[Info] Inline 3Dmol-min.js a échoué:', e)

        try:
            file_url = 'file:///' + local_js.replace('\\', '/')
            return html.replace(placeholder, '<script src="' + file_url + '"></script>')
        except Exception as e:
            print('[Info] Chemin file:/// 3Dmol-min.js a échoué:', e)

    return html.replace(placeholder, '')


warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

APP_VERSION = "1.0.0"
DEFAULT_HGVS = "NM_004304.5(ALK):c.3520T>C"

# ----------------------------------------------------------------------------------------------------------------------
# Pipeline HTTP Listener
# ----------------------------------------------------------------------------------------------------------------------
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

class PipelineBridge(QtCore.QObject):
    requestReceived = QtCore.pyqtSignal(dict)

class PipelineHTTPListener(QtCore.QThread):
    """Thread serveur HTTP qui écoute les requêtes de la pipeline"""
    def __init__(self, bridge: 'PipelineBridge', parent=None):
        """
        Initialise le serveur HTTP avec la configuration depuis config.yaml
        
        Args:
            bridge: Pont de communication vers l'interface
            parent: Widget parent Qt
        """
        super().__init__(parent)
        self.bridge = bridge
        
        self.host = APP_CONFIG.server_ip
        self.port = APP_CONFIG.server_port
        self.token = APP_CONFIG.server_token
        self.allowed_ips = set(APP_CONFIG.allowed_ips)
        self.httpd = None
        
        print(f"[Serveur HTTP] Configuration: {self.host}:{self.port}")
        if self.token:
            print("[Serveur HTTP] Authentification par token activée")
        print(f"[Serveur HTTP] IPs autorisées: {list(self.allowed_ips)}")

    def _make_handler(self):
        bridge = self.bridge
        token = self.token
        allowed_ips = self.allowed_ips

        class Handler(BaseHTTPRequestHandler):
            def _auth_ok(self):
                ip_ok = (self.client_address and self.client_address[0] in allowed_ips)
                if not ip_ok:
                    return False
                if token is None:
                    return True
                
                header_token = self.headers.get("X-Auth-Token")
                if header_token == token:
                    return True
                
                parsed = urlparse(self.path)
                qs = parse_qs(parsed.query)
                query_token = (qs.get("X-Auth-Token") or [None])[0]
                return query_token == token

            def _json(self, status, payload):
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode("utf-8"))

            def log_message(self, *args, **kwargs):
                return

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path not in ("/mutviewer/search",):
                    self._json(404, {"ok": False, "error": "endpoint inconnue"})
                    return
                if not self._auth_ok():
                    self._json(403, {"ok": False, "error": "forbidden"})
                    return

                qs = parse_qs(parsed.query)
                get = lambda k: (qs.get(k) or [None])[0]
                payload = {
                    "endpoint": parsed.path,
                    "hgvs":      get("hgvs"),
                    "gene":      get("gene"),
                    "mut":       get("mut"),
                }

                bridge.requestReceived.emit(payload)
                self._json(200, {"ok": True, "queued": True})

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token")
                self.end_headers()

        return Handler

    def run(self):
        Handler = self._make_handler()
        try:
            self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
            print(f"[Pipeline Listener] Serveur démarré sur {self.host}:{self.port}")
            self.httpd.serve_forever()
        except Exception as e:
            print(f"[Pipeline Listener] Erreur serveur: {e}")

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            print("[Pipeline Listener] Serveur arrêté")

# ----------------------------------------------------------------------------------------------------------------------
# Gestion Proxy
# ----------------------------------------------------------------------------------------------------------------------
def resolve_chu_proxy() -> Optional[Dict[str, str]]:
    try:
        return APP_CONFIG.get_proxy_config()
    except Exception as e:
        print(f"[Erreur Proxy] {e}")
        return None

# ----------------------------------------------------------------------------------------------------------------------
# Session HTTP robuste
# ----------------------------------------------------------------------------------------------------------------------
def create_robust_session(timeout: Optional[int] = None, retries: Optional[int] = None) -> requests.Session:
    if timeout is None:
        timeout = APP_CONFIG.http_timeout
    if retries is None:
        retries = APP_CONFIG.http_retries
    
    s = requests.Session()
    
    proxy_config = resolve_chu_proxy()
    if proxy_config:
        s.proxies.update(proxy_config)
        print(f"[Proxy] Activé - Configuration: {proxy_config}")
    else:
        print("[Proxy] Désactivé - Utilisation des proxies système ou aucun proxy")
    
    retry_strategy = Retry(
        total=retries,
        backoff_factor=3,
        status_forcelist=[429, 500, 502, 503, 504, 408, 520, 521, 522, 524],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=15, pool_maxsize=25)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.timeout = timeout
    s.headers.update({
        'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    })
    s.verify = False
    return s

def validate_hgvs_transcript(s: str) -> bool:
    patt = r'^NM_\d+\.\d+\([A-Za-z0-9._-]+\):c\.[0-9_]+.*$'
    return re.match(patt, s.strip()) is not None

def parse_gene_from_entry(hgvs_notation: str) -> str:
    m = re.search(r'\(([^)]+)\)', hgvs_notation)
    return m.group(1) if m else ""

def vep_hgvs_fast(hgvs_notation: str, progress_callback=None) -> dict:
    cleaned = re.sub(r'\([^)]+\)', '', hgvs_notation)
    url = f"https://rest.ensembl.org/vep/human/hgvs/{quote(cleaned, safe='')}"
    params = {"canonical": 1, "protein": 1, "hgvs": 1, "uniprot": 1, "numbers": 1, "variant_class": 1}
    if progress_callback: progress_callback("Appel VEP (Ensembl)…")
    s = create_robust_session(timeout=120, retries=2)
    r = s.get(url, headers={"Accept":"application/json"}, params=params)
    r.raise_for_status()
    data = r.json()
    s.close()
    if isinstance(data, list) and data: data = data[0]
    tcs_all = []
    tcs = data.get("transcript_consequences") or []
    if not tcs:
        tcs_all.append(data)
    else:
        for tc in tcs:
            merged = {**data, **tc}
            tcs_all.append(merged)
    def key(rec):
        canon = 1 if str(rec.get("canonical","")).lower() in ["1","true","yes"] else 0
        impact = {"HIGH":3, "MODERATE":2, "LOW":1}.get(str(rec.get("impact","")).upper(), 0)
        return (canon, impact)
    best = sorted(tcs_all, key=key, reverse=True)[0]
    out = {
        "protein_hgvs": best.get("HGVSp") or best.get("hgvsp"),
        "protein_id": best.get("protein_id"),
        "amino_acids": best.get("amino_acids"),
        "protein_start": best.get("protein_start"),
        "uniprot": None
    }
    for k in ("swissprot","uniprot_isoform","uniprot_acc","uniprot_id"):
        v = best.get(k)
        if isinstance(v,str) and v: out["uniprot"] = v; break
    if not out["uniprot"] and out.get("protein_id"):
        try:
            s = create_robust_session(timeout=60, retries=2)
            xx = s.get(f"https://rest.ensembl.org/xrefs/id/{out['protein_id']}", headers={"Accept":"application/json"})
            if xx.status_code == 200:
                for row in xx.json():
                    if row.get("dbname") in ["Uniprot/SWISSPROT","UniProtKB/Swiss-Prot"]:
                        out["uniprot"] = row.get("primary_id"); break
            s.close()
        except Exception:
            pass
    return out

def fetch_alphafold_pdb(uniprot_id: str, timeout=180) -> str:
    url = f"https://alphafold.ebi.ac.uk/files/AF-{uniprot_id}-F1-model_v4.pdb"
    s = create_robust_session(timeout=timeout, retries=2)
    r = s.get(url)
    r.raise_for_status()
    text = r.text
    s.close()
    return text

def fetch_uniprot_features(uniprot_id: str, timeout=180):
    if pd is None: return None
    url = f"https://rest.uniprot.org/uniprotkb/{uniprot_id}.json"
    s = create_robust_session(timeout=timeout, retries=2)
    r = s.get(url, headers={"Accept":"application/json"})
    r.raise_for_status(); data = r.json(); s.close()
    feats = data.get("features", [])
    rows = []
    for feat in feats:
        ftype = (feat.get("type","") or "").replace(" ","_").upper()
        loc = feat.get("location", {}) or {}
        start = (loc.get("start") or {}).get("value")
        end = (loc.get("end") or {}).get("value")
        if start is None or end is None: continue
        desc = feat.get("description") or ""
        if not desc and "note" in feat:
            note = feat["note"]
            if isinstance(note, dict):
                desc = (note.get("texts", [{}])[0] or {}).get("value", "")
            else:
                desc = str(note)
        rows.append({"type": ftype, "start": int(start), "end": int(end), "description": desc or f"{ftype} region"})
    df = pd.DataFrame(rows)
    if not df.empty:
        df["length"] = df["end"] - df["start"] + 1
    return df

AA3_TO_1 = {'Ala':'A','Arg':'R','Asn':'N','Asp':'D','Cys':'C','Gln':'Q','Glu':'E','Gly':'G','His':'H','Ile':'I','Leu':'L','Lys':'K','Met':'M','Phe':'F','Pro':'P','Ser':'S','Thr':'T','Trp':'W','Tyr':'Y','Val':'V'}
AA1_TO_3 = {v:k for k,v in AA3_TO_1.items()}

def parse_hgvsp_to_parts(hgvsp: str):
    if not hgvsp:
        return None, None, None
    s = hgvsp.strip()
    if ":" in s:
        s = s.split(":")[-1]
    s = s.strip()
    s = s.replace("p.", "").replace("(", "").replace(")", "").strip()
    m = re.match(r'([A-Z][a-z]{2})(\d+)([A-Z][a-z]{2})', s)
    if m:
        orig3, pos, mut3 = m.group(1), int(m.group(2)), m.group(3)
        return orig3, pos, mut3
    m = re.match(r'([A-Z])(\d+)([A-Z])', s)
    if m:
        o1, pos, m1 = m.group(1), int(m.group(2)), m.group(3)
        orig3 = AA1_TO_3.get(o1, None)
        mut3  = AA1_TO_3.get(m1, None)
        return orig3, pos, mut3
    return None, None, None

def extract_amino_acids_and_position(hgvsp: str):
    if not hgvsp:
        return None, None, None, None
    s = hgvsp.strip()
    if ":" in s:
        s = s.split(":")[-1]
    clean = s.replace('p.', '').replace('(', '').replace(')', '').strip()
    m = re.match(r'([A-Z][a-z]{2})(\d+)([A-Z][a-z]{2})', clean)
    if m:
        aa_from_3, position, aa_to_3 = m.groups()
        aa_from_1 = AA3_TO_1.get(aa_from_3, '?'); aa_to_1 = AA3_TO_1.get(aa_to_3, '?')
        return aa_from_1, int(position), aa_to_1, f"{aa_from_1}{position}{aa_to_1}"
    m = re.match(r'([A-Z])(\d+)([A-Z])', clean)
    if m:
        aa_from_1, position, aa_to_1 = m.groups()
        return aa_from_1, int(position), aa_to_1, f"{aa_from_1}{position}{aa_to_1}"
    return None, None, None, None

# ----------------------------------------------------------------------------------------------------------------------
# 3Dmol.js HTML templates
# ----------------------------------------------------------------------------------------------------------------------

HTML_TMPL = r"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>3D View</title>
<script src="https://unpkg.com/3dmol/build/3Dmol-min.js"></script>
<style>
  * { box-sizing: border-box; }
  html, body { margin:0; padding:0; height:100%; background:#fff; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }
  .wrap { display:flex; height:100vh; width:100vw; overflow:hidden; }
  #viewer { flex:1 1 auto; height:100%; }
  .legend {
    width: 300px; flex: 0 0 300px; border-left: 1px solid #e5e5e5; padding: 16px; background:#fafafa; height:100%;
    display:flex; flex-direction:column; gap:12px;
  }
  .legend h2 { font-size:18px; margin:0 0 8px 0; }
  .subhead { font-weight:600; font-size:15px; margin:0 0 6px 0; }
  .item { display:flex; align-items:center; gap:10px; }
  .swatch { width:20px; height:20px; border-radius:4px; border:1px solid rgba(0,0,0,.1); }
  .swatch.grey { background: lightgrey; }
  .swatch.orange { background: orange; }
  .swatch.label { background: black; position:relative; }
  .swatch.label::after {
    content:"A"; color: yellow; position:absolute; inset:0; display:flex; align-items:center; justify-content:center; font-size:14px;
  }
  .swatch.plddt { background: linear-gradient(90deg, rgb(255,0,0), rgb(255,165,0), rgb(255,255,0), rgb(0,255,255), rgb(0,0,255)); }
  .note { font-size:14px; color:#555; }
  /* ---- Zone scrollable pour les features ---- */
  #legend-types-wrap {
    overflow: auto;
    max-height: 75vh;
    min-height: 100px;
    border: 1px solid #ececec;
    border-radius: 10px;
    background: #fff;
    padding: 8px 10px;
  }
  #legend-types .item { margin: 4px 0; }
  #legend-types .subhead { position: sticky; top: 0; background: #fff; padding: 2px 0 6px 0; z-index: 1; }
  /* Affiner la scrollbar (facultatif, sans dépendances) */
  #legend-types-wrap::-webkit-scrollbar { width: 8px; }
  #legend-types-wrap::-webkit-scrollbar-thumb { background: rgba(0,0,0,.2); border-radius: 8px; }
  #legend-types-wrap::-webkit-scrollbar-track { background: transparent; }
  .meta { margin-top:auto; font-size:14px; color:#666; }
  .mutline { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; background:#f4f4f4; padding:6px 8px; border-radius:6px; display:inline-block; }
</style>
</head>
<body>
<div class="wrap">
  <div id="viewer"></div>
  <aside class="legend">
    <h2>Légende</h2>

    <!-- Structure : mise à jour si pLDDT -->
    <div class="item" id="struct-line">
      <span class="swatch grey" id="struct-swatch"></span>
      <div id="struct-text">Structure (cartoon, gris clair, opacité 0.35)</div>
    </div>

    <!-- Zone scrollable des features -->
    <div id="legend-types-wrap">
      <div id="legend-types"></div>
    </div>

    <div class="item"><span class="swatch orange"></span><div>Résidu muté (sphère sur carbone alpha, orange)</div></div>
    <div class="item"><span class="swatch label"></span><div>Étiquette (texte jaune sur fond noir)</div></div>

    <div class="meta">
      <div><strong>UniProt</strong> : {UNIPROT}</div>
      <div><strong>Mutation</strong> : <span class="mutline">{MUTLINE}</span></div>
    </div>
  </aside>
</div>

<script>
(function(){
  const pdbData = `{PDB_DATA}`;
  const mutation = {MUT_JSON};     // {pos, aa_from, aa_to}
  const selections = {SELECTIONS_JSON};   // [{start,end,type,color,style,opacity}]
  const usePlddt = {USE_PLDDT};           // boolean
  const viewer = new $3Dmol.GLViewer(document.getElementById('viewer'), {backgroundColor:'white'});

  // -------- Helpers pour légende dynamique --------
  function updateLegend(){
      const dyn = document.getElementById('legend-types');
      const structText = document.getElementById('struct-text');
      const structSwatch = document.getElementById('struct-swatch');
      dyn.innerHTML = '';

      if(usePlddt){
          // Adapter la ligne "Structure" et afficher le dégradé pLDDT
          structText.textContent = "Structure (cartoon, pLDDT – 0→100)";
          structSwatch.className = 'swatch plddt';
          structSwatch.title = "pLDDT (0 → 100)";

          const head = document.createElement('div');
          head.className = 'subhead';
          head.textContent = "Mode pLDDT";
          dyn.appendChild(head);

          const item = document.createElement('div');
          item.className = 'item';
          item.innerHTML = '<span class="swatch plddt"></span><div>Coloration pLDDT (faible → forte confiance)</div>';
          dyn.appendChild(item);
      } else {
          // Remettre la ligne "Structure" par défaut
          structText.textContent = "Structure (cartoon, gris clair, opacité 0.35)";
          structSwatch.className = 'swatch grey';
          structSwatch.removeAttribute('title');

          // Regrouper par type + compter
          const byType = {};
          (selections || []).forEach(s=>{
              if(!s || !s.type) return;
              if(!byType[s.type]) byType[s.type] = {color:s.color || '#377eb8', count:0, style:s.style || 'cartoon'};
              byType[s.type].count += 1;
          });

          const types = Object.keys(byType).sort();
          if(types.length){
              const head = document.createElement('div');
              head.className = 'subhead';
              head.textContent = "Features UniProt sélectionnées";
              dyn.appendChild(head);

              types.forEach(t=>{
                  const item = document.createElement('div');
                  item.className = 'item';
                  const info = byType[t];
                  item.innerHTML = `<span class="swatch" style="background:${info.color}"></span><div>${t} (${info.count})</div>`;
                  dyn.appendChild(item);
              });
          } else {
              const note = document.createElement('div');
              note.className = 'note';
              note.textContent = "Aucune feature sélectionnée.";
              dyn.appendChild(note);
          }
      }
  }

  // -------- Chargement de la structure et styles --------
  viewer.addModel(pdbData, 'pdb');

  function colorFromB(b){
      // Dégradé simplifié (approximation AlphaFold : rouge→orange→jaune→cyan→bleu)
      const v = Math.max(0, Math.min(100, b||0));
      if (v < 50) { // rouge -> orange
        const t = v/50.0;
        const r = 255;
        const g = Math.floor(165 * t);
        const bl = 0;
        return 'rgb('+r+','+g+','+bl+')';
      } else if (v < 70) { // orange -> jaune
        const t = (v-50)/20.0;
        const r = 255;
        const g = 165 + Math.floor((255-165)*t);
        const bl = 0;
        return 'rgb('+r+','+g+','+bl+')';
      } else if (v < 90) { // jaune -> cyan
        const t = (v-70)/20.0;
        const r = 255 - Math.floor(255*t);
        const g = 255;
        const bl = Math.floor(255*t);
        return 'rgb('+r+','+g+','+bl+')';
      } else { // cyan -> bleu
        const t = (v-90)/10.0;
        const r = 0;
        const g = 255 - Math.floor(255*t);
        const bl = 255;
        return 'rgb('+r+','+g+','+bl+')';
      }
  }

  if(usePlddt){
    viewer.setStyle({}, {cartoon:{colorfunc: function(atom){ return colorFromB(atom.b); }, opacity:0.9}});
  } else {
    viewer.setStyle({}, {cartoon:{color:'lightgrey', opacity:0.35}});
    // Dessin des features sélectionnées
    (selections||[]).forEach(f=>{
        const sel = (f.start===f.end) ? {resi:f.start} : {resi: f.start + '-' + f.end};
        const color = f.color || 'blue';
        const op = f.opacity==null ? 1.0 : f.opacity;
        let style = {};
        if(f.style==='surface'){ style.surface = {opacity: op, color: color}; }
        else if(f.style==='stick'){ style.stick = {radius:0.4, color: color}; }
        else if(f.style==='sphere'){ style.sphere = {radius:1.5, opacity: op, color: color}; }
        else { style.cartoon = {opacity: op, color: color}; }
        viewer.addStyle(sel, style);
    });
  }

  // Mutation - affichage simplifié avec une seule boule sur le carbone alpha
  if(mutation && mutation.pos){
      // Sélection du carbone alpha uniquement pour une seule boule
      const selMutCA = {resi: mutation.pos, atom: 'CA'};
      viewer.addStyle(selMutCA, {sphere:{radius:3.0, opacity:0.8, color:'orange'}});
      // Pas d'étiquette encombrante pour la mutation
  }
  
  // Zoom pour voir toute la protéine avec un facteur de dézoom
  viewer.zoomTo();
  viewer.zoom(0.8); // Dézoom de 20% pour voir la protéine entière

  // Construire la légende
  updateLegend();
  viewer.render();
})();
</script>
</body>
</html>
"""

HTML_MINI = r"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"/><script src="https://unpkg.com/3dmol/build/3Dmol-min.js"></script><style>html,body{margin:0;padding:0;height:100%}#viewer{width:100%;height:100%}</style></head>
<body>
<div id="viewer"></div>
<script>
(function(){
  const pdbData = `{PDB_DATA}`;
  const v = new $3Dmol.GLViewer(document.getElementById('viewer'), {backgroundColor:'white'});
  v.addModel(pdbData, 'pdb');
  v.setStyle({}, {cartoon:{color:'white',opacity:0.0}});
  v.zoomTo();
  v.zoom(0.8); // Dézoom pour voir la protéine entière
  v.render();
})();
</script>
</body></html>
"""

# Palette des couleurs
PALETTE = [
    "#e41a1c","#377eb8","#4daf4a","#984ea3","#ff7f00",
    "#ffff33","#a65628","#f781bf","#999999"
]

def get_critical_types(df):
    critical = {'ACTIVE_SITE','BINDING_SITE','METAL_BINDING','DISULFIDE_BOND','DOMAIN','DNA_BINDING','CATALYTIC_ACTIVITY'}
    if df is None or (hasattr(df,"empty") and df.empty): return set()
    return set(df[df['type'].isin(critical)]['type'].unique())

# ----------------------------------------------------------------------------------------------------------------------
# UI Qt
# ----------------------------------------------------------------------------------------------------------------------


def build_selections_from_df(df, type_enabled, style="cartoon", opacity=1):
    sel = []
    if df is None or (hasattr(df, "empty") and df.empty):
        return sel
    uniq_types = sorted(df["type"].unique())
    color_map = {t: PALETTE[i % len(PALETTE)] for i, t in enumerate(uniq_types)}
    for _, row in df.iterrows():
        t = row["type"]
        if t not in type_enabled:
            continue
        sel.append({
            "start": int(row["start"]),
            "end": int(row["end"]),
            "type": t,
            "color": color_map.get(t, "#377eb8"),
            "style": style,
            "opacity": float(opacity)
        })
    return sel





# ----------------------------------------------------------------------------------------------------------------------
# Worker INPS-MD
# ----------------------------------------------------------------------------------------------------------------------
class INPSMDWorker(QtCore.QThread):
    startedJob = QtCore.pyqtSignal(str, str)
    progress   = QtCore.pyqtSignal(str)
    finishedOk = QtCore.pyqtSignal(dict)
    failed     = QtCore.pyqtSignal(str)
    logLine    = QtCore.pyqtSignal(str)
    savedHtml  = QtCore.pyqtSignal(str)

    BASE = "https://inpsmd.biocomp.unibo.it"
    SUBMIT_URL = f"{BASE}/submitstruct/"
    UUID_RE   = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    CSRF_RE   = re.compile(r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']', re.I)
    JSON_RE   = re.compile(r'href="([^"]+\.json)"', re.I)
    TSV_RE    = re.compile(r'href="([^"]+\.tsv)"', re.I)

    def __init__(self, pdb_bytes: bytes, chain: str, mutation: str, poll: bool=True, parent=None):
        super().__init__(parent)
        self.pdb_bytes = pdb_bytes or b""
        self.chain = (chain or "A").strip()[:1]
        self.mutation = (mutation or "").strip()
        self.poll = poll
        self.s = create_robust_session(timeout=180, retries=2)
        self.s.headers.update({
            "User-Agent": "inpsmd-mini/0.4 (+pyqt)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def _log(self, msg: str):
        self.logLine.emit(msg)

    def _get_csrf(self) -> str:
        self._log(f"GET {self.SUBMIT_URL}")
        r = self.s.get(self.SUBMIT_URL, timeout=60)
        self._log(f"<- {r.status_code} {r.reason}; url={r.url}")
        r.raise_for_status()
        m = self.CSRF_RE.search(r.text)
        token = m.group(1) if m else ""
        cookie_token = self.s.cookies.get("csrftoken") or self.s.cookies.get("CSRF-TOKEN") or ""
        if not token:
            fp = tempfile.NamedTemporaryFile(delete=False, suffix="_submit_get.html")
            fp.write(r.content); fp.close()
            self.savedHtml.emit(fp.name)
            raise RuntimeError("CSRF introuvable dans la page de soumission.")
        if not cookie_token:
            raise RuntimeError("Cookie csrftoken absent après GET – soumission bloquée.")
        self._log(f"CSRF ok ({token[:8]}…)")
        return token

    def _find_downloads(self, html: str):
        links = {}
        m = self.JSON_RE.search(html)
        if m: links["json"] = self.BASE + m.group(1) if m.group(1).startswith("/") else m.group(1)
        m = self.TSV_RE.search(html)
        if m: links["tsv"] = self.BASE + m.group(1) if m.group(1).startswith("/") else m.group(1)
        return links

    def run(self):
        try:
            if not self.pdb_bytes:
                raise RuntimeError("PDB vide — rien à envoyer.")
            if not self.chain or len(self.chain) != 1:
                raise RuntimeError("Chaîne invalide (ex: A).")
            if not re.match(r"^[ACDEFGHIKLMNPQRSTVWY]\d+[ACDEFGHIKLMNPQRSTVWY]$", self.mutation):
                self._log("⚠️ Mutation non standard (attendu X123Y).")

            csrf = self._get_csrf()

            sha = hashlib.sha256(self.pdb_bytes).hexdigest()[:12]
            self._log(f"PDB buffer ~{len(self.pdb_bytes)} octets (sha256={sha})")

            files = {"pdb_file": ("structure.pdb", io.BytesIO(self.pdb_bytes), "application/octet-stream")}
            data = {"csrfmiddlewaretoken": csrf, "chain_id": self.chain, "mutations": self.mutation}
            headers = {"Referer": self.SUBMIT_URL, "Origin": self.BASE, "X-CSRFToken": csrf}

            self._log(f"POST {self.SUBMIT_URL} (chain={self.chain}, mut={self.mutation})")
            r = self.s.post(self.SUBMIT_URL, data=data, files=files, headers=headers, timeout=180, allow_redirects=True)
            r.raise_for_status()
            self._log(f"<- {r.status_code}; final url={r.url}")
            job_url = r.url

            if job_url.rstrip('/').endswith('/submitstruct'):
                fp = tempfile.NamedTemporaryFile(delete=False, suffix="_submit_returned.html")
                fp.write(r.content); fp.close()
                self.savedHtml.emit(fp.name)
                raise RuntimeError("Validation échouée (retour sur /submitstruct).")

            m_uuid = self.UUID_RE.search(r.text) or self.UUID_RE.search(job_url)
            job_id = m_uuid.group(0) if m_uuid else ""
            if job_id and ("strresult" not in job_url):
                job_url = f"{self.BASE}/{job_id}/strresult/"

            self.startedJob.emit(job_id, job_url)

            if not self.poll:
                self.finishedOk.emit({})
                return

            deadline = time.time() + 30*60
            while time.time() < deadline:
                self._log(f"GET {job_url} (poll)")
                pg = self.s.get(job_url, timeout=60, allow_redirects=True)
                self._log(f"<- {pg.status_code} {pg.url}")
                pg.raise_for_status()
                links = self._find_downloads(pg.text)
                if links:
                    self._log(f"Résultats: {links}")
                    self.finishedOk.emit(links)
                    return
                self.progress.emit("En cours… nouvelle vérif dans 20 s")
                time.sleep(20)
            raise RuntimeError("Timeout: résultats non disponibles.")
        except Exception as e:
            self.failed.emit(str(e))

# ----------------------------------------------------------------------------------------------------------------------
# DynaMut2 worker
# ----------------------------------------------------------------------------------------------------------------------
class DynaMut2Worker(QtCore.QThread):
    jobStarted = QtCore.pyqtSignal(str)
    jobMessage = QtCore.pyqtSignal(str)
    jobFinished = QtCore.pyqtSignal(dict)
    jobError = QtCore.pyqtSignal(str)

    def __init__(self, pdb_bytes: bytes, chain: str, mutation_code: str, parent=None):
        super().__init__(parent)
        self.pdb_bytes = pdb_bytes
        self.chain = chain
        self.mutation_code = mutation_code
        self._stop = False

    def stop(self): self._stop = True

    def run(self):
        try:
            submit_url = "https://biosig.lab.uq.edu.au/dynamut2/api/prediction_single"
            files = {"pdb_file": ("structure.pdb", self.pdb_bytes, "chemical/x-pdb")}
            data = {"chain": self.chain, "mutation": self.mutation_code}
            s = create_robust_session(timeout=60, retries=2)
            r = s.post(submit_url, files=files, data=data)
            r.raise_for_status()
            j = r.json()
            job_id = j.get("job_id")
            if not job_id:
                raise RuntimeError(f"Soumission invalide: {j}")
            self.jobStarted.emit(job_id)

            get_url = submit_url
            max_attempts = 120; attempts = 0
            while not self._stop and attempts < max_attempts:
                g = s.get(get_url, params={"job_id": job_id})
                g.raise_for_status()
                out = g.json()
                if out.get("message") == "RUNNING":
                    self.jobMessage.emit(f"RUNNING ({attempts+1}/{max_attempts})")
                    time.sleep(5); attempts += 1; continue
                self.jobFinished.emit(out); s.close(); return
            s.close()
            if attempts >= max_attempts: self.jobError.emit("Timeout: job trop long.")
            elif self._stop: self.jobError.emit("Job annulé.")
        except Exception as e:
            self.jobError.emit(str(e))

# ----------------------------------------------------------------------------------------------------------------------
# Onglet Entrée mutation
# ----------------------------------------------------------------------------------------------------------------------
class MutationEntryTab(QWidget):
    mutationValidated = QtCore.pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(30)
        
        main_layout.addStretch(1)
        
        central_widget = QWidget()
        central_widget.setMaximumWidth(800)
        central_widget.setMinimumWidth(600)
        central_layout = QVBoxLayout(central_widget)
        central_layout.setSpacing(25)
        
        title = QLabel("Entrer une mutation (HGVS transcript)")
        title.setStyleSheet("""
            QLabel {
                font-size: 32px;
                font-weight: 600;
                color: #1f2937;
                margin-bottom: 10px;
            }
        """)
        title.setAlignment(Qt.AlignCenter)
        central_layout.addWidget(title)
        
        self.input = QLineEdit(DEFAULT_HGVS)
        self.input.setPlaceholderText("ex: NM_005228.5(EGFR):c.2390G>C")
        self.input.setStyleSheet("""
            QLineEdit {
                font-size: 18px;
                padding: 15px 20px;
                border: 2px solid #d1d5db;
                border-radius: 12px;
                background: #ffffff;
                min-height: 20px;
            }
            QLineEdit:focus {
                border: 2px solid #2c5aa0;
                outline: none;
            }
            QLineEdit:hover {
                border: 2px solid #9ca3af;
            }
        """)
        self.input.returnPressed.connect(self.validate)
        central_layout.addWidget(self.input)
        
        self.btn = QPushButton("Valider")
        self.btn.setStyleSheet("""
            QPushButton {
                background: #2c5aa0;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 32px;
                font-size: 16px;
                font-weight: 600;
                min-height: 16px;
            }
            QPushButton:hover {
                background: #1e40af;
            }
            QPushButton:pressed {
                background: #1e3a8a;
            }
        """)
        self.btn.clicked.connect(self.validate)
        
        button_container = QHBoxLayout()
        button_container.addStretch()
        button_container.addWidget(self.btn)
        button_container.addStretch()
        central_layout.addLayout(button_container)
        
        info = QLabel("Exemple valide: NM_005228.5(EGFR):c.2390G>C")
        info.setStyleSheet("""
            QLabel {
                color: #6b7280;
                font-size: 16px;
                font-style: italic;
                background: #f9fafb;
                padding: 12px 16px;
                border-radius: 8px;
                border: 1px solid #e5e7eb;
            }
        """)
        info.setAlignment(Qt.AlignCenter)
        central_layout.addWidget(info)
        
        container_layout = QHBoxLayout()
        container_layout.addStretch()
        container_layout.addWidget(central_widget)
        container_layout.addStretch()
        main_layout.addLayout(container_layout)
        
        main_layout.addStretch(1)
        
        version_container = QHBoxLayout()
        version_container.addStretch()
        version_label = QLabel(f"Version {APP_VERSION}")
        version_label.setStyleSheet("""
            QLabel {
                color: #9ca3af;
                font-size: 12px;
                font-style: italic;
                padding: 5px;
            }
        """)
        version_container.addWidget(version_label)
        main_layout.addLayout(version_container)

    def validate(self):
        text = self.input.text().strip()
        if not validate_hgvs_transcript(text):
            QMessageBox.warning(self, "Format invalide", "Format attendu (HGVS transcript) :\nNM_005228.5(EGFR):c.2390G>C")
            return
        self.mutationValidated.emit(text)

# ----------------------------------------------------------------------------------------------------------------------
# Onglet Visualisation 3D
# ----------------------------------------------------------------------------------------------------------------------

class FeaturesPanel(QWidget):
    changed = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.type_checks = {}
        self.features_df = pd.DataFrame() if pd is not None else None

        root = QVBoxLayout(self)
        root.setContentsMargins(0,0,0,0)

        box_mode = QGroupBox("Options de visualisation")
        v = QVBoxLayout(box_mode)
        self.mode_normal = QRadioButton("Normal (Features)"); self.mode_plddt = QRadioButton("pLDDT (Confiance)")
        self.mode_normal.setChecked(True)
        self.mode_normal.toggled.connect(self.changed.emit); self.mode_plddt.toggled.connect(self.changed.emit)
        v.addWidget(self.mode_normal); v.addWidget(self.mode_plddt)

        box_feat = QGroupBox("Affichage Features")
        form = QFormLayout(box_feat)
        self.style = QComboBox(); self.style.addItems(["cartoon","surface","stick","sphere"])
        self.opacity = QDoubleSpinBox(); self.opacity.setRange(0.1,1.0); self.opacity.setSingleStep(0.1); self.opacity.setValue(1.0)
        self.style.currentIndexChanged.connect(self.changed.emit); self.opacity.valueChanged.connect(self.changed.emit)
        row_btns = QHBoxLayout()
        self.btn_crit = QPushButton("Critiques uniquement"); self.btn_all = QPushButton("Toutes"); self.btn_none = QPushButton("Aucune")
        self.btn_crit.clicked.connect(self.select_critical_only); self.btn_all.clicked.connect(self.select_all); self.btn_none.clicked.connect(self.select_none)
        form.addRow("Style:", self.style); form.addRow("Opacité:", self.opacity); form.addRow(row_btns)
        row_btns.addWidget(self.btn_crit); row_btns.addWidget(self.btn_all); row_btns.addWidget(self.btn_none)

        box_types = QGroupBox("Types disponibles")
        
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setMaximumHeight(500)
        self.scroll_area.setMinimumHeight(450)
        
        self.types_widget = QWidget()
        self.v_types = QVBoxLayout(self.types_widget)
        self.v_types.setContentsMargins(0, 0, 0, 0)
        self.v_types.setSpacing(2)
        
        self.scroll_area.setWidget(self.types_widget)
        
        types_layout = QVBoxLayout(box_types)
        types_layout.setContentsMargins(5, 10, 5, 5)
        types_layout.addWidget(self.scroll_area)

        root.addWidget(box_mode)
        root.addWidget(box_feat)
        root.addWidget(box_types)
        root.addStretch(1)

        self.setDisabled(True)

    def populate(self, df):
        for i in reversed(range(self.v_types.count())):
            w = self.v_types.itemAt(i).widget()
            if w is not None: w.setParent(None)
        self.type_checks.clear()
        self.features_df = df if df is not None else (pd.DataFrame() if pd is not None else None)
        if df is None or (hasattr(df,"empty") and df.empty):
            self.v_types.addWidget(QLabel("Aucun type trouvé."))
            self.setDisabled(False)
            self.changed.emit()
            return
        counts = df["type"].value_counts()
        for t in sorted(df["type"].unique()):
            cb = QCheckBox(f"{t} ({counts.get(t,0)})")
            cb.stateChanged.connect(self.changed.emit)
            self.type_checks[t] = cb
            self.v_types.addWidget(cb)
        self.setDisabled(False)
        self.changed.emit()

    def enabled_types(self):
        return {t for t, cb in self.type_checks.items() if cb.isChecked()}

    def select_critical_only(self):
        crit = get_critical_types(self.features_df)
        for t, cb in self.type_checks.items():
            cb.setChecked(t in crit)
        self.changed.emit()

    def select_all(self):
        for cb in self.type_checks.values(): cb.setChecked(True)
        self.changed.emit()

    def select_none(self):
        for cb in self.type_checks.values(): cb.setChecked(False)
        self.changed.emit()

    def is_plddt(self): return self.mode_plddt.isChecked()
    def current_style(self): return self.style.currentText()
    def current_opacity(self): return float(self.opacity.value())

class ViewerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.uniprot_id = None
        self.pdb_text = ""
        self.hgvsp = ""
        self.gene = ""
        self.pos = None
        self.aa_from = ""
        self.aa_to = ""
        self._last_html_path = None
        self.features_df = pd.DataFrame() if pd is not None else None

        outer = QVBoxLayout(self)

        hdr = QLabel("<h2>Visualisation 3D (ouverte dans le navigateur)</h2>")
        info = QLabel("Après validation de la mutation, la structure AlphaFold est récupérée et la scène 3D s’ouvre automatiquement dans votre navigateur par défaut. \
La page inclut une légende à droite des couleurs utilisées.")
        info.setWordWrap(True)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.open_browser_btn = QPushButton("Ouvrir dans le navigateur")
        self.open_browser_btn.setEnabled(False)
        self.open_browser_btn.clicked.connect(self.open_in_browser)
        
        self.open_molart_btn = QPushButton("Ouvrir MolArt (PC puissant)")
        self.open_molart_btn.setToolTip("Ouvre la page MolArt locale avec l’ID UniProt détecté")
        self.open_molart_btn.setEnabled(False)
        self.open_molart_btn.clicked.connect(self.open_molart)
        
        btn_row.addWidget(self.open_molart_btn)
        btn_row.addWidget(self.open_browser_btn)

        self.status_lbl = QLabel("En attente…")

        outer.addWidget(hdr)
        outer.addWidget(info)
        outer.addLayout(btn_row)
        outer.addWidget(self.status_lbl)

        self.features_panel = FeaturesPanel()
        self.features_panel.changed.connect(self.regenerate_html_silent)
        outer.addWidget(self.features_panel)
        outer.addStretch(1)

    def _write_html(self, html: str):
        fd, tmp = tempfile.mkstemp(prefix="viewer_", suffix=".html")
        with os.fdopen(fd, "w", encoding="utf-8") as f: f.write(html)
        self._last_html_path = tmp
        self.open_browser_btn.setEnabled(True)

    def open_in_browser(self):
        if self._last_html_path:
            url = "file:///" + self._last_html_path.replace("\\", "/")
            webbrowser.open(url)


    def open_molart(self):
        """Ouvre l'index MolArt local en passant ?uniprot=<ID> automatiquement."""
        if not self.uniprot_id:
            QMessageBox.warning(self, "MolArt", "ID UniProt inconnu – validez d'abord la mutation.")
            return

        base_dir = os.path.dirname(__file__)
        candidates = [
            os.path.join(base_dir, "test_local_mol_art_index.html"),
            os.path.join(base_dir, "Assets", "molart", "index.html"),
            os.path.join(base_dir, "Assets", "MolArt", "index.html"),
            os.path.join(base_dir, "index.html"),
        ]

        index_path = None
        for p in candidates:
            if os.path.exists(p):
                index_path = p
                break

        if not index_path:
            QMessageBox.critical(
                self, "MolArt",
                "Impossible de trouver la page MolArt locale.\n"
                "Placez votre index ici :\n"
                " - ./test_local_mol_art_index.html (fourni), ou\n"
                " - ./Assets/molart/index.html (recommandé)."
            )
            return

        url = "file:///" + index_path.replace("\\", "/") + "?uniprot=" + quote_plus(self.uniprot_id)
        webbrowser.open(url)

    
    def _build_html(self, selections, use_plddt=False):
        mut = {"pos": self.pos, "aa_from": self.aa_from, "aa_to": self.aa_to}
        html = (HTML_TMPL
                .replace("{PDB_DATA}", (self.pdb_text or "").replace("\\","\\\\").replace("`","\\`"))
                .replace("{MUT_JSON}", json.dumps(mut))
                .replace("{UNIPROT}", self.uniprot_id or "-")
                .replace("{MUTLINE}", f"{self.aa_from}{self.pos}{self.aa_to}" if (self.aa_from and self.pos and self.aa_to) else (self.hgvsp or "-"))
                .replace("{SELECTIONS_JSON}", json.dumps(selections))
                .replace("{USE_PLDDT}", "true" if use_plddt else "false")
        )
        return html

    def regenerate_html_silent(self):
        if not self.pdb_text: return
        enabled = self.features_panel.enabled_types()
        style = self.features_panel.current_style()
        op = self.features_panel.current_opacity()
        use_plddt = self.features_panel.is_plddt()
        selections = [] if use_plddt else build_selections_from_df(self.features_df, enabled, style, op)
        html = self._build_html(selections, use_plddt=use_plddt)
        self._write_html(html)

    def _build_and_open_html(self):
        self.regenerate_html_silent()
        self.open_in_browser()

    def load_from_mutation(self, hgvs_transcript: str):
        progress = QProgressDialog("Initialisation...", "Annuler", 0, 100, self)
        progress.setWindowModality(Qt.WindowModal); progress.setAutoClose(True); progress.setMinimumDuration(0); progress.setMinimumWidth(420)
        
        # Style moderne pour la barre de progression
        progress.setStyleSheet("""
            QProgressBar {
                border: solid grey;
                border-radius: 25px;
                color: black;
                text-align: center;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #05B8CC;
                border-radius: 25px;
            }
        """)
        
        progress.show()

        def update(msg, val=None):
            if val is not None: progress.setValue(val)
            self.status_lbl.setText(msg)
            progress.setLabelText(msg); QApplication.processEvents()
            if progress.wasCanceled(): raise RuntimeError("Annulé")

        try:
            update("Analyse HGVS…", 5)
            gene = parse_gene_from_entry(hgvs_transcript)

            info = vep_hgvs_fast(hgvs_transcript, progress_callback=lambda _: None)
            hgvsp = info.get("protein_hgvs"); uniprot = info.get("uniprot") or info.get("protein_id")
            if not hgvsp or not uniprot: raise RuntimeError("Impossible d'obtenir HGVSp/UniProt (VEP).")

            update("Téléchargement AlphaFold…", 45)
            pdb_text = fetch_alphafold_pdb(uniprot)

            # Features UniProt
            update("Récupération des features UniProt…", 65)
            df = fetch_uniprot_features(uniprot)

            aa_from, pos, aa_to = parse_hgvsp_to_parts(hgvsp)
            if pos is None: pos = info.get("protein_start")
            self.uniprot_id = uniprot; self.pdb_text = pdb_text; self.hgvsp = hgvsp
            self.gene = gene; self.pos = pos; self.aa_from = AA3_TO_1.get(aa_from, "") if aa_from else ""
            self.aa_to = AA3_TO_1.get(aa_to, "") if aa_to else ""
            self.features_df = df if df is not None else (pd.DataFrame() if pd is not None else None)

            self.features_panel.populate(self.features_df)

            # Active le bouton MolArt si UniProt est dispo
            if hasattr(self, "open_molart_btn"):
                self.open_molart_btn.setEnabled(bool(self.uniprot_id))

            update("Génération de la page 3D…", 85)
            self.regenerate_html_silent()
            update("OK", 100)
        except Exception as e:
            progress.close()
            QMessageBox.critical(self, "Erreur", str(e))
            self.status_lbl.setText("Erreur : " + str(e))
        finally:
            progress.close()

class PredictionsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.uniprot = ""
        self.pdb_text = ""
        self.hgvsp = ""
        self.gene = ""
        self.pos = None
        self.aa_from = ""
        self.aa_to = ""

        self.worker_dyn = None
        self.worker_inps = None
        self.current_url_dyn = None
        self.current_url_inps = None

        outer = QVBoxLayout(self)

        info_box = QGroupBox("Informations extraites")
        form = QFormLayout(info_box)
        self.gene_lbl = QLabel("-"); self.uniprot_lbl = QLabel("-"); self.hgvsp_lbl = QLabel("-")
        self.pos_lbl = QLabel("-"); self.aa_lbl = QLabel("-"); self.mutation_code_lbl = QLabel("-")
        form.addRow("Gène:", self.gene_lbl)
        form.addRow("UniProt:", self.uniprot_lbl)
        form.addRow("HGVSp:", self.hgvsp_lbl)
        form.addRow("Position:", self.pos_lbl)
        form.addRow("AA:", self.aa_lbl)
        form.addRow("Code mutation:", self.mutation_code_lbl)

        outer.addWidget(info_box)

        cols = QHBoxLayout()

        # DynaMut2
        g_dyn = QGroupBox("DynaMut2")
        f_dyn = QFormLayout(g_dyn)
        self.chain_dyn = QComboBox(); self.chain_dyn.addItems(list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")); self.chain_dyn.setCurrentText("A")
        self.mut_dyn = QLineEdit(); self.mut_dyn.setPlaceholderText("Ex: E346K")
        self.af_dyn = QCheckBox("Utiliser AlphaFold automatiquement (chaine A)"); self.af_dyn.setChecked(True)
        self.btn_run_dyn = QPushButton("Lancer DynaMut2")
        self.btn_run_dyn.clicked.connect(self.run_dynamut2)
        self.status_dyn = QLabel("En attente…")
        self.json_dyn = QTextEdit(); self.json_dyn.setReadOnly(True); self.json_dyn.setMinimumHeight(120)
        self.url_dyn = QLabel("-"); self.btn_open_dyn = QPushButton("Ouvrir la page DynaMut2"); self.btn_open_dyn.setEnabled(False); self.btn_open_dyn.clicked.connect(self.open_dyn_url)
        f_dyn.addRow("Chaîne:", self.chain_dyn)
        f_dyn.addRow("Code mutation:", self.mut_dyn)
        f_dyn.addRow(self.af_dyn)
        f_dyn.addRow(self.btn_run_dyn)
        f_dyn.addRow("Statut:", self.status_dyn)
        f_dyn.addRow("URL:", self.url_dyn)
        f_dyn.addRow(self.btn_open_dyn)
        f_dyn.addRow("Réponse JSON:", self.json_dyn)

        # INPS-MD
        g_inps = QGroupBox("INPS-MD (biocomp.unibo.it)")
        f_inps = QFormLayout(g_inps)
        self.chain_inps = QComboBox(); self.chain_inps.addItems(list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")); self.chain_inps.setCurrentText("A")
        self.mut_inps = QLineEdit(); self.mut_inps.setPlaceholderText("Ex: E346K (un seul variant)")
        self.poll_inps = QCheckBox("Attendre les résultats (polling)"); self.poll_inps.setChecked(True)
        self.btn_run_inps = QPushButton("Soumettre INPS-MD")
        self.btn_run_inps.clicked.connect(self.run_inpsmd)
        self.status_inps = QLabel("En attente…")
        self.url_inps = QLineEdit(); self.url_inps.setReadOnly(True)
        self.btn_open_inps = QPushButton("Ouvrir la page"); self.btn_open_inps.setEnabled(False); self.btn_open_inps.clicked.connect(self.open_inps_url)
        self.logs_inps = QTextEdit(); self.logs_inps.setReadOnly(True); self.logs_inps.setMinimumHeight(120)
        f_inps.addRow("Chaîne:", self.chain_inps)
        f_inps.addRow("Code mutation:", self.mut_inps)
        f_inps.addRow(self.poll_inps)
        f_inps.addRow(self.btn_run_inps)
        f_inps.addRow("Statut:", self.status_inps)
        f_inps.addRow("URL job:", self.url_inps)
        f_inps.addRow(self.btn_open_inps)
        f_inps.addRow("Logs:", self.logs_inps)

        cols.addWidget(g_dyn, 1)
        cols.addWidget(g_inps, 1)

        outer.addLayout(cols)

    def ensure_pdb_text(self) -> str:
        if self.pdb_text: return self.pdb_text
        if not self.uniprot: raise RuntimeError("UniProt inconnu – validez d'abord la mutation.")
        self.pdb_text = fetch_alphafold_pdb(self.uniprot)
        return self.pdb_text

    def load_from_hgvs(self, hgvs_text: str):
        try:
            gene = parse_gene_from_entry(hgvs_text)
            info = vep_hgvs_fast(hgvs_text)
            hgvsp = info.get("protein_hgvs")
            uniprot = info.get("uniprot") or info.get("protein_id")
            if not hgvsp or not uniprot:
                raise RuntimeError("Impossible d'obtenir HGVSp ou UniProt.")
            aa_from1, pos, aa_to1, mut_code = extract_amino_acids_and_position(hgvsp)
            if not pos:
                pos = info.get("protein_start")
            if not mut_code and aa_from1 and aa_to1 and pos:
                mut_code = f"{aa_from1}{pos}{aa_to1}"

            self.uniprot = uniprot; self.hgvsp = hgvsp; self.gene = gene or ""; self.pos = pos
            self.aa_from = aa_from1 or ""; self.aa_to = aa_to1 or ""
            self.gene_lbl.setText(self.gene or "-")
            self.uniprot_lbl.setText(self.uniprot)
            self.hgvsp_lbl.setText(self.hgvsp)
            self.pos_lbl.setText(str(self.pos) if self.pos else "-")
            self.aa_lbl.setText(f"{self.aa_from} → {self.aa_to}")
            self.mutation_code_lbl.setText(mut_code or "-")
            if mut_code:
                self.mut_dyn.setText(mut_code)
                self.mut_inps.setText(mut_code)
            self.pdb_text = ""
            self.status_dyn.setText("Prêt.")
            self.status_inps.setText("Prêt.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))

    # --- DynaMut2
    def run_dynamut2(self):
        try:
            chain = self.chain_dyn.currentText().strip() or 'A'
            mut_code = self.mut_dyn.text().strip()
            if not re.match(r'^[ACDEFGHIKLMNPQRSTVWY]\d+[ACDEFGHIKLMNPQRSTVWY]$', mut_code):
                raise RuntimeError("Code mutation invalide. Ex: E346K")
            pdb_text = self.ensure_pdb_text() if self.af_dyn.isChecked() else self.pdb_text
            if not pdb_text:
                raise RuntimeError("Aucune structure PDB chargée.")
            self.status_dyn.setText("Soumission en cours…")
            self.json_dyn.clear()
            self.worker_dyn = DynaMut2Worker(pdb_text.encode('utf-8'), chain, mut_code)
            self.worker_dyn.jobStarted.connect(lambda jid: self.status_dyn.setText(f"Job {jid} soumis. Attente…"))
            self.worker_dyn.jobMessage.connect(lambda m: self.status_dyn.setText(f"Statut: {m}"))
            self.worker_dyn.jobFinished.connect(self.on_dyn_finished)
            self.worker_dyn.jobError.connect(self.on_dyn_error)
            self.worker_dyn.start()
        except Exception as e:
            QMessageBox.critical(self, "DynaMut2", str(e))

    @QtCore.pyqtSlot(dict)
    def on_dyn_finished(self, payload: dict):
        try:
            self.json_dyn.setPlainText(json.dumps(payload, indent=2))
            message = payload.get("message")
            if message == "RUNNING":
                self.status_dyn.setText("Job en cours…")
                self.url_dyn.setText("En attente…"); self.btn_open_dyn.setEnabled(False); return
            url = payload.get("results_page"); self.current_url_dyn = url
            if url:
                self.url_dyn.setText(url); self.btn_open_dyn.setEnabled(True)
                self.status_dyn.setText("Résultats prêts.")
            else:
                jid = payload.get("job_id")
                if jid:
                    built = f"https://biosig.lab.uq.edu.au/dynamut2/results_prediction/{jid}"
                    self.current_url_dyn = built; self.url_dyn.setText(built); self.btn_open_dyn.setEnabled(True)
                    self.status_dyn.setText("URL construite via job_id.")
                else:
                    self.url_dyn.setText("—"); self.btn_open_dyn.setEnabled(False)
                    self.status_dyn.setText("Terminé (pas d'URL dans la réponse).")
            pred = payload.get("prediction")
            if pred is not None:
                try:
                    ddg = float(pred)
                    note = "Stabilisant" if ddg > 0 else ("Déstabilisant" if ddg < 0 else "Neutre")
                    self.status_dyn.setText(self.status_dyn.text() + f" | ΔΔG = {ddg:.2f} kcal/mol → {note}")
                except Exception:
                    pass
        except Exception as e:
            self.on_dyn_error(str(e))

    @QtCore.pyqtSlot(str)
    def on_dyn_error(self, message: str):
        self.status_dyn.setText("Erreur")
        QMessageBox.critical(self, "DynaMut2", message)

    def open_dyn_url(self):
        if self.current_url_dyn: webbrowser.open(self.current_url_dyn)

    # --- INPS-MD
    def run_inpsmd(self):
        try:
            chain = self.chain_inps.currentText().strip() or 'A'
            mut_code = self.mut_inps.text().strip()
            if not mut_code:
                raise RuntimeError("Veuillez saisir un code mutation (ex: E346K).")
            pdb_text = self.ensure_pdb_text()
            self.status_inps.setText("Soumission en cours…")
            self.logs_inps.clear(); self.url_inps.setText(""); self.btn_open_inps.setEnabled(False)
            self.worker_inps = INPSMDWorker(pdb_text.encode('utf-8'), chain, mut_code, poll=self.poll_inps.isChecked())
            self.worker_inps.logLine.connect(self.logs_inps.append)
            self.worker_inps.progress.connect(lambda m: self.status_inps.setText(m))
            self.worker_inps.startedJob.connect(self.on_inps_started)
            self.worker_inps.finishedOk.connect(self.on_inps_done)
            self.worker_inps.failed.connect(self.on_inps_error)
            self.worker_inps.savedHtml.connect(lambda p: self.logs_inps.append(f"[Debug HTML] {p}"))
            self.worker_inps.start()
        except Exception as e:
            QMessageBox.critical(self, "INPS-MD", str(e))

    def on_inps_started(self, job_id: str, url: str):
        self.status_inps.setText(f"Job soumis{(' – ' + job_id) if job_id else ''}. Attente…")
        self.url_inps.setText(url); self.current_url_inps = url; self.btn_open_inps.setEnabled(True)

    def on_inps_done(self, links: dict):
        if links:
            msg = " / ".join([f"{k.upper()}: {v}" for k,v in links.items()])
            self.logs_inps.append(f"Résultats: {msg}")
            self.status_inps.setText("Terminé – liens de résultats détectés.")
        else:
            self.status_inps.setText("Soumission terminée (sans polling).")

    def on_inps_error(self, err: str):
        self.status_inps.setText("Erreur")
        QMessageBox.critical(self, "INPS-MD", err)
        self.logs_inps.append(f"ERREUR: {err}")

    def open_inps_url(self):
        if self.current_url_inps: webbrowser.open(self.current_url_inps)

# ----------------------------------------------------------------------------------------------------------------------
# Onglet APIs externes (Miztli + ProtVar)
# ----------------------------------------------------------------------------------------------------------------------
class ExternalAPIsTab(QWidget):
    MY_API_BASE = "https://miztli.biokerden.eu"   # changer en local si besoin

    def __init__(self, parent=None):
        super().__init__(parent)
        self.gene = ""
        self.mut_str = ""
        self.mutation_input = ""  # MUTATION_INPUT (HGVS transcript saisi au départ)

        main = QVBoxLayout(self)

        # Affichage en lecture seule des infos (pas d'inputs)
        info_box = QGroupBox("Contexte (prérenseigné)")
        form = QFormLayout(info_box)
        self.lblMutIn = QLabel("-")
        self.lblGene = QLabel("-")
        self.lblMutShort = QLabel("-")
        form.addRow("Mutation entrée (HGVS):", self.lblMutIn)
        form.addRow("Gène:", self.lblGene)
        form.addRow("Mutation (code court):", self.lblMutShort)
        main.addWidget(info_box)

        # Actions
        rowb = QHBoxLayout()
        self.btnOpenMyApi = QPushButton("Ouvrir Miztli")
        self.btnOpenProtVar = QPushButton("Ouvrir ProtVar")
        rowb.addWidget(self.btnOpenMyApi); rowb.addWidget(self.btnOpenProtVar); rowb.addStretch(1)
        main.addLayout(rowb)

        self.btnOpenMyApi.clicked.connect(self.on_open_myapi)
        self.btnOpenProtVar.clicked.connect(self.on_open_protvar)

        tip = QLabel("Cet onglet interroge des API externes (Miztli, ProtVar) en envoyant automatiquement la nomenclature HGVS.")
        tip.setWordWrap(True)
        main.addWidget(tip); main.addStretch(1)

    def load_from_values(self, mutation_input: str, gene: str, mut_short: str):
        """Pré-remplit les champs d'affichage (lecture seule)."""
        self.mutation_input = mutation_input or ""
        self.gene = gene or ""
        self.mut_str = mut_short or ""
        self.lblMutIn.setText(self.mutation_input or "-")
        self.lblGene.setText(self.gene or "-")
        self.lblMutShort.setText(self.mut_str or "-")

    def on_open_myapi(self):
        # Conserve le comportement d'origine: nécessite gene + code court
        gene = (self.gene or "").strip(); mut = (self.mut_str or "").strip()
        if not (gene and mut):
            QMessageBox.warning(self, "Miztli", "Gène et mutation (code court) requis pour Miztli.")
            return
        url = f"{self.MY_API_BASE}/?variant&{quote_plus(gene)}&{quote_plus(mut)}"
        webbrowser.open(url)

    def on_open_protvar(self):
        # Utilise EXCLUSIVEMENT MUTATION_INPUT (HGVS transcript)
        q = (self.mutation_input or "").strip()
        if not q:
            QMessageBox.warning(self, "ProtVar", "Aucune MUTATION_INPUT (HGVS) disponible.")
            return
        url = f"https://www.ebi.ac.uk/ProtVar/query?search={quote_plus(q)}"
        webbrowser.open(url)

# ----------------------------------------------------------------------------------------------------------------------
# Onglet Export PDF
# ----------------------------------------------------------------------------------------------------------------------
class ExportTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = None
        self.exporter = None
        self._setup_ui()
    
    def set_main_window(self, main_window):
        self.main_window = main_window
        self.exporter = _ReportExporter(main_window)
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Titre
        title = QLabel("Export du rapport en PDF")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Générez un rapport PDF complet incluant les données de mutation, "
                     "la visualisation 3D, et les prédictions d'impact structural.")
        desc.setWordWrap(True)
        desc.setStyleSheet("margin: 10px; color: #666; font-size: 15px;")
        layout.addWidget(desc)
        
        # Bouton d'export
        export_btn = QPushButton("Exporter le rapport PDF")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 14px;
                border-radius: 6px;
                margin: 20px;
                min-height: 28px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        export_btn.clicked.connect(self.export_pdf)
        layout.addWidget(export_btn)
        
        # Warning / Avertissement
        warning_label = QLabel("""
AVERTISSEMENT : Ce logiciel est actuellement en développement et fait appel à des APIs externes pour utiliser des méthodes d'interprétation en dernière intention. Toute utilisation engage la responsabilité de l'utilisateur dans la prise de décision.

📧 Pour toutes questions, contactez : Magne Florian © - florian.magne@etu.unilim.fr 
        """.strip())
        warning_label.setWordWrap(True)
        warning_label.setStyleSheet("""
            QLabel {
                background-color: #fff3cd;
                border: 1px solid #ffeaa7;
                border-radius: 6px;
                padding: 12px;
                margin: 10px;
                font-size: 15px;
                color: #856404;
                line-height: 1.4;
            }
        """)
        layout.addWidget(warning_label)
        
        # Espace flexible
        layout.addStretch()
    
    def export_pdf(self):
        if self.exporter:
            self.exporter.export_pdf_dialog()
        else:
            QMessageBox.warning(self, "Erreur", "L'exportateur PDF n'est pas initialisé.")

# ----------------------------------------------------------------------------------------------------------------------
# Fenêtre principale
# ----------------------------------------------------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        
        # Configuration de la taille de fenêtre plus flexible
        self.resize(1200, 800)
        self.setMinimumSize(800, 600)  # Taille minimale plus raisonnable
        
        # Centrer la fenêtre sur l'écran
        self.center_on_screen()

        # Configuration de l'interface moderne
        tabs = QTabWidget()
        
        # Application du style moderne aux onglets
        set_tab_as_navrail(tabs)
        
        # Création des onglets
        self.entry = MutationEntryTab()
        self.viewer = ViewerTab()
        self.pred = PredictionsTab()
        self.apis = ExternalAPIsTab()
        self.export_tab = ExportTab()

        tabs.addTab(self.entry, "Entrée mutation")
        tabs.addTab(self.viewer, "Visualisation 3D")
        tabs.addTab(self.pred, "Prédictions")
        tabs.addTab(self.apis, "APIs externes")
        tabs.addTab(self.export_tab, "Export PDF")

        self.setCentralWidget(tabs)

        # Application du marquage des boutons primaires
        mark_primary(self)

        self.entry.mutationValidated.connect(self.on_mutation_validated)
        
        # Connecter l'onglet export avec les autres onglets
        self.export_tab.set_main_window(self)

        # ----------------------------------------------------------------------------------------------------------------------
        # Pipeline HTTP Listener - Initialisation du serveur d'écoute
        # ----------------------------------------------------------------------------------------------------------------------
        self._bridge = PipelineBridge()
        self._bridge.requestReceived.connect(self._on_pipeline_request)

        # Création du serveur HTTP avec configuration depuis YAML
        self._listener = PipelineHTTPListener(
            self._bridge, 
            parent=self
        )
        self._listener.start()
        
        # Afficher l'info de connexion dans le titre
        self.setWindowTitle(f"{APP_TITLE}")

    @QtCore.pyqtSlot(str)
    def on_mutation_validated(self, hgvs_text: str):
        self.viewer.load_from_mutation(hgvs_text)
        self.pred.load_from_hgvs(hgvs_text)
        short_mut = ""
        if self.pred.aa_from and self.pred.pos and self.pred.aa_to:
            short_mut = f"{self.pred.aa_from}{self.pred.pos}{self.pred.aa_to}"
        self.apis.load_from_values(hgvs_text, self.pred.gene or "", short_mut)

    @QtCore.pyqtSlot(dict)
    def _on_pipeline_request(self, payload: dict):
        """Traite les requêtes reçues depuis la pipeline HTTP"""
        try:
            ep = payload.get("endpoint")
            print(f"[Pipeline Request] Reçu: {ep} - {payload}")

            # --- 1) Recherche dans MutViewer ---
            if ep == "/mutviewer/search":
                hgvs = (payload.get("hgvs") or "").strip()
                gene = (payload.get("gene") or "").strip()
                mut  = (payload.get("mut")  or "").strip()

                if hgvs:
                    # Chemin « idéal » : tout part de l'HGVS
                    print(f"[Pipeline] Chargement HGVS: {hgvs}")
                    # Remplir le champ d'entrée et déclencher la validation
                    self.entry.input.setText(hgvs)
                    self.on_mutation_validated(hgvs)
                    
                    # Optionnel : basculer vers l'onglet visualisation
                    tabs = self.centralWidget()
                    if isinstance(tabs, QTabWidget):
                        tabs.setCurrentIndex(1)  # Index de l'onglet "Visualisation 3D"
                        
                elif gene and mut:
                    # Fallback : on pré-remplit l'UI avec gène + code court
                    print(f"[Pipeline] Chargement Gene+Mut: {gene} {mut}")
                    # Construire un HGVS approximatif pour déclencher le workflow
                    approximate_hgvs = f"NM_000000.0({gene}):c.000{mut}"  # placeholder
                    self.entry.input.setText(approximate_hgvs)
                    # ou appeler directement les méthodes avec les valeurs partielles
                    try:
                        if hasattr(self.apis, "load_from_values"):
                            self.apis.load_from_values("", gene, mut)
                    except Exception as e:
                        print(f"[Pipeline] Erreur load_from_values: {e}")
                else:
                    print("[Pipeline] Rien d'exploitable dans la requête")

            else:
                print(f"[Pipeline] Endpoint inconnu: {ep}")

        except Exception as e:
            # best-effort : ne pas planter l'UI si la requête est imparfaite
            print(f"[Pipeline Listener] Erreur lors du traitement: {e}")
            import traceback
            traceback.print_exc()

    def center_on_screen(self):
        """Centre la fenêtre sur l'écran principal"""
        try:
            screen = QDesktopWidget().screenGeometry()
            window = self.geometry()
            x = (screen.width() - window.width()) // 2
            y = (screen.height() - window.height()) // 2
            self.move(x, y)
        except Exception as e:
            print(f"[MainWindow] Impossible de centrer la fenêtre: {e}")

    def closeEvent(self, event):
        """Nettoyage lors de la fermeture de l'application"""
        try:
            if hasattr(self, '_listener'):
                print("[MainWindow] Arrêt du serveur HTTP...")
                self._listener.stop()
                self._listener.wait(5000)  # Attendre max 5 secondes
        except Exception as e:
            print(f"[MainWindow] Erreur lors de l'arrêt du serveur: {e}")
        
        super().closeEvent(event)

def main():
    app = QApplication(sys.argv)
    
    # Application du thème moderne
    apply_modern_theme(app, primary="#2c5aa0")
    
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

# ===========================
# === Export PDF Add-on  ====
# ===========================
from PyQt5.QtPrintSupport import QPrinter
from PyQt5.QtGui import QTextDocument
from PyQt5.QtWidgets import QToolBar, QAction, QFileDialog, QMessageBox
from PyQt5 import QtGui
from datetime import datetime
import shutil

class _ReportExporter:

    def _screenshot_with_html2image(self, url_or_path: str, out_path: str,
                                    width: int = 1600, height: int = 900,
                                    wait_ms: int = 3000) -> str:
        """
        Capture une page (URL http/https ou fichier local) en PNG avec html2image.
        Retourne le chemin du PNG si succès, sinon "" (best-effort).
        OPTIMISÉ : timeout réduit et résolution adaptative
        """
        try:
            from html2image import Html2Image
            import os

            # Normalise en URL file:/// si on reçoit un chemin local
            if url_or_path and not url_or_path.lower().startswith(("http://", "https://", "file:///")):
                url = "file:///" + url_or_path.replace("\\", "/")
            else:
                url = url_or_path

            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            # Flags optimisés pour rapidité
            flags = [
                f"--virtual-time-budget={int(wait_ms)}",
                "--enable-webgl",
                "--ignore-gpu-blocklist",
                "--use-angle=swiftshader",   # rendu logiciel si GPU indisponible
                "--hide-scrollbars",
                "--disable-extensions",      # NOUVEAU : désactive les extensions pour plus de rapidité
                "--no-sandbox",              # NOUVEAU : évite les délais de sandbox
                "--disable-dev-shm-usage",   # NOUVEAU : évite les problèmes de mémoire partagée
            ]

            hti = Html2Image(size=(width, height), custom_flags=flags, output_path=os.path.dirname(out_path))
            hti.screenshot(url=url, save_as=os.path.basename(out_path))
            return out_path if os.path.exists(out_path) else ""
        except Exception:
            return ""

    # === NOUVELLES MÉTHODES POUR INTÉGRATION BASE64 ET MISE EN PAGE MIXTE ===
    
    def _img_to_data_uri(self, path: str) -> str:
        """Convertit une image en Data URI base64 pour intégration dans HTML - OPTIMISÉ"""
        try:
            if not path or not os.path.exists(path):
                return ""
                
            # Optimisation : vérifier la taille du fichier
            file_size = os.path.getsize(path)
            if file_size > 5 * 1024 * 1024:  # Plus de 5MB
                # Compresser l'image si elle est trop grosse
                return self._compress_and_convert_image(path)
                
            with open(path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            ext = os.path.splitext(path)[1].lower()
            if ext in (".png",):
                mime = "image/png"
            elif ext in (".jpg", ".jpeg"):
                mime = "image/jpeg"
            elif ext in (".svg",):
                mime = "image/svg+xml"
            else:
                mime = "application/octet-stream"
            return f"data:{mime};base64,{b64}"
        except Exception:
            return ""

    def _compress_and_convert_image(self, path: str) -> str:
        """Compresse une image trop volumineuse avant conversion base64"""
        try:
            from PIL import Image
            
            # Ouvrir et redimensionner l'image
            with Image.open(path) as img:
                # Convertir en RGB si nécessaire
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')
                
                # Redimensionner si trop grande
                max_size = (1200, 800)
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                # Sauvegarder en mémoire avec compression JPEG
                import io
                buffer = io.BytesIO()
                img.save(buffer, format='JPEG', quality=85, optimize=True)
                
                # Convertir en base64
                buffer.seek(0)
                b64 = base64.b64encode(buffer.read()).decode("ascii")
                return f"data:image/jpeg;base64,{b64}"
                
        except ImportError:
            # Si PIL n'est pas disponible, retourner l'image non compressée
            with open(path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            return f"data:image/png;base64,{b64}"
        except Exception:
            return ""

    def _img_tag(self, path: str, alt: str = "", css_class: str = "full-image") -> str:
        """Génère un tag img avec l'image intégrée en base64"""
        uri = self._img_to_data_uri(path)
        if not uri:
            # Placeholder si l'image n'est pas disponible
            return f'<div style="border:1px solid #ccc;padding:12px;text-align:center;border-radius:6px;">(Image indisponible) {alt or ""}</div>'
        alt = (alt or "").replace('"', '\\"')
        return f'<img src="{uri}" alt="{alt}" class="{css_class}"/>'

    def _build_report_html_split(self, d: dict):
        """Retourne (html_page1_portrait, [html_pages_figures_landscape])"""
        # Page 1 : résumé exécutif en portrait (on réutilise la logique existante)
        cover_html = self._build_report_html_cover(d)

        # Pages figures individuelles en paysage - SEULEMENT POUR LES IMAGES QUI EXISTENT
        figs = []
        if d.get("viewer_capture_png") and os.path.exists(d.get("viewer_capture_png", "")):
            figs.append(("Visualisation 3D du modèle AlphaFold", d["viewer_capture_png"]))
        if d.get("dynamut_capture_png") and os.path.exists(d.get("dynamut_capture_png", "")):
            figs.append(("Résultats DynaMut2", d["dynamut_capture_png"]))
        if d.get("inpsmd_capture_png") and os.path.exists(d.get("inpsmd_capture_png", "")):
            figs.append(("Page INPS-MD", d["inpsmd_capture_png"]))

        figure_pages = []
        common_style = """
        <style>
            @page { size: A4 landscape; margin: 12mm; }
            body { font-family: 'Segoe UI', Roboto, Arial, sans-serif; }
            .image-page { text-align:center; display:flex; flex-direction:column; justify-content:center; min-height:90vh; }
            .full-image { max-width:100%; max-height:80vh; width:auto; height:auto; object-fit:contain;
                          border:1px solid #ddd; border-radius:8px; box-shadow:0 4px 8px rgba(0,0,0,.1); }
            h2 { color:#2c5aa0; margin:0 0 10px 0; font-size: 24pt; }
            .image-caption { font-weight:600; color:#2c5aa0; margin-top:12px; font-size: 16pt; }
        </style>
        """
        
        for idx, (caption, path) in enumerate(figs, start=1):
            img = self._img_tag(path, caption)
            html = f"""<!doctype html><html><head><meta charset="utf-8"/>{common_style}</head>
            <body><div class="image-page">
              {img}
              <div class="image-caption">{caption}</div>
            </div></body></html>"""
            figure_pages.append(html)

        return cover_html, figure_pages

    def _write_pdf(self, doc_or_html, file_path: str, orientation: str = "Portrait"):
        """Écrit un PDF avec orientation spécifique"""
        from PyQt5.QtPrintSupport import QPrinter
        from PyQt5.QtGui import QTextDocument

        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setPaperSize(QPrinter.A4)
        printer.setOrientation(QPrinter.Landscape if str(orientation).lower().startswith("land") else QPrinter.Portrait)
        printer.setResolution(300)
        printer.setPageMargins(12, 12, 12, 12, QPrinter.Millimeter)
        printer.setOutputFileName(file_path)

        if isinstance(doc_or_html, str):
            qdoc = QTextDocument()
            qdoc.setHtml(doc_or_html)
        else:
            qdoc = doc_or_html

        qdoc.setDocumentMargin(8)
        qdoc.setPageSize(QSizeF(printer.pageRect().size()))
        qdoc.print(printer)

    def _merge_pdfs(self, inputs: list, out_path: str) -> bool:
        """Fusionne plusieurs PDFs en un seul"""
        if not inputs or not HAVE_PYPDF2:
            return False
        try:
            merger = PyPDF2.PdfMerger()
            for p in inputs:
                if p and os.path.exists(p):
                    merger.append(p)
            merger.write(out_path)
            merger.close()
            return True
        except Exception:
            return False
    def __init__(self, main_window):
        self.win = main_window

    # ---------- UI wiring ----------
    def add_toolbar_and_menu(self):
        # Export PDF sera disponible uniquement via un onglet dédié
        # Plus de toolbar ni menu pour éviter l'encombrement
        pass

    # ---------- Export orchestration ----------

    def export_pdf_dialog(self):
        """Export PDF optimisé avec barre de progression"""
        try:
            suggested = os.path.join(os.path.expanduser("~"), "Rapport_Mutation.pdf")
            out_path, _ = QFileDialog.getSaveFileName(
                self.win, "Exporter le compte-rendu en PDF", suggested, "PDF (*.pdf)"
            )
            if not out_path:
                return
            assets_dir = os.path.splitext(out_path)[0] + "_assets"
            os.makedirs(assets_dir, exist_ok=True)

            # === BARRE DE PROGRESSION ===
            progress = QProgressDialog("Génération du rapport PDF en cours...", "Annuler", 0, 100, self.win)
            progress.setWindowTitle("Export PDF")
            progress.setMinimumDuration(0)
            progress.setValue(0)
            
            # Style moderne pour la barre de progression
            progress.setStyleSheet("""
                QProgressBar {
                    border: solid grey;
                    border-radius: 25px;
                    color: black;
                    text-align: center;
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: #05B8CC;
                    border-radius: 25px;
                }
            """)
            
            QApplication.processEvents()

            # Collect data
            progress.setLabelText("Collecte des données...")
            progress.setValue(10)
            QApplication.processEvents()
            if progress.wasCanceled():
                return
            data = self._collect_report_data(assets_dir)

            # ---- Captures html2image (vue 3D locale, DynaMut2, INPS-MD) ----
            progress.setLabelText("Capture d'écran de la vue 3D...")
            progress.setValue(20)
            QApplication.processEvents()
            if progress.wasCanceled():
                return
                
            try:
                # 1) Vue 3D locale (si on a le HTML généré)
                viewer_html = getattr(self.win.viewer, "_last_html_path", "") if hasattr(self.win, "viewer") else ""
                if viewer_html and os.path.exists(viewer_html):
                    out_cap = os.path.join(assets_dir, "viewer_capture.png")
                    cap = self._screenshot_with_html2image(viewer_html, out_cap, width=2400, height=1600, wait_ms=3000)
                    if cap:
                        data["viewer_capture_png"] = cap
            except Exception:
                pass

            progress.setLabelText("Capture d'écran de DynaMut2...")
            progress.setValue(40)
            QApplication.processEvents()
            if progress.wasCanceled():
                return

            try:
                # 2) DynaMut2 (si l’URL de résultat est dispo)
                dyn_url = data.get("dyn_url") or ""
                if dyn_url:
                    out_cap = os.path.join(assets_dir, "dynamut_capture.png")
                    cap = self._screenshot_with_html2image(dyn_url, out_cap, width=2400, height=1600, wait_ms=4000)
                    if cap:
                        data["dynamut_capture_png"] = cap
            except Exception:
                pass

            try:
                # 3) INPS-MD (si l’URL de job/résultats est dispo)
                inps_url = data.get("inps_url") or ""
                if inps_url:
                    out_cap = os.path.join(assets_dir, "inpsmd_capture.png")
                    cap = self._screenshot_with_html2image(inps_url, out_cap, width=2400, height=1600, wait_ms=4000)
                    if cap:
                        data["inpsmd_capture_png"] = cap
            except Exception:
                pass

            # External links (ProtVar/Miztli) — EXACT same format as ExternalAPIsTab buttons
            protvar_url = ""
            miztli_url = ""
            try:
                from urllib.parse import quote_plus
            except Exception:
                def quote_plus(x): return x
            try:
                apis = getattr(self.win, "apis", None)
                if apis is not None:
                    # ProtVar button uses ?search= with the raw mutation_input
                    q = (getattr(apis, "mutation_input", "") or "").strip()
                    if q:
                        protvar_url = f"https://www.ebi.ac.uk/ProtVar/query?search={quote_plus(q)}"
                    # Miztli button uses base /?variant&<gene>&<mut_short>
                    base = (getattr(apis, "MY_API_BASE", "") or "").rstrip("/")
                    gene = (getattr(apis, "gene", "") or "").strip()
                    mut = (getattr(apis, "mut_str", "") or "").strip()
                    if base and gene and mut:
                        miztli_url = f"{base}/?variant&{quote_plus(gene)}&{quote_plus(mut)}"
            except Exception:
                pass
            data["protvar_url"] = protvar_url
            data["miztli_url"] = miztli_url

            # 3D preview PNG (best-effort)
            try:
                preview_png = self._capture_view3d_png(assets_dir, data.get("uniprot"))
            except Exception:
                preview_png = ""
            if preview_png:
                data["viewer_png"] = preview_png

            # === NOUVELLE APPROCHE : PAGES SÉPARÉES ===
            progress.setLabelText("Génération du contenu HTML...")
            progress.setValue(75)
            QApplication.processEvents()
            if progress.wasCanceled():
                return
                
            # 1) Construire HTML split (page 1 + pages figures)
            cover_html, figure_pages = self._build_report_html_split(data)

            progress.setLabelText("Génération du PDF final...")
            progress.setValue(85)
            QApplication.processEvents()
            if progress.wasCanceled():
                return

            # 2) Écrire la page 1 (portrait) dans un PDF temporaire
            tmp_cover = os.path.join(assets_dir, "_tmp_cover.pdf")
            self._write_pdf(cover_html, tmp_cover, orientation="Portrait")

            # 3) Écrire chaque figure en paysage, 1 PDF par page (seulement si des figures existent)
            tmp_figs = []
            if figure_pages:  # Ne générer des PDFs figure que s'il y a des images
                for i, html in enumerate(figure_pages, start=1):
                    p = os.path.join(assets_dir, f"_tmp_fig_{i:02d}.pdf")
                    self._write_pdf(html, p, orientation="Landscape")
                    tmp_figs.append(p)

            progress.setLabelText("Fusion des pages...")
            progress.setValue(95)
            QApplication.processEvents()
            if progress.wasCanceled():
                return

            # 4) Fusion (seulement si il y a des figures à fusionner)
            if tmp_figs:  # S'il y a des figures, on fusionne
                parts = [tmp_cover] + tmp_figs
                merged_ok = self._merge_pdfs(parts, out_path)
            else:  # Pas de figures : on copie directement la page 1
                shutil.copy2(tmp_cover, out_path)
                merged_ok = True
            # Finalisation
            progress.setValue(100)
            progress.close()
            
            if not merged_ok:
                # Fallback : si PyPDF2 absent, on sauve tout de même la page 1
                # et on laisse les pages "figures" à côté dans _assets/
                shutil.copy2(tmp_cover, out_path)
                msg_pypdf = ""
                if not HAVE_PYPDF2:
                    msg_pypdf = "\n\nPyPDF2 non détecté pour fusionner les pages paysage.\nInstalle PyPDF2 pour fusionner automatiquement :\n    pip install PyPDF2"
                
                QMessageBox.information(
                    self.win, "Export PDF",
                    f"Le PDF final (page 1) a été généré.\n"
                    f"Les pages figures sont disponibles dans :\n{assets_dir}{msg_pypdf}"
                )
            else:
                # Nettoyage des fichiers temporaires
                try:
                    for tmp_file in parts:
                        if os.path.exists(tmp_file):
                            os.remove(tmp_file)
                except Exception:
                    pass
                
                QMessageBox.information(
                    self.win, "Export PDF",
                    f"Compte-rendu exporté :\n{out_path}\n\nImages intégrées et mise en page portrait/paysage OK.\n"
                    f"Pièces jointes copiées dans :\n{assets_dir}"
                )

            # Save JSON snapshot
            try:
                with open(os.path.join(assets_dir, "rapport_data.json"), "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
        except Exception as e:
            QMessageBox.critical(self.win, "Export PDF", str(e))

    # ---------- Helpers: files & downloads ----------
    def _copy_asset(self, src_path: str, dst_dir: str, dst_name: str=None) -> str:
        try:
            if not src_path or not os.path.exists(src_path):
                return ""
            os.makedirs(dst_dir, exist_ok=True)
            base = dst_name if dst_name else os.path.basename(src_path)
            dst = os.path.join(dst_dir, base)
            shutil.copy2(src_path, dst)
            return dst
        except Exception:
            return ""

    def _download_to(self, url: str, dst_dir: str, dst_name: str=None) -> str:
        try:
            if not url:
                return ""
            s = create_robust_session(timeout=120, retries=2) if 'create_robust_session' in globals() else requests.Session()
            r = s.get(url, stream=True)
            r.raise_for_status()
            name = dst_name or os.path.basename(url.split('?')[0])
            path = os.path.join(dst_dir, name)
            with open(path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            try:
                s.close()
            except Exception:
                pass
            return path
        except Exception:
            return ""

    # ---------- 3D Capture ----------
    def _capture_view3d_png(self, assets_dir: str, uniprot_id: str):
        try:
            import py3Dmol  # optional
        except Exception:
            return ""
        pdb_path = ""
        try:
            if hasattr(self.win, "viewer"):
                pdb_path = getattr(self.win.viewer, "last_pdb_path", "") or ""
        except Exception:
            pdb_path = ""
        if (not pdb_path) and uniprot_id:
            if 'fetch_alphafold_pdb' in globals():
                try:
                    pdb_path = fetch_alphafold_pdb(uniprot_id)
                except Exception:
                    pdb_path = ""
        if not pdb_path or not os.path.exists(pdb_path):
            return ""
        try:
            with open(pdb_path, "r", encoding="utf-8", errors="ignore") as f:
                pdb_str = f.read()
            view = py3Dmol.view(width=1200, height=800)
            view.addModel(pdb_str, "pdb")
            view.setStyle({"cartoon": {"opacity": 0.9}})
            view.zoomTo()
            png_bytes = view.png()
            out = os.path.join(assets_dir, "viewer_preview.png")
            with open(out, "wb") as fp:
                fp.write(png_bytes)
            return out
        except Exception:
            return ""

    # ---------- Data collection ----------
    def _collect_report_data(self, assets_dir: str) -> dict:
        w = self.win
        now = datetime.now().strftime("%Y-%m-%d %H:%M")

        def get_attr(obj, path, default=""):
            cur = obj
            try:
                for p in path.split("."):
                    if p.endswith("()"):
                        cur = getattr(cur, p[:-2])()
                    else:
                        cur = getattr(cur, p)
                return cur if cur is not None else default
            except Exception:
                return default

        entry_text = ""
        if hasattr(w, "entry") and hasattr(w.entry, "input"):
            try:
                entry_text = w.entry.input.text()
            except Exception:
                pass

        gene = get_attr(w, "pred.gene", "")
        uniprot = get_attr(w, "pred.uniprot", "") or get_attr(w, "viewer.uniprot_id", "")
        hgvsp = get_attr(w, "pred.hgvsp", "")
        aa_from = get_attr(w, "pred.aa_from", "")
        aa_to = get_attr(w, "pred.aa_to", "")
        pos = get_attr(w, "pred.pos", "")
        mut_short = f"{aa_from}{pos}{aa_to}" if aa_from and aa_to and pos else ""

        dyn_json_text = ""
        dyn_url = ""
        ddg = None
        ddg_note = ""
        if hasattr(w, "pred"):
            dyn_url = get_attr(w, "pred.current_url_dyn", "") or get_attr(w, "pred.url_dyn.text()", "")
            try:
                dyn_json_text = get_attr(w, "pred.json_dyn.toPlainText()", "").strip()
                if dyn_json_text:
                    payload = json.loads(dyn_json_text)
                    if isinstance(payload, dict) and payload.get("prediction") is not None:
                        ddg = float(payload["prediction"])
                        ddg_note = "Stabilisant" if ddg > 0 else ("Déstabilisant" if ddg < 0 else "Neutre")
            except Exception:
                pass

        inps_url = get_attr(w, "pred.current_url_inps", "") or get_attr(w, "pred.url_inps.text()", "")
        inps_logs = get_attr(w, "pred.logs_inps.toPlainText()", "")

        json_links = re.findall(r'https?://\S+?\.json', inps_logs or "")
        tsv_links  = re.findall(r'https?://\S+?\.tsv',  inps_logs or "")

        attachments = []
        viewer_html = get_attr(w, "viewer._last_html_path", "")
        copied_viewer = self._copy_asset(viewer_html, assets_dir, "viewer_3d.html") if viewer_html else ""
        if copied_viewer:
            attachments.append(copied_viewer)

        for line in (inps_logs or "").splitlines():
            m = re.search(r"\[Debug HTML\]\s+(.*)", line)
            if m:
                p = (m.group(1) or "").strip()
                c = self._copy_asset(p, assets_dir)
                if c:
                    attachments.append(c)

        if dyn_json_text:
            try:
                path_dyn_json = os.path.join(assets_dir, "dynamut2.json")
                with open(path_dyn_json, "w", encoding="utf-8") as f:
                    f.write(dyn_json_text)
                attachments.append(path_dyn_json)
            except Exception:
                pass

        for u in (json_links + tsv_links):
            got = self._download_to(u, assets_dir)
            if got:
                attachments.append(got)

        try:
            if hasattr(w, "viewer") and hasattr(w.viewer, "features_df") and w.viewer.features_df is not None and not w.viewer.features_df.empty:
                features_csv = os.path.join(assets_dir, "uniprot_features.csv")
                w.viewer.features_df.to_csv(features_csv, index=False)
                attachments.append(features_csv)
        except Exception:
            pass

        return {
            "generated_at": now,
            "mutation_input": entry_text or "",
            "gene": gene,
            "uniprot": uniprot,
            "hgvsp": hgvsp,
            "aa_from": aa_from,
            "aa_to": aa_to,
            "position": pos,
            "mutation_short": mut_short,
            "dyn_url": dyn_url or "",
            "dyn_prediction_ddg": ddg,
            "dyn_prediction_note": ddg_note,
            "inps_url": inps_url or "",
            "inps_logs": inps_logs or "",
            "attachments": attachments
        }

    # ---------- HTML building methods for split layout ----------
    def _build_report_html_cover(self, d: dict) -> str:
        """Construit la page 1 (portrait) avec résumé exécutif et info de base"""
        
        def esc(s):
            return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        def link_or_dash(url, label=None):
            if url:
                lbl = esc(label) if label else esc(url)
                return f'<a href="{url}">{lbl}</a>'
            return "—"

        def badge(txt):
            return f'<span class="badge">{esc(txt)}</span>'

        # Badges ΔΔG
        ddg_val = d.get("dyn_prediction_ddg")
        ddg_txt = f"{ddg_val:.2f} kcal/mol" if ddg_val is not None else "—"
        ddg_note = d.get("dyn_prediction_note") or ""
        if ddg_note.lower().startswith("stabil"):
            ddg_badge = badge("Stabilisant")
        elif ddg_note.lower().startswith("déstab") or ddg_note.lower().startswith("destab"):
            ddg_badge = badge("Déstabilisant")
        elif ddg_val is None:
            ddg_badge = badge("ND")
        else:
            ddg_badge = badge("Neutre")

        # Liste des figures pour référence
        figs = []
        if d.get("viewer_capture_png"):
            figs.append("Visualisation 3D du modèle AlphaFold")
        if d.get("dynamut_capture_png"):
            figs.append("Résultats DynaMut2")
        if d.get("inpsmd_capture_png"):
            figs.append("Page INPS-MD")

        figures_list = ""
        if figs:
            list_items = []
            for i, caption in enumerate(figs, start=1):
                list_items.append(f"<li>{esc(caption)} (Page {i+1})</li>")
            figures_list = "<ul>" + "".join(list_items) + "</ul>"
        else:
            figures_list = "<p><em>Aucune figure disponible</em></p>"

        # Attachments
        att_list = ""
        for p in (d.get("attachments") or []):
            att_list += f"<li>{esc(os.path.basename(p))}</li>"
        att_block = f"<ul class='attach-list'>{'<li>Aucune pièce jointe</li>' if not att_list else att_list}</ul>"

        # Liens externes
        protvar = link_or_dash(d.get("protvar_url"), "ProtVar (EBI)")
        miztli = link_or_dash(d.get("miztli_url"), "Miztli")

        # Données principales
        gene = esc(d.get("gene") or "")
        mut_short = esc(d.get("mutation_short") or "")
        generated_at = esc(d.get("generated_at") or "")

        # Résumé exécutif
        resume_table = f"""
        <table class="professional-table">
            <tr><th>Mutation (HGVS)</th><td>{esc(d.get('mutation_input'))}</td></tr>
            <tr><th>Gène</th><td>{gene or "—"}</td></tr>
            <tr><th>UniProt</th><td>{esc(d.get('uniprot')) or "—"}</td></tr>
            <tr><th>HGVSp</th><td>{esc(d.get('hgvsp')) or "—"}</td></tr>
            <tr><th>Code court</th><td>{mut_short or "—"}</td></tr>
        </table>
        """

        # Méthodes
        methods = """
        <h2>Méthodes & services consultés</h2>
        <ul class="methods">
            <li>Ensembl VEP (HGVS → HGVSp / UniProt)</li>
            <li>AlphaFold DB (modèle PDB)</li>
            <li>UniProt REST (features)</li>
            <li>DynaMut2 API (ΔΔG)</li>
            <li>INPS-MD (soumission & polling)</li>
            <li>Scène 3D générée via 3Dmol.js</li>
        </ul>
        <p class="footnote">Document généré automatiquement.</p>
        """

        # Styles optimisés pour PDF professionnel
        style = """
        <style>
            @page {
                size: A4 portrait;
                margin: 15mm;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 14pt;
                line-height: 1.8;
                color: #2c3e50;
                margin: 0;
                padding: 20px;
                background: white;
            }
            
            /* En-tête clinique professionnel */
            .clinical-header {
                text-align: center;
                background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                border: 3px solid #2c5aa0;
                border-radius: 12px;
                padding: 40px 30px;
                margin-bottom: 50px;
                box-shadow: 0 4px 15px rgba(44, 90, 160, 0.15);
            }
            
            h1 {
                font-size: 42pt;
                color: #2c5aa0;
                margin: 0 0 20px 0;
                font-weight: 400;
                letter-spacing: -1px;
                text-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-transform: uppercase;
            }
            
            .clinical-subtitle {
                font-size: 20pt;
                color: #495057;
                margin: 20px 0;
                font-weight: 300;
                font-style: italic;
            }
            
            .mutation-badge {
                display: inline-block;
                background: transparent;
                color: #2c5aa0;
                padding: 15px 30px;
                border: 3px solid #2c5aa0;
                border-radius: 25px;
                font-size: 18pt;
                font-weight: 700;
                margin: 20px 0;
                box-shadow: none;
            }
            
            /* Tableaux professionnels */
            .professional-table {
                width: 100%;
                border-collapse: collapse;
                margin: 30px 0;
                background: white;
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            }
            
            .professional-table th {
                background: #2c5aa0;
                color: white !important;
                padding: 20px 15px;
                text-align: left;
                font-size: 16pt;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                width: 40%;
            }
            
            .professional-table td {
                padding: 18px 15px;
                border-bottom: 1px solid #e9ecef;
                font-size: 15pt;
                vertical-align: top;
                color: #2c3e50 !important;
                font-weight: 500;
            }
            
            .professional-table tr:nth-child(even) {
                background: #f8f9fa;
            }
            
            .professional-table tr:hover {
                background: #e3f2fd;
            }
            
            /* Sections avec style clinique */
            h2 {
                font-size: 24pt;
                color: #2c5aa0;
                margin: 40px 0 25px 0;
                border-bottom: 3px solid #2c5aa0;
                padding-bottom: 12px;
                text-align: left;
                font-weight: 400;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            h3 {
                font-size: 18pt;
                color: #495057;
                margin: 25px 0 15px 0;
                font-weight: 600;
                text-align: left;
            }
            
            /* Prédictions cliniques */
            .predictions-container {
                background: #f8f9fa;
                border-radius: 12px;
                padding: 30px;
                margin: 30px 0;
                border-left: 6px solid #2c5aa0;
            }
            
            .prediction-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 25px;
                margin: 20px 0;
            }
            
            .prediction-card {
                background: white;
                border-radius: 10px;
                padding: 25px;
                box-shadow: 0 3px 10px rgba(0,0,0,0.1);
                border-top: 4px solid #2c5aa0;
            }
            
            .prediction-title {
                font-size: 16pt;
                color: #2c5aa0;
                font-weight: 700;
                margin-bottom: 15px;
                text-transform: uppercase;
            }
            
            .prediction-value {
                font-size: 15pt;
                color: #2c3e50;
                font-weight: 600;
                margin: 10px 0;
            }
            
            /* Liens externes stylisés */
            .links-section {
                background: #e8f4fd;
                border-radius: 10px;
                padding: 25px;
                margin: 30px 0;
                border: 1px solid #2c5aa0;
            }
            
            .link-item {
                background: white;
                padding: 15px 20px;
                margin: 10px 0;
                border-radius: 8px;
                border-left: 4px solid #2c5aa0;
                font-size: 14pt;
                box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            }
            
            /* Liste des figures professionnelle */
            .figures-list {
                background: #fff;
                border: 2px solid #e9ecef;
                border-radius: 10px;
                padding: 25px;
                margin: 30px 0;
            }
            
            .figures-list ul {
                list-style: none;
                padding: 0;
                margin: 0;
            }
            
            .figures-list li {
                padding: 12px 0;
                border-bottom: 1px solid #e9ecef;
                font-size: 14pt;
                color: #2c3e50;
            }
            
            .figures-list li:last-child {
                border-bottom: none;
            }
            
            /* Méthodes */
            .methods-section {
                background: #f1f3f4;
                border-radius: 10px;
                padding: 25px;
                margin: 30px 0;
                border-left: 5px solid #6c757d;
            }
            
            .methods ul {
                font-size: 13pt;
                line-height: 1.8;
                color: #495057;
            }
            
            .badge {
                display: inline-block;
                padding: 4px 12px;
                font-size: 10pt;
                border-radius: 20px;
                background: #e3f2fd;
                color: #1976d2;
                margin-left: 8px;
                font-weight: 500;
            }
            
            .footnote {
                font-size: 10pt;
                color: #666;
                margin-top: 30px;
                text-align: center;
            }
        </style>
        """

        # Assemblage de la page 1
        page_content = f"""
            <div class="clinical-header">
                <h1>Rapport de Mutation Moléculaire</h1>
                {('<div class="mutation-badge">Gène '+gene+' — Mutation '+mut_short+'</div>') if (gene or mut_short) else ""}
                <div style="font-size: 16pt; color: #6c757d; margin-top: 25px;">
                    <strong>Date de génération :</strong> {generated_at or "—"}
                </div>
            </div>

            <h2>Résumé Exécutif</h2>
            <div style="overflow-x: auto;">
                {resume_table}
            </div>

            <h2>Ressources Externes</h2>
            <div class="links-section">
                <div class="link-item"><strong>ProtVar :</strong> {protvar}</div>
                <div class="link-item"><strong>Miztli :</strong> {miztli}</div>
            </div>

            <h2>Prédictions Bio-informatiques</h2>
            <div class="predictions-container">
                <div class="prediction-grid">
                    <div class="prediction-card">
                        <div class="prediction-title">DynaMut2</div>
                        {f'<div class="prediction-value"><strong>ΔΔG :</strong> {esc(ddg_txt)} {ddg_badge}</div>' if ddg_val is not None else ''}
                        <div class="prediction-value"><strong>Page résultats :</strong> {link_or_dash(d.get('dyn_url'))}</div>
                    </div>
                    <div class="prediction-card">
                        <div class="prediction-title">INPS-MD</div>
                        <div class="prediction-value"><strong>Job :</strong> {link_or_dash(d.get('inps_url'))}</div>
                    </div>
                </div>
            </div>

            <h2>Visualisation 3D</h2>
            <div style="background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 5px solid #2c5aa0;">
                <p style="font-size: 15pt; color: #2c3e50; margin: 0; line-height: 1.8;">
                    Une visualisation 3D interactive de la protéine est disponible dans l'application. 
                    Cette vue permet d'examiner la structure tridimensionnelle et l'impact de la mutation 
                    sur la conformation protéique selon le modèle AlphaFold.
                </p>
            </div>

            <h2>Documentation Annexe</h2>
            <div class="figures-list">
                <h3 style="color: #2c5aa0; margin-top: 0;">Figures et Visualisations</h3>
                <p style="font-size: 14pt; color: #495057;">Les figures suivantes sont disponibles aux pages suivantes :</p>
                {figures_list}
            </div>

            <h3>Pièces jointes</h3>
            {att_block}

            <div class="methods-section">
                {methods}
            </div>
            
            <!-- Pied de page avec version du logiciel -->
            <div style="margin-top: 40px; padding: 15px; border-top: 1px solid #dee2e6; font-size: 10pt; color: #6c757d; text-align: center;">
                <p>Rapport généré par MutViewer v{APP_VERSION}</p>
            </div>
        """

        return f"""<!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"/>{style}</head>
        <body>
            {page_content}
        </body>
        </html>"""

    # ---------- HTML building (clinician-friendly layout) ----------
    def _build_report_html(self, d: dict) -> str:
                """
                Mise en page améliorée et lisible par cliniciens :
                - Page de garde avec titre centré et sous-titre (Gène / Mutation / Date)
                - Résumé exécutif en tableau à fond gris
                - Encadrés prédictions (DynaMut2 / INPS-MD) avec badges
                - Captures d’écran numérotées et légendées (Figure 1, 2, 3)
                - Liste des pièces jointes
                - Méthodes
                """

                # -------- Helpers --------
                def esc(s):
                        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

                def link_or_dash(url, label=None):
                        if url:
                                lbl = esc(label) if label else esc(url)
                                return f'<a href="{url}">{lbl}</a>'
                        return "—"

                def badge(txt):
                        return f'<span class="badge">{esc(txt)}</span>'

                # Badges ΔΔG
                ddg_val = d.get("dyn_prediction_ddg")
                ddg_txt = f"{ddg_val:.2f} kcal/mol" if ddg_val is not None else "—"
                ddg_note = d.get("dyn_prediction_note") or ""
                if ddg_note.lower().startswith("stabil"):
                        ddg_badge = badge("Stabilisant")
                elif ddg_note.lower().startswith("déstab") or ddg_note.lower().startswith("destab"):
                        ddg_badge = badge("Déstabilisant")
                elif ddg_val is None:
                        ddg_badge = badge("ND")
                else:
                        ddg_badge = badge("Neutre")

                # Figures (numérotation auto si présentes)
                figs = []
                if d.get("viewer_capture_png"):
                        figs.append(("Visualisation 3D du modèle AlphaFold",
                                                 d["viewer_capture_png"]))
                if d.get("dynamut_capture_png"):
                        figs.append(("Résultats DynaMut2",
                                                 d["dynamut_capture_png"]))
                if d.get("inpsmd_capture_png"):
                        figs.append(("Page INPS-MD",
                                                 d["inpsmd_capture_png"]))

                figures_html = ""
                figures_list = ""
                figures_pages = ""
                if figs:
                        parts = []
                        for i, (caption, path) in enumerate(figs, start=1):
                                p = 'file:///' + path.replace('\\', '/')
                                parts.append(
                                        f"""
                                        <figure>
                                            <img src="{p}" alt="{esc(caption)}"/>
                                            <figcaption>Figure {i} — {esc(caption)}</figcaption>
                                        </figure>
                                        """
                                )
                        figures_html = "<h2>Captures d’écran</h2>" + "".join(parts)

                # Nouvelles variables pour le layout professionnel PDF
                if figs:
                        list_items = []
                        pages_content = []
                        
                        for i, (caption, path) in enumerate(figs, start=1):
                                # Item pour la liste page 1
                                list_items.append(f"<li>{esc(caption)} (Page {i+1})</li>")
                                
                                # Page séparée pour l'image
                                p_fig = 'file:///' + path.replace('\\', '/')
                                page_content = f"""
                                    <div class="image-page">
                                        <img src="{p_fig}" alt="{esc(caption)}" class="full-image"/>
                                        <p class="image-caption">{esc(caption)}</p>
                                    </div>
                                    <div class="page-break"></div>
                                """
                                pages_content.append(page_content)
                        
                        figures_list = "<ul>" + "".join(list_items) + "</ul>"
                        figures_pages = "".join(pages_content)
                else:
                        figures_list = "<p><em>Aucune figure disponible</em></p>"

                # Attachments pour la page de résumé
                att_list = ""
                for p in (d.get("attachments") or []):
                        att_list += f"<li>{esc(os.path.basename(p))}</li>"
                att_block = f"<ul class='attach-list'>{'<li>Aucune pièce jointe</li>' if not att_list else att_list}</ul>"

                # Liens externes
                protvar = link_or_dash(d.get("protvar_url"), "ProtVar (EBI)")
                miztli = link_or_dash(d.get("miztli_url"), "Miztli")

                # Données principales
                gene = esc(d.get("gene") or "")
                mut_short = esc(d.get("mutation_short") or "")
                generated_at = esc(d.get("generated_at") or "")
                uniprot = esc(d.get("uniprot") or "")
                hgvsp = esc(d.get("hgvsp") or "")
                mutation_input = esc(d.get("mutation_input") or "")

                # Résumé exécutif
                resume_table = f"""
                <table>
                    <tr><th>Mutation (HGVS)</th><td>{esc(d.get('mutation_input'))}</td></tr>
                    <tr><th>Gène</th><td>{gene or "—"}</td></tr>
                    <tr><th>UniProt</th><td>{esc(d.get('uniprot')) or "—"}</td></tr>
                    <tr><th>HGVSp</th><td>{esc(d.get('hgvsp')) or "—"}</td></tr>
                    <tr><th>Code court</th><td>{mut_short or "—"}</td></tr>
                </table>
                """

                # Prédictions (encadrés)
                dyn_block = f"""
                <div class="card">
                    <h3>DynaMut2</h3>
                    {f'<p><strong>ΔΔG :</strong> {esc(ddg_txt)} {ddg_badge}</p>' if ddg_val is not None else ''}
                    <p><strong>Page résultats :</strong> {link_or_dash(d.get('dyn_url'))}</p>
                </div>
                """

                inps_block = f"""
                <div class="card">
                    <h3>INPS-MD</h3>
                    <p><strong>Job :</strong> {link_or_dash(d.get('inps_url'))}</p>
                </div>
                """

                # Méthodes
                methods = """
                <h2>Méthodes & services consultés</h2>
                <ul class="methods">
                    <li>Ensembl VEP (HGVS → HGVSp / UniProt)</li>
                    <li>AlphaFold DB (modèle PDB)</li>
                    <li>UniProt REST (features)</li>
                    <li>DynaMut2 API (ΔΔG)</li>
                    <li>INPS-MD (soumission & polling)</li>
                    <li>Scène 3D générée via 3Dmol.js</li>
                </ul>
                <p class="footnote">Document généré automatiquement.</p>
                """

                # Aperçu 3D best-effort (si PNG dispo via py3Dmol)
                viewer_preview = ""
                if d.get("viewer_png"):
                        p = 'file:///' + d['viewer_png'].replace('\\', '/')
                        viewer_preview = f"""
                        <h2>Aperçu 3D</h2>
                        <figure>
                            <img src="{p}" alt="Aperçu 3D"/>
                            <figcaption>Prévisualisation du modèle 3D (AlphaFold).</figcaption>
                        </figure>
                        """

                # -------- Styles optimisés pour PDF professionnel --------
                style = """
                <style>
                    @page {
                        size: A4;
                        margin: 15mm;
                    }
                    
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        font-size: 14pt;
                        line-height: 1.8;
                        color: #2c3e50;
                        margin: 0;
                        padding: 20px;
                        background: white;
                    }
                    
                    /* En-tête clinique professionnel */
                    .clinical-header {
                        text-align: center;
                        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                        border: 3px solid #2c5aa0;
                        border-radius: 12px;
                        padding: 40px 30px;
                        margin-bottom: 50px;
                        box-shadow: 0 4px 15px rgba(44, 90, 160, 0.15);
                    }
                    
                    h1 {
                        font-size: 42pt;
                        color: #2c5aa0;
                        margin: 0 0 20px 0;
                        font-weight: 400;
                        letter-spacing: -1px;
                        text-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        text-transform: uppercase;
                    }
                    
                    .clinical-subtitle {
                        font-size: 20pt;
                        color: #495057;
                        margin: 20px 0;
                        font-weight: 300;
                        font-style: italic;
                    }
                    
                    .mutation-badge {
                        display: inline-block;
                        background: transparent;
                        color: #2c5aa0;
                        padding: 15px 30px;
                        border: 3px solid #2c5aa0;
                        border-radius: 25px;
                        font-size: 18pt;
                        font-weight: 700;
                        margin: 20px 0;
                        box-shadow: none;
                    }
                    
                    /* Tableaux professionnels */
                    .professional-table {
                        width: 100%;
                        border-collapse: collapse;
                        margin: 30px 0;
                        background: white;
                        border-radius: 10px;
                        overflow: hidden;
                        box-shadow: 0 5px 15px rgba(0,0,0,0.08);
                    }
                    
                    .professional-table th {
                        background: #2c5aa0;
                        color: white !important;
                        padding: 20px 15px;
                        text-align: left;
                        font-size: 16pt;
                        font-weight: 600;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                        width: 40%;
                    }
                    
                    /* Pour les cellules th dans le corps du tableau (première colonne) */
                    .professional-table tbody th {
                        background: #f8f9fa !important;
                        color: #2c5aa0 !important;
                        font-weight: 700;
                        text-transform: none;
                        font-size: 15pt;
                    }
                    
                    .professional-table td {
                        padding: 18px 15px;
                        border-bottom: 1px solid #e9ecef;
                        font-size: 15pt;
                        vertical-align: top;
                        color: #2c3e50 !important;
                        font-weight: 500;
                    }
                    
                    /* Première colonne (labels) */
                    .professional-table td:first-child {
                        font-weight: 700;
                        color: #2c5aa0;
                        background: #f8f9fa;
                        width: 40%;
                    }
                    
                    /* Deuxième colonne (valeurs) */
                    .professional-table td:last-child {
                        color: #2c3e50;
                        font-weight: 500;
                    }
                    
                    .professional-table tr:nth-child(even) {
                        background: #f8f9fa;
                    }
                    
                    .professional-table tr:nth-child(even) td:first-child {
                        background: #e9ecef;
                    }
                    
                    .professional-table tr:hover {
                        background: #e3f2fd;
                    }
                    
                    .professional-table tr:hover td:first-child {
                        background: #bbdefb;
                    }
                    
                    .table-value {
                        color: #2c3e50;
                        font-weight: 500;
                    }
                    
                    /* Sections avec style clinique */
                    h2 {
                        font-size: 24pt;
                        color: #2c5aa0;
                        margin: 40px 0 25px 0;
                        border-bottom: 3px solid #2c5aa0;
                        padding-bottom: 12px;
                        text-align: left;
                        font-weight: 400;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    }
                    
                    h3 {
                        font-size: 18pt;
                        color: #495057;
                        margin: 25px 0 15px 0;
                        font-weight: 600;
                        text-align: left;
                    }
                    
                    /* Prédictions cliniques */
                    .predictions-container {
                        background: #f8f9fa;
                        border-radius: 12px;
                        padding: 30px;
                        margin: 30px 0;
                        border-left: 6px solid #2c5aa0;
                    }
                    
                    .prediction-grid {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 25px;
                        margin: 20px 0;
                    }
                    
                    .prediction-card {
                        background: white;
                        border-radius: 10px;
                        padding: 25px;
                        box-shadow: 0 3px 10px rgba(0,0,0,0.1);
                        border-top: 4px solid #2c5aa0;
                    }
                    
                    .prediction-title {
                        font-size: 16pt;
                        color: #2c5aa0;
                        font-weight: 700;
                        margin-bottom: 15px;
                        text-transform: uppercase;
                    }
                    
                    .prediction-value {
                        font-size: 15pt;
                        color: #2c3e50;
                        font-weight: 600;
                        margin: 10px 0;
                    }
                    
                    /* Liens externes stylisés */
                    .links-section {
                        background: #e8f4fd;
                        border-radius: 10px;
                        padding: 25px;
                        margin: 30px 0;
                        border: 1px solid #2c5aa0;
                    }
                    
                    .link-item {
                        background: white;
                        padding: 15px 20px;
                        margin: 10px 0;
                        border-radius: 8px;
                        border-left: 4px solid #2c5aa0;
                        font-size: 14pt;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.05);
                    }
                    
                    /* Liste des figures professionnelle */
                    .figures-list {
                        background: #fff;
                        border: 2px solid #e9ecef;
                        border-radius: 10px;
                        padding: 25px;
                        margin: 30px 0;
                    }
                    
                    .figures-list ul {
                        list-style: none;
                        padding: 0;
                        margin: 0;
                    }
                    
                    .figures-list li {
                        padding: 12px 0;
                        border-bottom: 1px solid #e9ecef;
                        font-size: 14pt;
                        color: #2c3e50;
                    }
                    
                    .figures-list li:last-child {
                        border-bottom: none;
                    }
                    
                    /* Méthodes */
                    .methods-section {
                        background: #f1f3f4;
                        border-radius: 10px;
                        padding: 25px;
                        margin: 30px 0;
                        border-left: 5px solid #6c757d;
                    }
                    
                    .methods ul {
                        font-size: 13pt;
                        line-height: 1.8;
                        color: #495057;
                    }
                    
                    /* Style pour les pages d'images */
                    .page-break {
                        page-break-before: always;
                        padding-top: 60px;
                    }
                    
                    .info-value {
                        color: #333;
                    }
                    
                    /* Sections de contenu */
                    .content-section {
                        margin: 30px 0;
                        text-align: left;
                    }
                    
                    h2 {
                        font-size: 18pt;
                        color: #2c5aa0;
                        margin: 30px 0 15px 0;
                        border-bottom: 2px solid #e9ecef;
                        padding-bottom: 8px;
                    }
                    
                    h3 {
                        font-size: 14pt;
                        color: #495057;
                        margin: 20px 0 10px 0;
                    }
                    
                    /* Prédictions */
                    .predictions {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 20px;
                        margin: 20px 0;
                    }
                    
                    .prediction-card {
                        border: 1px solid #dee2e6;
                        border-radius: 8px;
                        padding: 15px;
                        background: #fff;
                    }
                    
                    .prediction-card h3 {
                        color: #2c5aa0;
                        margin-top: 0;
                        font-size: 14pt;
                    }
                    
                    .badge {
                        display: inline-block;
                        padding: 4px 12px;
                        font-size: 10pt;
                        border-radius: 20px;
                        background: #e3f2fd;
                        color: #1976d2;
                        margin-left: 8px;
                        font-weight: 500;
                    }
                    
                    /* Liens et listes */
                    .links-section {
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 8px;
                        margin: 20px 0;
                    }
                    
                    .external-links {
                        display: flex;
                        gap: 15px;
                        flex-wrap: wrap;
                    }
                    
                    .external-links a {
                        display: inline-block;
                        padding: 8px 16px;
                        background: #2c5aa0;
                        color: white;
                        text-decoration: none;
                        border-radius: 6px;
                        font-weight: 500;
                    }
                    
                    ul.fig-list, ul.attach-list {
                        list-style-type: none;
                        padding: 0;
                    }
                    
                    ul.fig-list li, ul.attach-list li {
                        padding: 8px 0;
                        border-bottom: 1px solid #eee;
                    }
                    
                    .methods-list {
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 8px;
                        margin: 15px 0;
                    }
                    
                    .methods-list ul {
                        margin: 0;
                        padding-left: 20px;
                    }
                    
                    .methods-list li {
                        margin: 8px 0;
                    }
                    
                    /* Pages d'images */
                    .image-page {
                        page-break-before: always;
                        text-align: center;
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                        align-items: center;
                        min-height: 90vh;
                    }
                    
                    .image-page img {
                        max-width: 100%;
                        max-height: 80vh;
                        width: auto;
                        height: auto;
                        object-fit: contain;
                        border: 1px solid #ddd;
                        border-radius: 8px;
                        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                    }
                    
                    .image-caption {
                        font-size: 14pt;
                        color: #2c5aa0;
                        margin-top: 20px;
                        font-weight: 600;
                    }
                    
                    .footnote {
                        font-size: 10pt;
                        color: #666;
                        margin-top: 30px;
                        text-align: center;
                    }
                </style>
                """

                # -------- Assemblage --------
                # Page 1: Contenu textuel professionnel
                page1_content = f"""
                    <div class="clinical-header">
                        <h1>Rapport de Mutation Moléculaire</h1>
                        {('<div class="mutation-badge">Gène '+gene+' — Mutation '+mut_short+'</div>') if (gene or mut_short) else ""}
                        <div style="font-size: 16pt; color: #6c757d; margin-top: 25px;">
                            <strong>Date de génération :</strong> {generated_at or "—"}
                        </div>
                    </div>

                    <h2>Résumé Exécutif</h2>
                    <div style="overflow-x: auto;">
                        {resume_table.replace('<table', '<table class="professional-table"')}
                    </div>

                    <h2>Ressources Externes</h2>
                    <div class="links-section">
                        <div class="link-item"><strong>ProtVar :</strong> {protvar}</div>
                        <div class="link-item"><strong>Miztli :</strong> {miztli}</div>
                    </div>

                    <h2>Prédictions Bio-informatiques</h2>
                    <div class="predictions-container">
                        <div class="prediction-grid">
                            <div class="prediction-card">
                                <div class="prediction-title">DynaMut2</div>
                                {dyn_block}
                            </div>
                            <div class="prediction-card">
                                <div class="prediction-title">INPS-MD</div>
                                {inps_block}
                            </div>
                        </div>
                    </div>

                    <h2>Visualisation 3D</h2>
                    <div style="background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 5px solid #2c5aa0;">
                        <p style="font-size: 15pt; color: #2c3e50; margin: 0; line-height: 1.8;">
                            Une visualisation 3D interactive de la protéine est disponible dans l'application. 
                            Cette vue permet d'examiner la structure tridimensionnelle et l'impact de la mutation 
                            sur la conformation protéique selon le modèle AlphaFold.
                        </p>
                    </div>

                    <h2>Documentation Annexe</h2>
                    <div class="figures-list">
                        <h3 style="color: #2c5aa0; margin-top: 0;">Figures et Visualisations</h3>
                        <p style="font-size: 14pt; color: #495057;">Les figures suivantes sont disponibles aux pages suivantes :</p>
                        {figures_list}
                    </div>

                    {att_block}

                    <div class="methods-section">
                        {methods}
                    </div>
                    
                    <!-- Pied de page avec version du logiciel -->
                    <div style="margin-top: 40px; padding: 15px; border-top: 1px solid #dee2e6; font-size: 10pt; color: #6c757d; text-align: center;">
                        <p>Rapport généré par MutViewer v{APP_VERSION}</p>
                    </div>
                """

                # Assemblage final avec pages séparées
                html = f"""<!DOCTYPE html>
                <html>
                <head><meta charset="utf-8"/>{style}</head>
                <body>
                    {page1_content}
                    {figures_pages}
                </body>
                </html>"""
                return html


def _patch_mainwindow_for_export():
    # Plus besoin de patching, l'onglet export est maintenant intégré directement
    pass

# ----------------------------------------------------------------------------------------------------------------------
# Fonctions utilitaires pour la pipeline
# ----------------------------------------------------------------------------------------------------------------------

def test_pipeline_connection(host="127.0.0.1", port=8123, token="mutviewer-2024-secure"):
    """
    Fonction utilitaire pour tester la connexion depuis votre pipeline.
    
    Exemple d'utilisation depuis votre pipeline Python :
    from your_script import test_pipeline_connection
    test_pipeline_connection()
    """
    
    # Test avec HGVS
    url = f"http://{host}:{port}/mutviewer/search"
    headers = {"X-Auth-Token": token} if token else {}
    params = {"hgvs": "NM_004304.5(ALK):c.3520T>C"}
    
    # Utilisation de la session robuste avec proxy CHU
    session = create_robust_session(timeout=10, retries=1)
    
    try:
        response = session.get(url, headers=headers, params=params)
        session.close()
        print(f"Test HGVS - Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        session.close()
        print(f"Erreur de connexion: {e}")
        return False

def send_mutation_to_mutviewer(hgvs=None, gene=None, mut=None, host="127.0.0.1", port=8123, token="mutviewer-2024-secure"):
    url = f"http://{host}:{port}/mutviewer/search"
    headers = {"X-Auth-Token": token} if token else {}
    params = {}
    
    if hgvs:
        params["hgvs"] = hgvs
    if gene:
        params["gene"] = gene
    if mut:
        params["mut"] = mut
    
    if not params:
        print("Erreur: Au moins un paramètre (hgvs, gene, mut) doit être fourni")
        return False

    session = create_robust_session(timeout=15, retries=1)
    
    try:
        response = session.get(url, headers=headers, params=params)
        session.close()
        success = response.status_code == 200
        
        if success:
            print(f"✓ Mutation envoyée à MutViewer avec succès")
            print(f"  Paramètres: {params}")
        else:
            print(f"✗ Erreur {response.status_code}: {response.text}")
            
        return success
        
    except requests.exceptions.ConnectionError:
        session.close()
        print("✗ Erreur: MutViewer ne semble pas être en cours d'exécution")
        print(f"   Vérifiez que l'application est démarrée sur {host}:{port}")
        return False
    except Exception as e:
        session.close()
        print(f"✗ Erreur lors de l'envoi: {e}")
        return False

if __name__ == "__main__":
    main()

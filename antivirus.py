import os
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from PIL import Image, ImageDraw, ImageTk
import math
import random
from typing import List, Dict, Set, Tuple, Callable, Optional
import platform
import shutil
import datetime
import hashlib
import re
import queue
import concurrent.futures
import multiprocessing
import sys
import mmap
import zipfile
import tempfile
import urllib.request
import json
import glob

def has_valid_signature(file_path: str) -> bool:
    if platform.system() != "Windows":
        return False

    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                        ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                        ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                        ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                        ("pSignatureSettings", ctypes.c_void_p)]

        action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                      (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.dwUIChoice = 2
        trust_data.fdwRevocationChecks = 0
        trust_data.dwUnionChoice = 1
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = 0
        trust_data.dwProvFlags = 0x10 | 0x1000

        verify = ctypes.windll.wintrust.WinVerifyTrust
        verify.restype = ctypes.c_long
        verify.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
        return verify(None, ctypes.byref(action), ctypes.byref(trust_data)) == 0
    except Exception:
        return False


_worker_engine = None
_worker_stop = None

def _init_scan_worker(target_extensions, trusted_dirs, stop_event):
    global _worker_engine, _worker_stop
    _worker_engine = SimpleAntivirus(trusted_dirs=trusted_dirs)
    _worker_engine.target_extensions = target_extensions
    _worker_stop = stop_event

def _scan_batch(file_paths):
    results = []
    unreadable = 0
    for file_path in file_paths:
        if _worker_stop.is_set():
            break
        details = {}
        threats = _worker_engine.scan_file(file_path, details=details)
        if details["error"]:
            unreadable += 1
        if any(threats.values()):
            results.append((file_path, threats))
    return len(file_paths), results, unreadable


class SignatureDatabase:
    RECORD_SIZE = 20

    def __init__(self, path: str):
        self.path = path
        self._data = b""
        self.count = 0
        self.load()

    def load(self):
        self.close()
        try:
            with open(self.path, 'rb') as f:
                self._data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError):
            self._data = b""
        self.count = len(self._data) // self.RECORD_SIZE

    def close(self):
        if isinstance(self._data, mmap.mmap):
            self._data.close()
        self._data = b""
        self.count = 0

    def __len__(self):
        return self.count

    def __contains__(self, digest: bytes) -> bool:
        size = self.RECORD_SIZE
        data = self._data
        low, high = 0, self.count
        while low < high:
            mid = (low + high) // 2
            record = data[mid * size:(mid + 1) * size]
            if record < digest:
                low = mid + 1
            elif record > digest:
                high = mid
            else:
                return True
        return False


class SimpleAntivirus:
    SIGNATURES_URL = "https://bazaar.abuse.ch/export/txt/sha1/full/"

    TRUSTED_APP_NAMES = ["Microsoft VS Code", "Python", "Opera", "Lunar Client", "Antigravity IDE", "Trae"]
    TRUSTED_ROOT_NAMES = ["Riot Games", "XboxGames", "Epic Games", "Rockstar Games", "GOG Games"]

    def __init__(self, trusted_dirs=None):
        self.malware_signatures: Set[str] = {
            "e1112134b6dcc8bed54e0e34d8ac272795e73d74",
            "a1112134b6dcc8bed54e0e34d8ac272795e73d75",
            "3395856ce81f2b7382dee72602f798b642f14140",
        }

        self.signatures_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures", "malware_sha1.bin")
        self.signature_db = SignatureDatabase(self.signatures_path)

        self._is_windows = platform.system() == "Windows"

        self.trusted_paths_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trusted_paths.txt")
        if trusted_dirs is None:
            trusted_dirs = self.detect_trusted_dirs()
        self.trusted_dirs = tuple(trusted_dirs)

        self.signable_extensions = ('.exe', '.dll', '.msi', '.scr', '.com', '.ps1')

        self.suspicious_patterns = [
            rb"(?i)virus", rb"(?i)malware", rb"(?i)hack", rb"(?i)exploit", rb"(?i)payload",
            rb"(?i)(<script>|</script>)", rb"(?i)(exec\(|eval\(|system\()"
        ]

        self._compiled_suspicious = [re.compile(p) for p in self.suspicious_patterns]

        self._suspicious_literals = {
            rb"(?i)virus": (b"virus",),
            rb"(?i)malware": (b"malware",),
            rb"(?i)hack": (b"hack",),
            rb"(?i)exploit": (b"exploit",),
            rb"(?i)payload": (b"payload",),
            rb"(?i)(<script>|</script>)": (b"<script>", b"</script>"),
            rb"(?i)(exec\(|eval\(|system\()": (b"exec(", b"eval(", b"system("),
        }

        self._suspicious_labels = {
            rb"(?i)virus": "mot-clé « virus »",
            rb"(?i)malware": "mot-clé « malware »",
            rb"(?i)hack": "mot-clé « hack »",
            rb"(?i)exploit": "mot-clé « exploit »",
            rb"(?i)payload": "mot-clé « payload »",
            rb"(?i)(<script>|</script>)": "balise <script>",
            rb"(?i)(exec\(|eval\(|system\()": "appel exec( / eval( / system(",
        }

        self._threat_weights = {
            "Pattern suspect détecté: Décodage base64 suspect": 2,
            "Pattern suspect détecté: Communication Discord suspecte": 3,
            "Pattern suspect détecté: Exécution système suspecte": 2,
            "Pattern suspect détecté: Accès aux données sensibles": 3,
            "Pattern suspect détecté: Exécution PowerShell suspecte": 3,
            "Pattern suspect détecté: Exécution de commandes système": 2,
            "Pattern suspect détecté: Manipulation des comptes utilisateurs": 3,
            "Pattern suspect détecté: Modification du registre Windows": 2,
            "Niveau élevé d'obfuscation détecté": 3,
        }

        self._compiled_content_patterns = [
            (re.compile(r'eval\s*\(|exec\s*\(', re.IGNORECASE | re.MULTILINE), "Code exécuté dynamiquement",
             ((b"eval", b"exec"),)),
            (re.compile(r'base64\.b64decode', re.IGNORECASE | re.MULTILINE), "Décodage base64 suspect",
             ((b"base64.b64decode",),)),
            (re.compile(r'(password|token|cookie).{0,20}=', re.IGNORECASE | re.MULTILINE), "Collecte d'informations sensibles",
             ((b"password", b"token", b"cookie"), (b"=",))),
            (re.compile(r'webhook|discord\.com/api', re.IGNORECASE | re.MULTILINE), "Communication Discord suspecte",
             ((b"webhook", b"discord.com/api"),)),
            (re.compile(r'\\x[0-9a-fA-F]{2}', re.IGNORECASE | re.MULTILINE), "Caractères hexadécimaux encodés",
             ((b"\\x",),)),
            (re.compile(r'chr\s*\(\s*\d+\s*\)', re.IGNORECASE | re.MULTILINE), "Conversion de nombres en caractères",
             ((b"chr",),)),
            (re.compile(r'socket\.socket|subprocess|os\.system', re.IGNORECASE | re.MULTILINE), "Exécution système suspecte",
             ((b"socket.socket", b"subprocess", b"os.system"),)),
            (re.compile(r'(Chrome|Firefox|Discord).*?(Login Data|Local Storage)', re.IGNORECASE | re.MULTILINE), "Accès aux données sensibles",
             ((b"chrome", b"firefox", b"discord"), (b"login data", b"local storage"))),
            (re.compile(r'powershell\s+-\w+\s+', re.IGNORECASE | re.MULTILINE), "Exécution PowerShell suspecte",
             ((b"powershell",),)),
            (re.compile(r'cmd\.exe|command\.exe', re.IGNORECASE | re.MULTILINE), "Exécution de commandes système",
             ((b"cmd.exe", b"command.exe"),)),
            (re.compile(r'net\s+user|net\s+localgroup', re.IGNORECASE | re.MULTILINE), "Manipulation des comptes utilisateurs",
             ((b"net",), (b"user", b"localgroup"))),
            (re.compile(r'reg\s+add|regedit', re.IGNORECASE | re.MULTILINE), "Modification du registre Windows",
             ((b"reg",), (b"add", b"regedit"))),
        ]

        self.quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

        self.max_content_size = 10 * 1024 * 1024

        self.report_min_score = 4

        self.max_workers = min(os.cpu_count() or 4, 61)
        self.walker_threads = min(os.cpu_count() or 4, 8)
        self.batch_size = 64
        self.batch_bytes = 32 * 1024 * 1024
        self.scan_queue = queue.Queue()

        self._stop_event = threading.Event()
        self.last_scan_stats: Dict = {}

    def detect_trusted_dirs(self) -> Tuple[str, ...]:
        found = set()

        if self._is_windows:
            import string
            import winreg

            def read_registry(root, key, name):
                try:
                    with winreg.OpenKey(root, key) as handle:
                        return winreg.QueryValueEx(handle, name)[0]
                except OSError:
                    return None

            program_data = os.environ.get("ProgramData", r"C:\ProgramData")

            found.update([
                os.environ.get("ProgramFiles"),
                os.environ.get("ProgramFiles(x86)"),
                os.environ.get("ProgramW6432"),
                os.environ.get("SystemRoot"),
                os.path.join(program_data, "Microsoft"),
                os.path.join(program_data, "Package Cache"),
            ])

            steam_dirs = {
                read_registry(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
                read_registry(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
            }
            for steam_dir in filter(None, steam_dirs):
                found.add(steam_dir)
                try:
                    with open(os.path.join(steam_dir, "steamapps", "libraryfolders.vdf"), encoding="utf-8", errors="ignore") as f:
                        for library in re.findall(r'"path"\s+"([^"]+)"', f.read()):
                            found.add(os.path.join(library.replace("\\\\", "\\"), "steamapps"))
                except OSError:
                    pass

            for manifest in glob.glob(os.path.join(program_data, "Epic", "EpicGamesLauncher", "Data", "Manifests", "*.item")):
                try:
                    with open(manifest, encoding="utf-8") as f:
                        found.add(json.load(f).get("InstallLocation"))
                except (OSError, ValueError):
                    pass

            local_app_data = os.environ.get("LOCALAPPDATA")
            if local_app_data:
                found.add(os.path.join(local_app_data, "Discord"))
                for name in self.TRUSTED_APP_NAMES:
                    found.add(os.path.join(local_app_data, "Programs", name))

            for letter in string.ascii_uppercase:
                for name in self.TRUSTED_ROOT_NAMES:
                    found.add(f"{letter}:\\{name}")

        found.add(os.path.dirname(os.path.abspath(__file__)))

        try:
            with open(self.trusted_paths_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        found.add(line)
        except OSError:
            pass

        trusted = set()
        for path in filter(None, found):
            path = os.path.abspath(path)
            if os.path.isdir(path) and os.path.dirname(path) != path:
                trusted.add(os.path.normcase(path).rstrip(os.sep) + os.sep)
        return tuple(sorted(trusted))

    def is_trusted_path(self, path: str) -> bool:
        if not self.trusted_dirs:
            return False
        return (os.path.normcase(os.path.abspath(path)) + os.sep).startswith(self.trusted_dirs)

    def stop_scan(self):
        self._stop_event.set()

    def update_signatures(self, source: Optional[str] = None) -> int:
        source = source or self.SIGNATURES_URL
        downloaded = None

        try:
            if os.path.exists(source):
                local_path = source
            else:
                request = urllib.request.Request(source, headers={"User-Agent": "VirusWarp"})
                with urllib.request.urlopen(request, timeout=120) as response, \
                        tempfile.NamedTemporaryFile(delete=False, suffix=".download") as tmp:
                    shutil.copyfileobj(response, tmp)
                    downloaded = local_path = tmp.name

            if zipfile.is_zipfile(local_path):
                with zipfile.ZipFile(local_path) as archive:
                    raw = archive.read(archive.namelist()[0])
            else:
                with open(local_path, 'rb') as f:
                    raw = f.read()
        finally:
            if downloaded and os.path.exists(downloaded):
                os.remove(downloaded)

        digests = set()
        for line in raw.splitlines():
            line = line.strip()
            if len(line) != 40 or line.startswith(b"#"):
                continue
            try:
                digests.add(bytes.fromhex(line.decode('ascii')))
            except ValueError:
                continue

        if not digests:
            raise Exception("Aucune signature valide trouvée dans la source")

        os.makedirs(os.path.dirname(self.signatures_path), exist_ok=True)
        tmp_path = self.signatures_path + ".tmp"
        with open(tmp_path, 'wb') as f:
            f.write(b"".join(sorted(digests)))

        self.signature_db.close()
        try:
            os.replace(tmp_path, self.signatures_path)
        finally:
            self.signature_db.load()

        return len(self.signature_db)

    def calculate_file_hash(self, file_path: str) -> str:
        sha1 = hashlib.sha1()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha1.update(chunk)
            return sha1.hexdigest()
        except Exception as e:
            return ""

    def assess_risk(self, threats: Dict[str, List[str]]) -> Dict:
        if threats["malware_match"]:
            return {"level": "malware", "score": 1000}

        score = min(len(threats["suspicious_patterns"]), 2)
        score += sum(self._threat_weights.get(threat, 1) for threat in threats["content_threats"])
        if score >= 8:
            level = "élevé"
        elif score >= 4:
            level = "moyen"
        elif score >= 1:
            level = "faible"
        else:
            level = "sain"
        return {"level": level, "score": score}

    def scan_file(self, file_path: str, details: Optional[Dict] = None, progress_callback=None) -> Dict[str, List[str]]:
        threats = {"malware_match": [], "suspicious_patterns": [], "content_threats": []}

        if details is None:
            details = {}
        details.update(error=None, empty=False, size=0, sha1=None, trusted_dir=False, signed=False, heuristics=False)

        try:
            try:
                with open(file_path, 'rb') as f:
                    content_buffer = f.read(self.max_content_size)
                    if not content_buffer:
                        details["empty"] = True
                        return threats
                    sha1 = hashlib.sha1(content_buffer)
                    size = len(content_buffer)
                    if progress_callback:
                        progress_callback(size)
                    if size == self.max_content_size:
                        while True:
                            chunk = f.read(1048576)
                            if not chunk:
                                break
                            sha1.update(chunk)
                            size += len(chunk)
                            if progress_callback:
                                progress_callback(size)
                            if _worker_stop is not None and _worker_stop.is_set():
                                return threats
            except OSError as e:
                details["error"] = e.strerror or str(e)
                return threats

            digest = sha1.digest()
            file_hash = digest.hex()
            details["size"] = size
            details["sha1"] = file_hash
            if file_hash in self.malware_signatures or digest in self.signature_db:
                threats["malware_match"].append(f"Malware signature match: {file_hash}")
                return threats

            if self.is_trusted_path(file_path):
                details["trusted_dir"] = True
                return threats

            if file_path.lower().endswith(self.signable_extensions) and has_valid_signature(file_path):
                details["signed"] = True
                return threats

            content_size = len(content_buffer)

            is_executable_or_script = file_path.lower().endswith(tuple(self.target_extensions)) if hasattr(self, 'target_extensions') else True

            if not (content_size < 1048576 or is_executable_or_script):
                return threats

            details["heuristics"] = True

            lowered = content_buffer.lower()

            for pattern, compiled_pat in zip(self.suspicious_patterns, self._compiled_suspicious):
                literals = self._suspicious_literals.get(pattern)
                if literals is not None:
                    found = any(lit in lowered for lit in literals)
                else:
                    found = compiled_pat.search(content_buffer) is not None
                if found:
                    label = self._suspicious_labels.get(pattern) or pattern.decode(errors='replace')
                    threats["suspicious_patterns"].append(f"Élément suspect: {label}")

            if is_executable_or_script:
                content_threats = self.analyze_file_content(file_path, content=content_buffer, lowered=lowered)
                if content_threats:
                    threats["content_threats"].extend(content_threats)

        except Exception as e:
            details["error"] = str(e)

        return threats

    def analyze_file_content(self, file_path, content=None, lowered=None):
        try:
            if content is None:
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read(50 * 1024 * 1024)
                except (PermissionError, OSError):
                    return []

            if lowered is None:
                lowered = content.lower()

            text_content = None

            threats = []

            for compiled_pattern, description, prefilter in self._compiled_content_patterns:
                if not all(any(kw in lowered for kw in group) for group in prefilter):
                    continue
                if text_content is None:
                    text_content = content.decode('utf-8', errors='ignore')
                if compiled_pattern.search(text_content):
                    threats.append(f"Pattern suspect détecté: {description}")
                    if len(threats) >= 5:
                        break

            if b'\\x' in content:
                if text_content is None:
                    text_content = content.decode('utf-8', errors='ignore')
                if text_content.count('\\x') > len(text_content) * 0.05:
                    threats.append("Niveau élevé d'obfuscation détecté")

            return threats

        except Exception as e:
            return [f"Erreur lors de l'analyse: {str(e)}"]

    def batch_scan_worker(self, callback=None):
        while True:
            try:
                file_info = self.scan_queue.get(timeout=1)
                if file_info is None:
                    break

                file_path, scan_results = file_info

                threats = self.scan_file(file_path)

                if any(threats.values()):
                    with scan_results[0]:
                        scan_results[1].append((file_path, threats))
                        if callback:
                            callback(file_path, threats)

                self.scan_queue.task_done()
            except queue.Empty:
                continue
            except Exception:
                if 'file_info' in locals():
                    self.scan_queue.task_done()

    def file_collector_worker(self, dir_queue, all_excluded, ignored_names, target_extensions, file_queue, stop_event, stats_lock, stats):
        high_priority_exts = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.hta', '.scr', '.com', '.pif'}

        while True:
            root = dir_queue.get()
            try:
                if root is None:
                    return
                if stop_event.is_set():
                    continue

                root_lower = root.lower()
                is_user_dir = "\\users\\" in root_lower or "/home/" in root_lower
                base_priority = 1 if is_user_dir else 2

                files_found = 0
                files_seen = 0

                with os.scandir(root) as entries:
                    for entry in entries:
                        try:
                            name = entry.name

                            if entry.is_dir(follow_symlinks=False):
                                if name in ignored_names:
                                    continue
                                if self._is_windows and entry.is_junction():
                                    continue
                                if os.path.normcase(entry.path).startswith(all_excluded):
                                    continue
                                dir_queue.put(entry.path)
                                continue

                            files_seen += 1

                            _, ext = os.path.splitext(name.lower())
                            if ext not in target_extensions:
                                continue

                            if not entry.is_file():
                                continue
                            size = entry.stat().st_size
                            if size == 0:
                                continue

                            if ext in high_priority_exts:
                                file_priority = base_priority
                            else:
                                file_priority = base_priority + 1

                            file_queue.put((file_priority, entry.path, size))
                            files_found += 1

                        except OSError:
                            continue

                if files_seen:
                    with stats_lock:
                        stats["files_seen"] += files_seen
                        if files_found:
                            stats["files_found"] += files_found
                            stats["current_directory"] = root
                            if self.is_trusted_path(root):
                                stats["files_trusted"] += files_found

            except OSError:
                pass
            except Exception as e:
                with stats_lock:
                    stats["errors"].append(f"Erreur de collecte: {str(e)}")
            finally:
                dir_queue.task_done()

    def _next_batch(self, file_queue, wait):
        batch = []
        batch_bytes = 0
        collecting = True

        while len(batch) < self.batch_size and batch_bytes < self.batch_bytes:
            try:
                if batch:
                    _, file_path, size = file_queue.get_nowait()
                else:
                    _, file_path, size = file_queue.get(timeout=wait)
            except queue.Empty:
                break

            if file_path is None:
                collecting = False
                break

            batch.append(file_path)
            batch_bytes += size

        return batch, collecting

    def scan_system(self, callback=None, progress_callback=None, roots=None) -> List[Tuple[str, Dict[str, List[str]]]]:
        detected_threats = []
        stop_event = self._stop_event
        stop_event.clear()

        stats_lock = threading.Lock()
        stats = {
            "files_seen": 0,
            "files_found": 0,
            "files_trusted": 0,
            "files_analyzed": 0,
            "files_unreadable": 0,
            "files_minor": 0,
            "threats_found": 0,
            "current_directory": "",
            "current_file": "",
            "start_time": time.time(),
            "errors": [],
            "collecting": True,
            "finished": False,
            "cancelled": False
        }

        def snapshot():
            with stats_lock:
                snap = dict(stats)
                snap["errors"] = list(stats["errors"])
            snap["elapsed"] = time.time() - snap["start_time"]
            snap["speed"] = snap["files_analyzed"] / snap["elapsed"] if snap["elapsed"] > 0 else 0
            return snap

        if self._is_windows:
            import string
            from ctypes import windll

            drives = []
            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1

            excluded_dirs = [
                "C:\\System Volume Information",
                "C:\\$Recycle.Bin",
                "C:\\Windows\\WinSxS",
                "C:\\Windows\\Installer",
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64",
            ]
            ignored_names = {
                "node_modules", ".git", ".vscode", ".idea", "__pycache__", "vendor",
                "site-packages", "gems", "cargo", "go", "npm-cache"
            }

            target_extensions = {'.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.py', '.jar', '.msi',
                               '.php', '.html', '.htm', '.hta', '.scr', '.com', '.pif', '.wsf', '.wsh', '.reg'}
        else:
            drives = [os.path.expanduser("~")]
            excluded_dirs = ["/proc", "/sys", "/dev", "/run", "/var/run", "/tmp"]
            ignored_names = {
                "node_modules", ".git", ".vscode", ".idea", "__pycache__", "vendor",
                "site-packages", "gems"
            }
            target_extensions = {'.out', '.bin', '.sh', '.py', '.js', '.php', '.html', '.htm', '.jar', '.pl', '.rb',
                               '.deb', '.rpm', '.so', '.ko'}

        if roots is not None:
            drives = list(roots)

        self.target_extensions = target_extensions

        all_excluded = tuple(os.path.normcase(d) for d in excluded_dirs + [self.quarantine_dir])

        file_queue = queue.PriorityQueue()
        dir_queue = queue.Queue()

        for drive in drives:
            if os.path.exists(drive):
                dir_queue.put(drive)

        collectors = []
        for _ in range(self.walker_threads):
            collector = threading.Thread(
                target=self.file_collector_worker,
                args=(dir_queue, all_excluded, ignored_names, target_extensions, file_queue, stop_event, stats_lock, stats)
            )
            collector.daemon = True
            collector.start()
            collectors.append(collector)

        def finish_collection():
            dir_queue.join()
            for _ in collectors:
                dir_queue.put(None)
            with stats_lock:
                stats["collecting"] = False
            file_queue.put((999, None, 0))

        collection_watcher = threading.Thread(target=finish_collection)
        collection_watcher.daemon = True
        collection_watcher.start()

        worker_stop = multiprocessing.Event()
        executor = concurrent.futures.ProcessPoolExecutor(
            max_workers=self.max_workers,
            initializer=_init_scan_worker,
            initargs=(target_extensions, self.trusted_dirs, worker_stop)
        )

        pending = {}
        max_pending = self.max_workers * 2
        collecting = True
        last_progress_time = time.time()

        try:
            while (collecting or pending) and not stop_event.is_set():
                while collecting and len(pending) < max_pending:
                    batch, collecting = self._next_batch(file_queue, wait=0 if pending else 0.05)
                    if not batch:
                        break
                    pending[executor.submit(_scan_batch, batch)] = len(batch)

                if pending:
                    done_futures, _ = concurrent.futures.wait(
                        pending, timeout=0.05, return_when=concurrent.futures.FIRST_COMPLETED
                    )

                    analyzed = 0
                    unreadable = 0
                    batch_threats = []
                    batch_errors = []

                    for future in done_futures:
                        batch_len = pending.pop(future)
                        analyzed += batch_len

                        try:
                            _, results, batch_unreadable = future.result()
                            batch_threats.extend(results)
                            unreadable += batch_unreadable
                        except Exception as e:
                            batch_errors.append(f"Erreur d'analyse d'un lot de {batch_len} fichiers: {str(e)}")

                    if done_futures:
                        reported = [(path, threats) for path, threats in batch_threats
                                    if self.assess_risk(threats)["score"] >= self.report_min_score]
                        minor = len(batch_threats) - len(reported)
                        batch_threats = reported
                        detected_threats.extend(batch_threats)

                        with stats_lock:
                            stats["files_analyzed"] += analyzed
                            stats["files_unreadable"] += unreadable
                            stats["threats_found"] += len(batch_threats)
                            stats["files_minor"] += minor
                            if batch_threats:
                                stats["current_file"] = batch_threats[-1][0]
                            if batch_errors:
                                stats["errors"].extend(batch_errors)

                        if callback:
                            for path, threats in batch_threats:
                                callback(path, threats)

                if progress_callback:
                    now = time.time()
                    if (now - last_progress_time) >= 0.25:
                        last_progress_time = now
                        progress_callback(snapshot())

        except Exception as e:
            with stats_lock:
                stats["errors"].append(f"Erreur générale: {str(e)}")
        finally:
            cancelled = stop_event.is_set()
            if cancelled:
                worker_stop.set()
            stop_event.set()

            executor.shutdown(wait=True, cancel_futures=True)

            collection_watcher.join(timeout=2.0)
            for collector in collectors:
                collector.join(timeout=2.0)

            with stats_lock:
                stats["collecting"] = False
                stats["finished"] = True
                stats["cancelled"] = cancelled

            self.last_scan_stats = snapshot()
            if progress_callback:
                progress_callback(self.last_scan_stats)

        return detected_threats

    def move_to_quarantine(self, file_path: str) -> str:
        try:
            if not os.path.exists(file_path):
                raise Exception(f"Le fichier n'existe pas: {file_path}")
                
            file_name = os.path.basename(file_path)
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            quarantine_name = f"{timestamp}_{file_name}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            info_path = f"{quarantine_path}.info"
            with open(info_path, 'w') as f:
                f.write(f"Original path: {file_path}\n")
                f.write(f"Quarantine date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"File size: {os.path.getsize(file_path)} bytes\n")
            
            shutil.move(file_path, quarantine_path)
            
            return quarantine_path
        except Exception as e:
            raise Exception(f"Erreur lors de la mise en quarantaine: {str(e)}")


class CircularProgress(tk.Canvas):
    SUPERSAMPLING = 4

    def __init__(self, master, size, bg, track_color, start_color, end_color, text_color, subtext_color):
        super().__init__(master, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        self._size = size
        self._bg = bg
        self._track_color = track_color
        self._start_color = start_color
        self._end_color = end_color
        self._thickness = max(6, size // 11)

        self._target = 0.0
        self._shown = 0.0
        self._forced_color = None
        self._text = None
        self._animation_job = None
        self._photo = None

        self._image_item = self.create_image(0, 0, anchor="nw")
        self._text_item = self.create_text(
            size / 2, size / 2 - size * 0.05, fill=text_color, font=("Segoe UI", -int(size * 0.22), "bold")
        )
        self._subtext_item = self.create_text(
            size / 2, size / 2 + size * 0.14, fill=subtext_color, font=("Segoe UI", -int(size * 0.075)),
            width=size - 4 * self._thickness, justify="center"
        )

        self.bind("<Destroy>", self._on_destroy)
        self._render()

    @staticmethod
    def _mix(color_a, color_b, ratio):
        a = [int(color_a[i:i + 2], 16) for i in (1, 3, 5)]
        b = [int(color_b[i:i + 2], 16) for i in (1, 3, 5)]
        return "#" + "".join(f"{int(x + (y - x) * ratio):02x}" for x, y in zip(a, b))

    def set(self, ratio, color=None, text=None, subtext=None):
        try:
            self._target = max(0.0, min(1.0, ratio))
            self._forced_color = color
            self._text = text
            if subtext is not None:
                self.itemconfigure(self._subtext_item, text=subtext)
            if self._animation_job is None:
                self._animate()
        except tk.TclError:
            pass

    def reset(self, subtext=""):
        try:
            self._target = self._shown = 0.0
            self._forced_color = None
            self._text = None
            self.itemconfigure(self._subtext_item, text=subtext)
            self._render()
        except tk.TclError:
            pass

    def _animate(self):
        self._animation_job = None
        try:
            gap = self._target - self._shown
            if abs(gap) < 0.004:
                self._shown = self._target
                self._render()
                return
            self._shown += gap * 0.25
            self._render()
            self._animation_job = self.after(16, self._animate)
        except tk.TclError:
            pass

    def _render(self):
        scale = self.SUPERSAMPLING
        size = self._size * scale
        width = self._thickness * scale
        box = (0, 0, size - 1, size - 1)

        image = Image.new("RGB", (size, size), self._bg)
        draw = ImageDraw.Draw(image)
        draw.arc(box, 0, 360, fill=self._track_color, width=width)

        if self._shown > 0:
            color = self._forced_color or self._mix(self._start_color, self._end_color, self._shown)
            sweep = 360 * self._shown
            draw.arc(box, -90, -90 + sweep, fill=color, width=width)
            radius = (size - width) / 2
            for angle in (-90, -90 + sweep):
                x = size / 2 + radius * math.cos(math.radians(angle))
                y = size / 2 + radius * math.sin(math.radians(angle))
                draw.ellipse((x - width / 2, y - width / 2, x + width / 2, y + width / 2), fill=color)

        self._photo = ImageTk.PhotoImage(image.resize((self._size, self._size), Image.LANCZOS))
        self.itemconfigure(self._image_item, image=self._photo)
        self.itemconfigure(self._text_item, text=self._text if self._text is not None else f"{self._shown * 100:.0f}%")

    def _on_destroy(self, event):
        if self._animation_job is not None:
            try:
                self.after_cancel(self._animation_job)
            except tk.TclError:
                pass
            self._animation_job = None


class ModernAntivirusGUI:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.colors = {
            "background": "#1a1b26",         
            "background_accent": "#24283b",  
            "background_grid": "#292e42",      
            "scan_file": "#3d59a1",          
            "scan_system": "#4B4887",         
            "realtime_protection": "#614C82", 
            "text_primary": "#c0caf5",         
            "text_secondary": "#a9b1d6",     
            "highlight": "#787c99",           
            "progress_bar": "#4B4887",    
            "status_bar": "#1a1b26",        
            "modal_overlay": "#1a1b26"       
        }
        
        self.ring_colors = {"start": "#7aa2f7", "end": "#9ece6a"}
        self.verdict_colors = {
            "sain": "#9ece6a",
            "faible": "#e0af68",
            "moyen": "#ff9e64",
            "élevé": "#f7768e",
            "malware": "#f7768e",
            "erreur": "#a9b1d6"
        }
        self.verdict_labels = {
            "sain": "Sain",
            "faible": "Risque faible",
            "moyen": "Risque moyen",
            "élevé": "Risque élevé",
            "malware": "Malware connu"
        }

        self.modal_window = None
        self.modal_content = None
        self.modal_visible = False
        
        self.animation = {
            "enabled": True,               
            "duration": 250,              
            "steps": 10,                   
            "card_expansion_height": 400, 
            "animation_in_progress": False 
        }
        
        self.background = {
            "animated": True,         
            "update_interval": 50,    
            "particles_count": 50,  
            "grid_spacing": 40,        
            "grid_opacity": 0.1,       
            "particle_size_range": (1, 3),
            "particle_speed_range": (0.2, 1.0), 
            "particles": []        
        }
        
        self.app = ctk.CTk()
        self.app.title("VirusWarp")
        self.app.geometry("1000x700")
        self.app.resizable(True, True)
        self.app.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.ico"))
        
        self.app.configure(fg_color=self.colors["background"])
        
        self.stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "scan_start_time": None,
            "scan_end_time": None
        }
        
        self.antivirus = SimpleAntivirus()
        self.detected_threats = []
        
        self.expand_icons = {}
        self.card_frames = {}
        self.card_content_frames = {}
        self.expanded_card = None
        
        self.create_gui()
        
    def create_gui(self):
        
        self.create_background_canvas()
        
        title_frame = ctk.CTkFrame(self.app, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=(30, 20))
        
        title = ctk.CTkLabel(
            title_frame,
            text="VirusWarp",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        title.pack(pady=(10, 5))
        
        subtitle = ctk.CTkLabel(
            title_frame,
            text="Protection avancée contre les menaces numériques",
            font=ctk.CTkFont(size=14),
            text_color=self.colors["text_secondary"]
        )
        subtitle.pack(pady=(0, 10))
        
        self.cards_frame = ctk.CTkFrame(self.app, fg_color="transparent")
        self.cards_frame.pack(expand=True, padx=50, pady=20)
        
        self.cards_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="column")
        
        self.create_card("scan_file", "Scanner un fichier", "", self.colors["scan_file"], 0, 0)
        
        self.create_card("scan_system", "Analyser la machine", "", self.colors["scan_system"], 0, 1)
        
        self.create_card("realtime_protection", "Protection en temps réel", "", self.colors["realtime_protection"], 0, 2)
        
        self.realtime_protection_active = False
        
        self.status_bar = ctk.CTkLabel(
            self.app,
            text="Prêt",
            height=30,
            fg_color=self.colors["status_bar"],
            text_color=self.colors["text_primary"],
            corner_radius=0
        )
        self.status_bar.pack(fill="x", side="bottom", padx=0, pady=0)
        
    def create_background_canvas(self):
        self.bg_frame = ctk.CTkFrame(self.app, fg_color=self.colors["background"])
        self.bg_frame.pack(fill="both", expand=True)
        
        self.bg_canvas = tk.Canvas(
            self.bg_frame,
            highlightthickness=0, 
            bg=self.colors["background"]
        )
        self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        
        self.bg_frame.lower()
        
        self.initialize_particles()
        
        if self.background["animated"]:
            self.animate_background()
        else:
            self.draw_background()
    
    def initialize_particles(self):
        self.background["particles"] = []
        
        width = self.app.winfo_width() or 1000  
        height = self.app.winfo_height() or 700
        
        for _ in range(self.background["particles_count"]):
            particle = {
                "x": random.uniform(0, width),
                "y": random.uniform(0, height),
                "size": random.uniform(*self.background["particle_size_range"]),
                "speed": random.uniform(*self.background["particle_speed_range"]),
                "angle": random.uniform(0, 2 * math.pi),
                "opacity": random.uniform(0.1, 0.5)
            }
            self.background["particles"].append(particle)
    
    def draw_background(self):
        self.bg_canvas.delete("all")
        
        width = self.app.winfo_width() or 1000
        height = self.app.winfo_height() or 700
        
        for y in range(0, height, 2):
            ratio = y / height
            r_val = int(int(self.colors["background"][1:3], 16) * (1 - ratio * 0.2))
            g_val = int(int(self.colors["background"][3:5], 16) * (1 - ratio * 0.2))
            b_val = int(int(self.colors["background"][5:7], 16) * (1 - ratio * 0.2))
            
            r_val = max(0, min(255, r_val))
            g_val = max(0, min(255, g_val))
            b_val = max(0, min(255, b_val))
            
            color = f"#{r_val:02x}{g_val:02x}{b_val:02x}"
            
            self.bg_canvas.create_line(0, y, width, y, fill=color)
        
        grid_spacing = self.background["grid_spacing"]
        grid_color_with_opacity = self.apply_opacity(self.colors["background_grid"], self.background["grid_opacity"])
        
        for y in range(0, height, grid_spacing):
            self.bg_canvas.create_line(0, y, width, y, fill=grid_color_with_opacity, dash=(1, 3))
        
        for x in range(0, width, grid_spacing):
            self.bg_canvas.create_line(x, 0, x, height, fill=grid_color_with_opacity, dash=(1, 3))
        
        for particle in self.background["particles"]:
            particle_color_with_opacity = self.apply_opacity(self.colors["highlight"], particle["opacity"])
            
            self.bg_canvas.create_oval(
                particle["x"] - particle["size"],
                particle["y"] - particle["size"],
                particle["x"] + particle["size"],
                particle["y"] + particle["size"],
                fill=particle_color_with_opacity,
                outline=""
            )
    
    def animate_background(self):
        self.draw_background()
        
        width = self.app.winfo_width() or 1000
        height = self.app.winfo_height() or 700
        
        for particle in self.background["particles"]:
            particle["x"] += math.cos(particle["angle"]) * particle["speed"]
            particle["y"] += math.sin(particle["angle"]) * particle["speed"]
            
            particle["opacity"] = max(0.1, min(0.5, particle["opacity"] + random.uniform(-0.02, 0.02)))
            
            if (particle["x"] < -10 or particle["x"] > width + 10 or 
                    particle["y"] < -10 or particle["y"] > height + 10):
                particle["x"] = random.uniform(0, width)
                particle["y"] = random.uniform(0, height)
                particle["angle"] = random.uniform(0, 2 * math.pi)
        
        if self.background["animated"]:
            self.app.after(self.background["update_interval"], self.animate_background)
    
    def apply_opacity(self, hex_color, opacity):
        r, g, b = int(hex_color[1:3], 16), int(hex_color[3:5], 16), int(hex_color[5:7], 16)
        
        bg_r, bg_g, bg_b = int(self.colors["background"][1:3], 16), int(self.colors["background"][3:5], 16), int(self.colors["background"][5:7], 16)
        
        r = int(r * opacity + bg_r * (1 - opacity))
        g = int(g * opacity + bg_g * (1 - opacity))
        b = int(b * opacity + bg_b * (1 - opacity))
        
        return f"#{r:02x}{g:02x}{b:02x}"
    
    def create_card(self, card_id, title, icon, color, row, column):
        card_frame = ctk.CTkFrame(
            self.cards_frame, 
            fg_color=color, 
            corner_radius=15,
            border_width=1,
            border_color=self.colors["highlight"]
        )
        card_frame.grid(row=row, column=column, padx=10, pady=10, sticky="nsew")
        self.card_frames[card_id] = card_frame
        
        header_frame = ctk.CTkFrame(card_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=5)
        
        header_label = ctk.CTkLabel(
            header_frame,
            text=f"{icon} {title}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        header_label.pack(side="left", padx=5)
        
        descriptions = {
            "scan_file": "Analysez un fichier spécifique pour détecter les menaces",
            "scan_system": "Vérifiez l'ensemble de votre système",
            "realtime_protection": "Protégez votre ordinateur en continu"
        }
        
        description_label = ctk.CTkLabel(
            card_frame,
            text=descriptions.get(card_id, ""),
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"],
            wraplength=200
        )
        description_label.pack(padx=10, pady=5)
        
        def on_click(event):
            self.show_modal(card_id)
            
        def on_enter(event):
            card_frame.configure(fg_color=self.adjust_color_brightness(color, 20))
            
        def on_leave(event):
            card_frame.configure(fg_color=color)
            
        for widget in [card_frame, header_frame, header_label]:
            widget.bind("<Button-1>", on_click)
            
        card_frame.bind("<Enter>", on_enter)
        card_frame.bind("<Leave>", on_leave)
    
    def show_modal(self, card_id):
        if self.modal_visible:
            self.content_frame.configure(fg_color=self.colors[card_id])
            
            titles = {
                "scan_file": "Scanner un fichier",
                "scan_system": "Analyser la machine",
                "realtime_protection": "Protection en temps réel"
            }
            self.title_label.configure(text=titles.get(card_id, ""))
            
            for widget in self.modal_content.winfo_children():
                widget.destroy()
                
            if card_id == "scan_file":
                self.create_scan_file_content(self.modal_content)
            elif card_id == "scan_system":
                self.create_scan_system_content(self.modal_content)
            elif card_id == "realtime_protection":
                self.create_protection_content(self.modal_content)
            return
            
        self.modal_overlay = ctk.CTkFrame(self.app, fg_color=self.colors["background"])
        self.modal_overlay.place(relx=0.5, rely=0.55, anchor="center", relwidth=0.9, relheight=0.78)
        
        self.content_frame = ctk.CTkFrame(
            self.modal_overlay,
            fg_color=self.colors[card_id],
            corner_radius=15
        )
        self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        header_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=5)
        
        titles = {
            "scan_file": "Scanner un fichier",
            "scan_system": "Analyser la machine",
            "realtime_protection": "Protection en temps réel"
        }
        
        self.title_label = ctk.CTkLabel(
            header_frame,
            text=titles.get(card_id, ""),
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        self.title_label.pack(side="left", padx=10)
        
        close_button = ctk.CTkButton(
            header_frame,
            text="×",
            width=30,
            font=ctk.CTkFont(size=20),
            command=self.hide_modal,
            fg_color="transparent",
            hover_color=self.adjust_color_brightness(self.colors[card_id], -20)
        )
        close_button.pack(side="right", padx=10)
        
        self.modal_content = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.modal_content.pack(fill="both", expand=True, padx=20, pady=20)
        
        if card_id == "scan_file":
            self.create_scan_file_content(self.modal_content)
        elif card_id == "scan_system":
            self.create_scan_system_content(self.modal_content)
        elif card_id == "realtime_protection":
            self.create_protection_content(self.modal_content)
            
        self.modal_visible = True
    
    def hide_modal(self):
        if hasattr(self, 'modal_overlay'):
            self.modal_overlay.destroy()
            self.modal_content = None
            self.modal_visible = False
    
    def _build_scan_panel(self, content_frame, color_key, placeholder):
        base_color = self.colors[color_key]
        try:
            scaling = ctk.ScalingTracker.get_window_scaling(self.app)
        except Exception:
            scaling = 1.0

        left = ctk.CTkFrame(content_frame, fg_color="transparent", width=230)
        left.pack(side="left", fill="y", padx=(0, 15))
        left.pack_propagate(False)

        ring = CircularProgress(
            left,
            size=int(170 * scaling),
            bg=base_color,
            track_color=self.adjust_color_brightness(base_color, -45),
            start_color=self.ring_colors["start"],
            end_color=self.ring_colors["end"],
            text_color=self.colors["text_primary"],
            subtext_color=self.colors["text_primary"]
        )
        ring.pack(pady=(5, 8))

        status_label = ctk.CTkLabel(
            left,
            text="En attente",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self.colors["text_primary"],
            wraplength=210
        )
        status_label.pack(pady=(0, 10))

        right = ctk.CTkFrame(content_frame, fg_color=self.adjust_color_brightness(base_color, -40), corner_radius=8)
        right.pack(side="left", fill="both", expand=True)

        title_label = ctk.CTkLabel(
            right,
            text="Résultats de l'analyse",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=self.colors["text_primary"],
            anchor="w"
        )
        title_label.pack(fill="x", padx=12, pady=(8, 0))

        stats_label = ctk.CTkLabel(
            right,
            text="Aucune analyse effectuée",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"],
            wraplength=520,
            justify="left",
            anchor="w"
        )
        stats_label.pack(fill="x", padx=12, pady=(2, 4))

        result_text = ctk.CTkTextbox(
            right,
            corner_radius=5,
            fg_color=self.adjust_color_brightness(base_color, -60),
            text_color=self.colors["text_primary"]
        )
        result_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        result_text.insert("end", placeholder)

        return left, ring, status_label, stats_label, result_text

    def _create_action_button(self, parent, text, command, color, hover_color):
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            width=200,
            height=38,
            fg_color=color,
            hover_color=hover_color,
            text_color=self.colors["text_primary"],
            corner_radius=10
        )

    def create_scan_file_content(self, content_frame):
        placeholder = "Sélectionnez un fichier pour l'analyser.\n\n"
        placeholder += "Il sera comparé à la base de malwares connus, sa signature numérique sera vérifiée "
        placeholder += "et son contenu sera examiné à la recherche de comportements suspects."

        left, self.file_ring, self.progress_label, self.stats_label, self.result_text = \
            self._build_scan_panel(content_frame, "scan_file", placeholder)

        self.select_file_button = self._create_action_button(
            left, "Sélectionner un fichier", self.choose_file,
            self.adjust_color_brightness(self.colors["scan_file"], -20),
            self.adjust_color_brightness(self.colors["scan_file"], -40)
        )
        self.select_file_button.pack()

        self.quarantine_button = self._create_action_button(
            left, "Mettre en quarantaine", self.quarantine_scanned_file, "#E74C3C", "#C0392B"
        )

        if getattr(self, 'file_scan_running', False):
            self.select_file_button.configure(state="disabled")

    def create_scan_system_content(self, content_frame):
        placeholder = "Cette fonction analyse l'ensemble de votre système pour détecter les menaces potentielles.\n\n"
        placeholder += "L'analyse peut prendre plusieurs minutes en fonction de la taille de votre disque. "
        placeholder += "Seuls les exécutables et scripts sont analysés (pas les images, vidéos, archives ou données de jeux)."

        left, self.system_ring, self.system_progress_label, self.system_stats_label, self.system_result_text = \
            self._build_scan_panel(content_frame, "scan_system", placeholder)

        self.scan_system_button = self._create_action_button(
            left, "Lancer l'analyse", self.scan_system,
            self.adjust_color_brightness(self.colors["scan_system"], -20),
            self.adjust_color_brightness(self.colors["scan_system"], -40)
        )
        self.scan_system_button.pack()

        self.cancel_scan_button = self._create_action_button(
            left, "Annuler l'analyse", self.cancel_scan, "#E74C3C", "#C0392B"
        )

        if getattr(self, 'scan_running', False):
            self.scan_system_button.configure(state="disabled")
            self.cancel_scan_button.pack(pady=(8, 0))
            self.system_progress_label.configure(text="Analyse en cours…")

    def create_protection_content(self, content_frame):
        protection_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        protection_frame.pack(fill="x", pady=10)
        
        protection_label = ctk.CTkLabel(
            protection_frame,
            text="Protection en temps réel:",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        protection_label.pack(side="left", padx=20)
        
        self.protection_switch = ctk.CTkSwitch(
            protection_frame,
            text="Activée",
            command=self.toggle_realtime_protection,
            progress_color=self.adjust_color_brightness(self.colors["realtime_protection"], 20),
            button_color=self.colors["realtime_protection"],
            button_hover_color=self.adjust_color_brightness(self.colors["realtime_protection"], -20)
        )
        self.protection_switch.pack(side="left", padx=20)
        
        description_frame = ctk.CTkFrame(content_frame, fg_color=self.adjust_color_brightness(self.colors["realtime_protection"], -40), corner_radius=5)
        description_frame.pack(fill="x", pady=10)
        
        description_text = "La protection en temps réel surveille votre système en continu pour détecter les menaces " 
        description_text += "au moment où elles apparaissent. Elle analyse tous les fichiers lorsqu'ils sont créés ou modifiés."
        
        description_label = ctk.CTkLabel(
            description_frame,
            text=description_text,
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"],
            wraplength=400
        )
        description_label.pack(pady=10, padx=10)
        
        options_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        options_frame.pack(fill="x", pady=10)
        
        options_label = ctk.CTkLabel(
            options_frame,
            text="Options de protection",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        options_label.pack(pady=5)
        
        option1_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        option1_frame.pack(fill="x", pady=5)
        
        self.option1_check = ctk.CTkCheckBox(
            option1_frame,
            text="Vérifier les fichiers lors de l'ouverture",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"],
            fg_color=self.colors["realtime_protection"],
            hover_color=self.adjust_color_brightness(self.colors["realtime_protection"], -20)
        )
        self.option1_check.pack(pady=5)
        self.option1_check.select() 
        
        option2_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        option2_frame.pack(fill="x", pady=5)
        
        self.option2_check = ctk.CTkCheckBox(
            option2_frame,
            text="Vérifier automatiquement les téléchargements",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"],
            fg_color=self.colors["realtime_protection"],
            hover_color=self.adjust_color_brightness(self.colors["realtime_protection"], -20)
        )
        self.option2_check.pack(pady=5)
        self.option2_check.select() 
        
        option3_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        option3_frame.pack(fill="x", pady=5)
        
        option3_label = ctk.CTkLabel(
            option3_frame,
            text="Niveau de sensibilité:",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"]
        )
        option3_label.pack(side="left", padx=20)
        
        self.sensitivity_var = ctk.StringVar(value="Moyen")
        sensitivity_combobox = ctk.CTkComboBox(
            option3_frame,
            values=["Faible", "Moyen", "Élevé"],
            variable=self.sensitivity_var,
            width=120,
            dropdown_fg_color=self.colors["realtime_protection"],
            border_color=self.colors["realtime_protection"]
        )
        sensitivity_combobox.pack(side="left", padx=5)
        
        activity_frame = ctk.CTkFrame(content_frame, fg_color=self.adjust_color_brightness(self.colors["realtime_protection"], -40), corner_radius=5)
        activity_frame.pack(fill="both", expand=True, pady=10)
        
        activity_label = ctk.CTkLabel(
            activity_frame,
            text="Journal d'activité",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        activity_label.pack(pady=5)
        
        self.activity_text = ctk.CTkTextbox(
            activity_frame,
            width=800,
            height=200,
            corner_radius=5,
            fg_color=self.adjust_color_brightness(self.colors["realtime_protection"], -60),
            text_color=self.colors["text_primary"]
        )
        self.activity_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.activity_text.insert("end", "La protection en temps réel est désactivée.\n")
        self.activity_text.insert("end", "❗ Votre système n'est pas protégé en temps réel.\n")
        self.activity_text.configure(state="disabled")
    
    def choose_file(self):
        if getattr(self, 'file_scan_running', False):
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            self.scan_file(os.path.normpath(file_path))

    def scan_file(self, file_path):
        self.file_scan_running = True
        self.last_scanned_file = None
        self.select_file_button.configure(state="disabled")
        self.quarantine_button.pack_forget()

        self.result_text.delete("0.0", "end")
        self.result_text.insert("end", f"🔍 Analyse du fichier: {file_path}\n\n")
        self.status_bar.configure(text="Analyse en cours...")

        self.stats["files_scanned"] = 1
        self.stats["threats_found"] = 0
        self.stats["scan_start_time"] = datetime.datetime.now()

        self.file_ring.reset()
        self.progress_label.configure(text="Analyse en cours…")
        self.stats_label.configure(text=os.path.basename(file_path))

        try:
            total_size = os.path.getsize(file_path)
        except OSError:
            total_size = 0

        last_update = [0.0]

        def on_progress(bytes_done):
            now = time.time()
            if total_size and (now - last_update[0]) >= 0.1:
                last_update[0] = now
                self.app.after(0, self._update_file_progress, bytes_done / total_size)

        def run_scan():
            details = {}
            threats = self.antivirus.scan_file(file_path, details=details, progress_callback=on_progress)
            self.app.after(0, self._show_file_result, file_path, threats, details)

        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()

    def _update_file_progress(self, ratio):
        if not self.file_scan_running:
            return
        try:
            ratio = min(ratio, 1.0) * 0.95
            self.file_ring.set(ratio)
        except tk.TclError:
            pass

    def _format_size(self, size):
        for unit in ("octets", "Ko", "Mo", "Go"):
            if size < 1024 or unit == "Go":
                return f"{size:.0f} {unit}" if unit == "octets" else f"{size:.1f} {unit}"
            size /= 1024

    def _show_file_result(self, file_path, threats, details):
        self.file_scan_running = False
        risk = self.antivirus.assess_risk(threats)
        indices = threats["suspicious_patterns"] + threats["content_threats"]
        self.stats["threats_found"] = len(threats["malware_match"]) + len(indices)

        lines = [f"🔍 Analyse du fichier: {file_path}\n\n"]

        if details["error"]:
            status = "Analyse impossible"
            lines.append("❓ ANALYSE IMPOSSIBLE\n")
            lines.append(f"Le fichier n'a pas pu être lu : {details['error']}\n")
            lines.append("Il n'a PAS été vérifié : ce résultat ne dit rien sur sa dangerosité.\n")
        elif details["empty"]:
            status = "Fichier vide"
            lines.append("ℹ️ FICHIER VIDE — rien à analyser.\n")
        elif risk["level"] == "malware":
            status = "Malware connu détecté"
            lines.append("❌ MALWARE CONNU\n")
            lines.append("Ce fichier est identique à un échantillon de la base de signatures (MalwareBazaar).\n")
        elif risk["level"] == "élevé":
            status = "Risque élevé"
            lines.append(f"🔴 RISQUE ÉLEVÉ (score {risk['score']})\n")
            lines.append("Plusieurs comportements typiques de malwares ont été trouvés dans ce fichier.\n")
        elif risk["level"] == "moyen":
            status = "Risque moyen"
            lines.append(f"🟠 RISQUE MOYEN (score {risk['score']})\n")
            lines.append("Des indices suspects ont été trouvés ; à vérifier si vous ne connaissez pas l'origine du fichier.\n")
        elif risk["level"] == "faible":
            status = "Risque faible"
            lines.append(f"🟡 RISQUE FAIBLE (score {risk['score']})\n")
            lines.append("Quelques indices, fréquents aussi dans des fichiers légitimes.\n")
        else:
            status = "Aucune menace détectée"
            lines.append("✅ AUCUNE MENACE DÉTECTÉE\n")

        if indices:
            lines.append("\nIndices trouvés :\n")
            for threat in indices:
                lines.append(f"  ⚠️ {threat}\n")

        if not details["error"] and not details["empty"]:
            lines.append("\nVérifications effectuées :\n")
            lines.append(f"  Taille : {self._format_size(details['size'])}\n")
            lines.append(f"  Empreinte SHA1 : {details['sha1']}\n")
            known = "CORRESPONDANCE" if threats["malware_match"] else "aucune correspondance"
            lines.append(f"  Base de malwares connus ({len(self.antivirus.signature_db)} signatures) : {known}\n")
            if not threats["malware_match"]:
                if details["trusted_dir"]:
                    lines.append("  Dossier d'application de confiance : oui (analyse des motifs non appliquée)\n")
                elif details["signed"]:
                    lines.append("  Signature numérique : valide, éditeur reconnu par Windows (analyse des motifs non appliquée)\n")
                else:
                    if file_path.lower().endswith(self.antivirus.signable_extensions):
                        lines.append("  Signature numérique : absente ou invalide\n")
                    if details["heuristics"]:
                        analyzed = min(details["size"], self.antivirus.max_content_size)
                        lines.append(f"  Analyse des motifs : effectuée sur {self._format_size(analyzed)}\n")
                    else:
                        lines.append("  Analyse des motifs : non appliquée (type de fichier non exécutable)\n")

        self.stats["scan_end_time"] = datetime.datetime.now()
        duration = (self.stats["scan_end_time"] - self.stats["scan_start_time"]).total_seconds()

        try:
            self.result_text.delete("0.0", "end")
            self.result_text.insert("end", "".join(lines))

            if details["error"]:
                self.file_ring.set(0, color=self.verdict_colors["erreur"], text="?", subtext="Non vérifié")
            elif details["empty"]:
                self.file_ring.set(1.0, color=self.verdict_colors["erreur"], subtext="Fichier vide")
            else:
                self.file_ring.set(1.0, color=self.verdict_colors[risk["level"]], subtext=self.verdict_labels[risk["level"]])
            self.progress_label.configure(text=status)
            self.stats_label.configure(text=f"{os.path.basename(file_path)} | Indices: {len(indices)} | Durée: {duration:.2f} secondes")
            self.select_file_button.configure(state="normal")

            if not details["error"] and risk["level"] != "sain":
                self.last_scanned_file = file_path
                self.quarantine_button.pack(pady=(8, 0), after=self.select_file_button)
        except tk.TclError:
            pass

        self.status_bar.configure(text=f"Analyse terminée — {status}")

    def quarantine_scanned_file(self):
        file_path = getattr(self, 'last_scanned_file', None)
        if not file_path:
            return

        confirmed = messagebox.askyesno(
            "Mise en quarantaine",
            f"Déplacer ce fichier en quarantaine ?\n\n{file_path}\n\n"
            "Il sera retiré de son emplacement actuel et ne pourra plus être exécuté."
        )
        if not confirmed:
            return

        try:
            quarantine_path = self.antivirus.move_to_quarantine(file_path)
        except Exception as e:
            messagebox.showerror("Mise en quarantaine", str(e))
            return

        self.last_scanned_file = None
        self.quarantine_button.pack_forget()
        self.result_text.insert("end", f"\n🔒 Fichier mis en quarantaine : {quarantine_path}\n")
        self.result_text.insert("end", f"   Emplacement d'origine enregistré dans : {quarantine_path}.info\n")
        self.status_bar.configure(text="Fichier mis en quarantaine")

    def scan_system(self):
        if hasattr(self, 'scan_thread') and self.scan_thread.is_alive():
            messagebox.showinfo("Information", "Une analyse est déjà en cours.")
            return
            
        self.system_result_text.delete("0.0", "end")
        self.system_result_text.insert("end", "🔍 Analyse complète du système en cours...\n\n")
        self.status_bar.configure(text="Analyse du système en cours...")
        
        self.stats["files_scanned"] = 0
        self.stats["threats_found"] = 0
        self.stats["scan_start_time"] = datetime.datetime.now()
        
        self.system_ring.reset()
        self.system_progress_label.configure(text="Recherche des fichiers…")
        self.system_stats_label.configure(text="Démarrage de l'analyse…")
        
        self.detected_threats = []
        
        self.scan_running = True
        
        self.scan_system_button.configure(state="disabled")
        self.cancel_scan_button.pack(pady=(8, 0), after=self.scan_system_button)

        def update_progress(scan_stats):
            if not self.scan_running:
                return

            self.app.after(0, self._update_scan_progress, scan_stats)

        def run_scan():
            try:
                detected_threats = self.antivirus.scan_system(progress_callback=update_progress)

                if self.scan_running:
                    self.app.after(0, self._finish_scan, detected_threats)
            except Exception as e:
                self.app.after(0, self._handle_scan_error, str(e))

        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def _end_system_scan_ui(self):
        try:
            self.cancel_scan_button.pack_forget()
            self.scan_system_button.configure(state="normal")
        except (AttributeError, tk.TclError):
            pass

    def _update_scan_progress(self, scan_stats):
        if not self.scan_running:
            return

        analyzed = scan_stats["files_analyzed"]
        found = scan_stats["files_found"]

        self.stats["files_scanned"] = analyzed
        self.stats["threats_found"] = scan_stats["threats_found"]

        try:
            if found:
                self.system_ring.set(min(analyzed / found, 1.0), subtext=f"{analyzed} / {found}")
                self.system_progress_label.configure(
                    text="Recherche des fichiers…" if scan_stats["collecting"] else "Analyse en cours…"
                )

            stats_text = f"Vitesse: {scan_stats['speed']:.0f} fichiers/sec | "
            stats_text += f"Fichiers signalés: {scan_stats['threats_found']}\n"
            stats_text += f"Dossier: {scan_stats['current_directory']}"
            self.system_stats_label.configure(text=stats_text)
        except tk.TclError:
            pass

    def _finish_scan(self, detected_threats):
        self._end_system_scan_ui()

        self.detected_threats = detected_threats
        self.stats["files_scanned"] = self.antivirus.last_scan_stats.get("files_analyzed", 0)
        self.stats["threats_found"] = sum(
            len(threats["malware_match"]) + len(threats["suspicious_patterns"]) + len(threats["content_threats"])
            for _, threats in detected_threats
        )

        if not detected_threats:
            self.system_result_text.delete("0.0", "end")
            self.system_result_text.insert("end", "✅ Aucune menace détectée sur le système !\n")
        else:
            ranked = sorted(
                ((self.antivirus.assess_risk(threats), file_path, threats) for file_path, threats in detected_threats),
                key=lambda item: -item[0]["score"]
            )
            counts = {}
            for risk, _, _ in ranked:
                counts[risk["level"]] = counts.get(risk["level"], 0) + 1

            lines = [f"⚠️ {len(detected_threats)} fichiers signalés sur le système :\n"]
            lines.append(f"   ❌ Malwares connus : {counts.get('malware', 0)}\n")
            lines.append(f"   🔴 Risque élevé : {counts.get('élevé', 0)}\n")
            lines.append(f"   🟠 Risque moyen : {counts.get('moyen', 0)}\n")
            minor = self.antivirus.last_scan_stats.get('files_minor', 0)
            lines.append(f"   🟡 Risque faible : {minor} (non listés, indices courants dans des logiciels légitimes)\n")

            for risk, file_path, threats in ranked:
                level = "MALWARE CONNU" if risk["level"] == "malware" else f"risque {risk['level']}"
                lines.append(f"\n📁 [{level}] {file_path}\n")
                for threat in threats["malware_match"]:
                    lines.append(f"❌ {threat}\n")
                for pattern in threats["suspicious_patterns"]:
                    lines.append(f"⚠️ {pattern}\n")
                for threat in threats["content_threats"]:
                    lines.append(f"⚠️ {threat}\n")

            self.system_result_text.delete("0.0", "end")
            self.system_result_text.insert("end", "".join(lines))

            if hasattr(self, 'show_threat_management_window'):
                self.show_threat_management_window()

        levels = {self.antivirus.assess_risk(threats)["level"] for _, threats in detected_threats}
        worst = next((level for level in ("malware", "élevé", "moyen", "faible") if level in levels), "sain")
        self.system_ring.set(
            1.0, color=self.verdict_colors[worst],
            subtext=f"{len(detected_threats)} signalés" if detected_threats else "Aucune menace"
        )
        self.system_progress_label.configure(text="Analyse terminée")

        self.stats["scan_end_time"] = datetime.datetime.now()
        duration = (self.stats["scan_end_time"] - self.stats["scan_start_time"]).total_seconds()
        stats_text = f"Fichiers analysés: {self.stats['files_scanned']} | "
        stats_text += f"Menaces trouvées: {self.stats['threats_found']} | "
        stats_text += f"Durée: {duration:.2f} secondes"
        scan_stats = self.antivirus.last_scan_stats
        stats_text += f"\n{scan_stats.get('files_seen', 0)} fichiers parcourus sur les disques, "
        stats_text += f"dont {self.stats['files_scanned']} exécutables/scripts analysés "
        stats_text += f"({scan_stats.get('files_trusted', 0)} d'applications de confiance : signatures uniquement)"
        if scan_stats.get('files_minor'):
            stats_text += f"\n{scan_stats['files_minor']} fichiers à risque faible non signalés (indices courants dans des logiciels légitimes)"
        if scan_stats.get('files_unreadable'):
            stats_text += f"\n❓ {scan_stats['files_unreadable']} fichiers n'ont pas pu être lus et n'ont PAS été vérifiés"
        self.system_stats_label.configure(text=stats_text)

        self.status_bar.configure(text="Analyse du système terminée")
        self.scan_running = False
    
    def _handle_scan_error(self, error_message):
        self._end_system_scan_ui()
            
        self.system_result_text.insert("end", f"\n❌ Erreur lors de l'analyse: {error_message}\n")
        self.system_progress_label.configure(text="Erreur lors de l'analyse")
        self.status_bar.configure(text="Erreur lors de l'analyse du système")
        self.scan_running = False
    
    def cancel_scan(self):
        if hasattr(self, 'scan_running') and self.scan_running:
            self.scan_running = False
            self.antivirus.stop_scan()
            self.status_bar.configure(text="Analyse annulée")
            self.system_result_text.insert("end", "\n⚠️ Analyse annulée par l'utilisateur\n")
            
            self.system_progress_label.configure(text="Analyse annulée")
            self._end_system_scan_ui()
    
    def run(self):
        self.app.mainloop()

    def toggle_realtime_protection(self):
        self.realtime_protection_active = not self.realtime_protection_active
        
        if self.realtime_protection_active:
            self.protection_switch.configure(text="Activée")
            self.status_bar.configure(text="Protection en temps réel activée")
            
            self.activity_text.configure(state="normal")
            self.activity_text.delete("0.0", "end")
            self.activity_text.insert("end", "✅ Protection en temps réel activée à " + 
                                     datetime.datetime.now().strftime("%H:%M:%S") + "\n")
            self.activity_text.insert("end", "👁️ Surveillance du système en cours...\n")
            
            self.simulate_realtime_activity()
        else:
            self.protection_switch.configure(text="Désactivée")
            self.status_bar.configure(text="Protection en temps réel désactivée")
            
            self.activity_text.configure(state="normal")
            self.activity_text.delete("0.0", "end")
            self.activity_text.insert("end", "⚠️ Protection en temps réel désactivée à " + 
                                     datetime.datetime.now().strftime("%H:%M:%S") + "\n")
            self.activity_text.insert("end", "❗ Votre système n'est pas protégé en temps réel.\n")
            self.activity_text.configure(state="disabled")
    
    def simulate_realtime_activity(self):
        if not self.realtime_protection_active:
            return
            
        self.activity_text.configure(state="normal")
        self.activity_text.delete("1.0", "end")
        self.activity_text.insert("end", "VirusWarp est actif et protège votre système\n")
        self.activity_text.insert("end", "✓ Protection en temps réel activée\n")
        self.activity_text.insert("end", "✓ Surveillance des fichiers en cours\n")
        self.activity_text.insert("end", "✓ Base de données des menaces à jour\n")
        self.activity_text.configure(state="disabled")
        
        if self.activity_text.get("1.0", "end").count("\n") > 20:
            self.activity_text.configure(state="normal")
            self.activity_text.delete("1.0", "10.0")
            self.activity_text.configure(state="disabled")
            
        self.activity_text.configure(state="normal")
        self.activity_text.insert("end", "🕒 " + datetime.datetime.now().strftime("%H:%M:%S") + 
                                 " - " + "VirusWarp a mis les fichiers en quarantaine.\n")
        self.activity_text.see("end")  
        self.activity_text.configure(state="disabled")
        
        self.app.after(5000, self.simulate_realtime_activity) 

    def adjust_color_brightness(self, hex_color, factor):
        r, g, b = int(hex_color[1:3], 16), int(hex_color[3:5], 16), int(hex_color[5:7], 16)
        
        if factor > 0:
            r = min(255, r + factor)
            g = min(255, g + factor)
            b = min(255, b + factor)
        else:
            r = max(0, r + factor)
            g = max(0, g + factor)
            b = max(0, b + factor)
            
        return f"#{r:02x}{g:02x}{b:02x}"

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] == "--update-signatures":
        count = SimpleAntivirus().update_signatures(sys.argv[2] if len(sys.argv) > 2 else None)
        print(f"Base de signatures mise à jour : {count} signatures")
    else:
        app = ModernAntivirusGUI()
        app.run()

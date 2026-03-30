import os
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from PIL import Image, ImageTk
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

class SimpleAntivirus:
    def __init__(self):
        self.malware_signatures: Set[str] = {
            "e1112134b6dcc8bed54e0e34d8ac272795e73d74",
            "a1112134b6dcc8bed54e0e34d8ac272795e73d75",
        }
        
        self.suspicious_patterns = [
            rb"(?i)virus", rb"(?i)malware", rb"(?i)hack", rb"(?i)exploit", rb"(?i)payload",
            rb"(?i)(<script>|</script>)", rb"(?i)(exec\(|eval\(|system\()"
        ]
        
        self.quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
            
        self.max_workers = os.cpu_count() or 4
        self.batch_size = 50  
        self.scan_queue = queue.Queue() 

    def calculate_file_hash(self, file_path: str) -> str:
        sha1 = hashlib.sha1()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha1.update(chunk)
            return sha1.hexdigest()
        except Exception as e:
            return ""

    def scan_file(self, file_path: str) -> Dict[str, List[str]]:
        threats = {"malware_match": [], "suspicious_patterns": [], "content_threats": []}
        
        try:
            if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
                return threats
                
            sha1 = hashlib.sha1()
            content_buffer = b''
            max_content_size = 10 * 1024 * 1024 
            
            try:
                with open(file_path, 'rb') as f:
                    while True:
                        chunk = f.read(64 * 1024) 
                        if not chunk:
                            break
                        sha1.update(chunk)
                        if len(content_buffer) < max_content_size:
                            content_buffer += chunk
            except Exception:
                return threats
                
            file_hash = sha1.hexdigest()
            if file_hash in self.malware_signatures:
                threats["malware_match"].append(f"Malware signature match: {file_hash}")
                return threats 
            
            is_executable_or_script = file_path.lower().endswith(tuple(self.target_extensions)) if hasattr(self, 'target_extensions') else True
            
            if content_buffer and (len(content_buffer) < 1024 * 1024 or is_executable_or_script):
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, content_buffer, re.DOTALL):
                        pattern_str = pattern.decode(errors='replace')
                        threats["suspicious_patterns"].append(f"Suspicious pattern found: {pattern_str}")
            
            if is_executable_or_script:
                content_threats = self.analyze_file_content(file_path, content=content_buffer)
                if content_threats:
                    threats["content_threats"].extend(content_threats)
        
        except Exception:
            pass
        
        return threats
    
    def analyze_file_content(self, file_path, content=None):
        """Analyse le contenu d'un fichier pour détecter des menaces potentielles"""
        try:
            if content is None:
                with open(file_path, 'rb') as f:
                    content = b''
                    chunk_size = 1024 * 1024 
                    for chunk in iter(lambda: f.read(chunk_size), b''):
                        content += chunk
                        if len(content) > 50 * 1024 * 1024:
                            break
            
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                text_content = str(content)
            
            threats = []
            
            suspicious_patterns = [
                (r'eval\s*\(|exec\s*\(', "Code exécuté dynamiquement"),
                (r'base64\.b64decode', "Décodage base64 suspect"),
                (r'(password|token|cookie).{0,20}=', "Collecte d'informations sensibles"),
                (r'webhook|discord\.com/api', "Communication Discord suspecte"),
                
                (r'\\x[0-9a-fA-F]{2}', "Caractères hexadécimaux encodés"),
                (r'chr\s*\(\s*\d+\s*\)', "Conversion de nombres en caractères"),
                
                (r'socket\.socket|subprocess|os\.system', "Exécution système suspecte"),
                (r'(Chrome|Firefox|Discord).*?(Login|Storage)', "Accès aux données sensibles"),
                
                (r'powershell\s+-\w+\s+', "Exécution PowerShell suspecte"),
                (r'cmd\.exe|command\.exe', "Exécution de commandes système"),
                (r'net\s+user|net\s+localgroup', "Manipulation des comptes utilisateurs"),
                (r'reg\s+add|regedit', "Modification du registre Windows")
            ]
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, text_content, re.IGNORECASE | re.MULTILINE):
                    threats.append(f"Pattern suspect détecté: {description}")
            
            if text_content.count('\\x') > len(text_content) * 0.05:
                threats.append("Niveau élevé d'obfuscation détecté")
            
            return threats
            
        except Exception as e:
            return [f"Erreur lors de l'analyse: {str(e)}"]
    
    def batch_scan_worker(self, callback=None):
        """
        Fonction de travail pour le scan par lots qui traite les fichiers depuis la file d'attente
        """
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
    
    def file_collector_worker(self, drives, excluded_dirs, ignored_names, target_extensions, file_queue, stop_event, stats_lock, stats):
        """
        Fonction de travail pour collecter les fichiers à analyser en parallèle
        """
        try:
            for drive in drives:
                if stop_event.is_set():
                    break
                    
                if not os.path.exists(drive):
                    continue
                
                for root, dirs, files in os.walk(drive, topdown=True):
                    if stop_event.is_set():
                        break
                    
                    with stats_lock:
                        stats["current_directory"] = root
                    
                    if platform.system() == "Windows":
                        system_dirs = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"]
                        dirs[:] = [d for d in dirs if not any(os.path.join(root, d).startswith(sys_dir) for sys_dir in system_dirs)]
                    else:
                        system_dirs = ["/proc", "/sys", "/dev"]
                        dirs[:] = [d for d in dirs if not any(os.path.join(root, d).startswith(sys_dir) for sys_dir in system_dirs)]
                    
                    dirs[:] = [d for d in dirs if d not in ignored_names and not any(os.path.join(root, d).startswith(ex_dir) for ex_dir in excluded_dirs)]
                    
                    if "\\Users\\" in root or "/home/" in root:
                        priority = 1 
                    else:
                        priority = 2 
                    
                    for file in files:
                        if stop_event.is_set():
                            break
                            
                        try:
                            file_path = os.path.join(root, file)
                            
                            with stats_lock:
                                stats["files_found"] += 1
                            
                            _, ext = os.path.splitext(file_path.lower())
                            
                            if ext in {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.hta', '.scr', '.com', '.pif'}:
                                file_priority = priority - 0.5 
                            elif ext in target_extensions:
                                file_priority = priority  
                            else:
                                file_priority = priority + 1
                                
                            file_queue.put((file_priority, file_path))
                     
                                
                        except Exception:
                            continue
        except Exception as e:
            with stats_lock:
                stats["errors"].append(f"Erreur de collecte: {str(e)}")
        finally:
            file_queue.put((999, None))  
    
    def scan_system(self, callback=None) -> List[Tuple[str, Dict[str, List[str]]]]:
        """
        Analyse toute la machine et retourne une liste de tuples contenant le chemin du fichier et les menaces détectées
        """
        detected_threats = []
        scan_lock = threading.Lock()  
        scan_results = (scan_lock, detected_threats)  
        stop_event = threading.Event()  
        
        stats_lock = threading.Lock()
        stats = {
            "files_found": 0,       
            "files_analyzed": 0,    
            "current_directory": "", 
            "current_file": "",      
            "start_time": time.time(), 
            "errors": []            
        }
        
        if platform.system() == "Windows":
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
            ]
            ignored_names = {
                "node_modules", ".git", ".vscode", ".idea", "__pycache__", "vendor", 
                "site-packages", "gems", "cargo", "go", "npm-cache"
            }
            
            target_extensions = {'.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.py', '.jar', '.msi', 
                               '.php', '.html', '.htm', '.hta', '.scr', '.com', '.pif', '.wsf', '.wsh', '.reg'}
        else:
            drives = [os.path.expanduser("~")]
            excluded_dirs = [
                "/proc",
                "/sys",
                "/dev",
                "/run",
                "/var/run",
                "/tmp"
            ]
            ignored_names = {
                "node_modules", ".git", ".vscode", ".idea", "__pycache__", "vendor", 
                "site-packages", "gems"
            }
            target_extensions = {'.out', '.bin', '.sh', '.py', '.js', '.php', '.html', '.htm', '.jar', '.pl', '.rb',
                               '.deb', '.rpm', '.so', '.ko'}
        
        file_queue = queue.PriorityQueue()
        
        collectors = []
        collector_count = min(len(drives), self.max_workers)  
        
        drives_per_collector = [drives[i::collector_count] for i in range(collector_count)]
        
        for drive_subset in drives_per_collector:
            if drive_subset: 
                collector = threading.Thread(
                    target=self.file_collector_worker,
                    args=(drive_subset, excluded_dirs, ignored_names, target_extensions, file_queue, stop_event, stats_lock, stats)
                )
                collector.daemon = True
                collector.start()
                collectors.append(collector)
        
        def scan_callback(file_path, threats):
            with stats_lock:
                stats["current_file"] = file_path
                stats["files_analyzed"] += 1
                should_update = (stats["files_analyzed"] % 50 == 0) 
                
            if callback and should_update:
                callback(file_path, threats)
                

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            collector_done_count = 0
            
            try:
                while collector_done_count < len(collectors) or not file_queue.empty():
                    try:
                        priority, file_path = file_queue.get(timeout=0.1)
                        
                        if file_path is None: 
                            collector_done_count += 1
                            file_queue.task_done()
                            continue
                        
                        with stats_lock:
                            stats["current_file"] = file_path
                        
                        future = executor.submit(self.scan_file, file_path)
                        futures.append((future, file_path, scan_results))
                        
                        for i in range(len(futures) - 1, -1, -1):
                            future, path, results = futures[i]
                            if future.done():
                                try:
                                    threats = future.result()
                                    with stats_lock:
                                        stats["files_analyzed"] += 1
                                        
                                    if any(threats.values()):
                                        with results[0]: 
                                            results[1].append((path, threats))
                                            scan_callback(path, threats)
                                except Exception as e:
                                    with stats_lock:
                                        stats["errors"].append(f"Erreur d'analyse de {path}: {str(e)}")
                                
                                futures.pop(i)
                        
                        file_queue.task_done()
                        
                        if stats["files_analyzed"] % 50 == 0 and callback:
                            elapsed = time.time() - stats["start_time"]
                            speed = stats["files_analyzed"] / elapsed if elapsed > 0 else 0
                            progress_info = f"Analysés: {stats['files_analyzed']}/{stats['files_found']} fichiers, Vitesse: {speed:.1f} fichiers/sec"
                            callback(progress_info, {})
                            
                    except queue.Empty:
                        continue
                
                for future, path, results in futures:
                    try:
                        threats = future.result()
                        with stats_lock:
                            stats["files_analyzed"] += 1
                            
                        if any(threats.values()):
                            with results[0]:  
                                results[1].append((path, threats))
                                scan_callback(path, threats)
                    except Exception as e:
                        with stats_lock:
                            stats["errors"].append(f"Erreur d'analyse de {path}: {str(e)}")
            
            except Exception as e:
                with stats_lock:
                    stats["errors"].append(f"Erreur générale: {str(e)}")
            finally:
                stop_event.set()
                
                for collector in collectors:
                    collector.join(timeout=1.0)
                
                if callback:
                    elapsed = time.time() - stats["start_time"]
                    speed = stats["files_analyzed"] / elapsed if elapsed > 0 else 0
                    final_stats = (
                        f"Analyse terminée en {elapsed:.1f} secondes\n"
                        f"Fichiers trouvés: {stats['files_found']}\n"
                        f"Fichiers analysés: {stats['files_analyzed']}\n"
                        f"Vitesse moyenne: {speed:.1f} fichiers/sec\n"
                        f"Erreurs: {len(stats['errors'])}"
                    )
                    callback(final_stats, {})
        
        return detected_threats
    
    def move_to_quarantine(self, file_path: str) -> str:
        """
        Déplace un fichier vers le dossier de quarantaine et retourne le nouveau chemin
        """
        try:
            if not os.path.exists(file_path):
                raise Exception(f"Le fichier n'existe pas: {file_path}")
                
            file_name = os.path.basename(file_path)
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            quarantine_name = f"{timestamp}_{file_name}"
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
        """Création de l'interface graphique"""
        
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
        """Crée un canvas avec un arrière-plan élégant"""
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
        """Initialise les particules pour l'arrière-plan"""
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
        """Dessine l'arrière-plan avec motif hexagonal et dégradé"""
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
        """Anime l'arrière-plan"""
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
        """Convertit une couleur hexadécimale avec opacité en format pour tkinter"""
        r, g, b = int(hex_color[1:3], 16), int(hex_color[3:5], 16), int(hex_color[5:7], 16)
        
        bg_r, bg_g, bg_b = int(self.colors["background"][1:3], 16), int(self.colors["background"][3:5], 16), int(self.colors["background"][5:7], 16)
        
        r = int(r * opacity + bg_r * (1 - opacity))
        g = int(g * opacity + bg_g * (1 - opacity))
        b = int(b * opacity + bg_b * (1 - opacity))
        
        return f"#{r:02x}{g:02x}{b:02x}"
    
    def create_card(self, card_id, title, icon, color, row, column):
        """Crée une carte interactive"""
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
        """Affiche une fenêtre modale avec le contenu de la carte"""
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
        self.modal_overlay.place(relx=0.5, rely=0.4, anchor="center", relwidth=0.8, relheight=0.6)
        
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
        """Ferme la fenêtre modale"""
        if hasattr(self, 'modal_overlay'):
            self.modal_overlay.destroy()
            self.modal_content = None
            self.modal_visible = False
    
    def create_scan_file_content(self, content_frame):
        select_file_button = ctk.CTkButton(
            content_frame,
            text="Sélectionner un fichier",
            command=self.choose_file,
            width=200,
            height=40,
            fg_color=self.adjust_color_brightness(self.colors["scan_file"], -20),
            hover_color=self.adjust_color_brightness(self.colors["scan_file"], -40),
            text_color=self.colors["text_primary"],
            corner_radius=10
        )
        select_file_button.pack(pady=10)
        
        self.progress_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        self.progress_frame.pack(fill="x", pady=5)
        
        self.progress_label = ctk.CTkLabel(
            self.progress_frame,
            text="Progression: 0%",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"]
        )
        self.progress_label.pack(pady=(5, 0))
        
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame,
            width=800,
            height=15,
            corner_radius=5,
            mode="determinate",
            progress_color=self.colors["highlight"]
        )
        self.progress_bar.pack(pady=5, fill="x")
        self.progress_bar.set(0)
        
        self.stats_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        self.stats_frame.pack(fill="x", pady=5)
        
        self.stats_label = ctk.CTkLabel(
            self.stats_frame,
            text="Statistiques: Aucune analyse effectuée",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"]
        )
        self.stats_label.pack(pady=5)
        
        result_frame = ctk.CTkFrame(content_frame, fg_color=self.adjust_color_brightness(self.colors["scan_file"], -40), corner_radius=5)
        result_frame.pack(fill="both", expand=True, pady=10)
        
        result_label = ctk.CTkLabel(
            result_frame,
            text="Résultats de l'analyse",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        result_label.pack(pady=5)
        
        self.result_text = ctk.CTkTextbox(
            result_frame,
            width=800,
            height=200,
            corner_radius=5,
            fg_color=self.adjust_color_brightness(self.colors["scan_file"], -60),
            text_color=self.colors["text_primary"]
        )
        self.result_text.pack(fill="both", expand=True, padx=10, pady=10)
    
    def create_scan_system_content(self, content_frame):
        scan_system_button = ctk.CTkButton(
            content_frame,
            text="Lancer l'analyse du système",
            command=self.scan_system,
            width=200,
            height=40,
            fg_color=self.adjust_color_brightness(self.colors["scan_system"], -20),
            hover_color=self.adjust_color_brightness(self.colors["scan_system"], -40),
            text_color=self.colors["text_primary"],
            corner_radius=10
        )
        scan_system_button.pack(pady=10)
        
        info_frame = ctk.CTkFrame(content_frame, fg_color=self.adjust_color_brightness(self.colors["scan_system"], -40), corner_radius=5)
        info_frame.pack(fill="x", pady=10)
        
        info_text = "Cette fonction analyse l'ensemble de votre système pour détecter les menaces potentielles. "
        info_text += "L'analyse peut prendre plusieurs minutes en fonction de la taille de votre disque."
        
        info_label = ctk.CTkLabel(
            info_frame,
            text=info_text,
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"],
            wraplength=400
        )
        info_label.pack(pady=10, padx=10)
        
        system_progress_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        system_progress_frame.pack(fill="x", pady=5)
        
        self.system_progress_label = ctk.CTkLabel(
            system_progress_frame,
            text="Progression: 0%",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"]
        )
        self.system_progress_label.pack(pady=(5, 0))
        
        self.system_progress_bar = ctk.CTkProgressBar(
            system_progress_frame,
            width=800,
            height=15,
            corner_radius=5,
            mode="determinate",
            progress_color=self.colors["highlight"]
        )
        self.system_progress_bar.pack(pady=5, fill="x")
        self.system_progress_bar.set(0)
        
        system_stats_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        system_stats_frame.pack(fill="x", pady=5)
        
        self.system_stats_label = ctk.CTkLabel(
            system_stats_frame,
            text="Statistiques: Aucune analyse effectuée",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["text_primary"]
        )
        self.system_stats_label.pack(pady=5)
        
        system_result_frame = ctk.CTkFrame(content_frame, fg_color=self.adjust_color_brightness(self.colors["scan_system"], -40), corner_radius=5)
        system_result_frame.pack(fill="both", expand=True, pady=10)
        
        system_result_label = ctk.CTkLabel(
            system_result_frame,
            text="Résultats de l'analyse système",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors["text_primary"]
        )
        system_result_label.pack(pady=5)
        
        self.system_result_text = ctk.CTkTextbox(
            system_result_frame,
            width=800,
            height=200,
            corner_radius=5,
            fg_color=self.adjust_color_brightness(self.colors["scan_system"], -60),
            text_color=self.colors["text_primary"]
        )
        self.system_result_text.pack(fill="both", expand=True, padx=10, pady=10)
    
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
        file_path = filedialog.askopenfilename()
        if file_path:
            self.status_bar.configure(text="Analyse en cours...")
            self.scan_file(file_path)
            self.status_bar.configure(text="Analyse terminée")
    
    def scan_file(self, file_path):
        self.result_text.delete("0.0", "end")
        self.result_text.insert("end", f"🔍 Analyse du fichier: {file_path}\n\n")
        
        self.stats["files_scanned"] = 1
        self.stats["threats_found"] = 0
        self.stats["scan_start_time"] = datetime.datetime.now()
        
        self.progress_bar.set(0.5)
        self.progress_label.configure(text="Progression: 50%")
        self.app.update()
        
        threats = self.antivirus.scan_file(file_path)
        if not any(threats.values()):
            self.result_text.insert("end", "✅ Aucune menace détectée !\n")
        else:
            self.stats["threats_found"] = len(threats["malware_match"]) + len(threats["suspicious_patterns"]) + len(threats["content_threats"])
            
            if threats["malware_match"]:
                self.result_text.insert("end", "⚠️ MALWARE DETECTÉ:\n")
                for threat in threats["malware_match"]:
                    self.result_text.insert("end", f"❌ {threat}\n")
            if threats["suspicious_patterns"]:
                self.result_text.insert("end", "\n⚠️ PATRONS SUSPECTS DETECTÉS:\n")
                for pattern in threats["suspicious_patterns"]:
                    self.result_text.insert("end", f"⚠️ {pattern}\n")
            if threats["content_threats"]:
                self.result_text.insert("end", "\n⚠️ MENACES DE CONTENU DETECTÉES:\n")
                for threat in threats["content_threats"]:
                    self.result_text.insert("end", f"⚠️ {threat}\n")
        
        self.progress_bar.set(1.0)
        self.progress_label.configure(text="Progression: 100%")
        
        self.stats["scan_end_time"] = datetime.datetime.now()
        duration = (self.stats["scan_end_time"] - self.stats["scan_start_time"]).total_seconds()
        stats_text = f"Fichiers analysés: {self.stats['files_scanned']} | "
        stats_text += f"Menaces trouvées: {self.stats['threats_found']} | "
        stats_text += f"Durée: {duration:.2f} secondes"
        self.stats_label.configure(text=stats_text)

    def scan_system(self):
        """
        Analyse toute la machine et affiche les résultats
        """
        if hasattr(self, 'scan_thread') and self.scan_thread.is_alive():
            messagebox.showinfo("Information", "Une analyse est déjà en cours.")
            return
            
        self.system_result_text.delete("0.0", "end")
        self.system_result_text.insert("end", "🔍 Analyse complète du système en cours...\n\n")
        self.status_bar.configure(text="Analyse du système en cours...")
        
        self.stats["files_scanned"] = 0
        self.stats["threats_found"] = 0
        self.stats["scan_start_time"] = datetime.datetime.now()
        
        self.system_progress_bar.set(0)
        self.system_progress_label.configure(text="Progression: 0%")
        self.app.update()
        
        self.detected_threats = []
        
        self.scan_running = True
        
        self.cancel_scan_button = ctk.CTkButton(
            self.modal_content,
            text="Annuler l'analyse",
            command=self.cancel_scan,
            width=200,
            height=40,
            fg_color="#E74C3C",
            hover_color="#C0392B",
            text_color=self.colors["text_primary"],
            corner_radius=10
        )
        self.cancel_scan_button.pack(pady=10)
        
        def update_progress(file_path, threats):
            if not self.scan_running:
                return
                
            self.app.after(0, self._update_scan_progress, file_path, threats)
        
        def run_scan():
            try:
                detected_threats = self.antivirus.scan_system(callback=update_progress)
                
                if self.scan_running:
                    self.app.after(0, self._finish_scan, detected_threats)
            except Exception as e:
                self.app.after(0, self._handle_scan_error, str(e))
        
        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _update_scan_progress(self, file_path, threats):
        """Mise à jour de l'interface depuis le thread principal"""
        self.stats["files_scanned"] += 1
        
        if any(threats.values()):
            self.stats["threats_found"] += len(threats["malware_match"]) + len(threats["suspicious_patterns"]) + len(threats["content_threats"])
            
        if self.stats["files_scanned"] % 10 == 0:
            self.system_result_text.insert("end", f"Analyse: {file_path}\n")
            self.system_progress_label.configure(text=f"Fichiers analysés: {self.stats['files_scanned']}")
            self.app.update()
        
        if any(threats.values()):
            self.detected_threats.append((file_path, threats))
    
    def _finish_scan(self, detected_threats):
        """Finaliser l'analyse et mettre à jour l'interface"""
        if hasattr(self, 'cancel_scan_button'):
            self.cancel_scan_button.destroy()
        
        if not detected_threats:
            self.system_result_text.delete("0.0", "end")
            self.system_result_text.insert("end", "✅ Aucune menace détectée sur le système !\n")
        else:
            self.system_result_text.delete("0.0", "end")
            self.system_result_text.insert("end", f"⚠️ {len(detected_threats)} menaces détectées sur le système !\n\n")
            
            for file_path, threats in detected_threats:
                self.system_result_text.insert("end", f"\n📁 Fichier: {file_path}\n")
                if threats["malware_match"]:
                    for threat in threats["malware_match"]:
                        self.system_result_text.insert("end", f"❌ {threat}\n")
                if threats["suspicious_patterns"]:
                    for pattern in threats["suspicious_patterns"]:
                        self.system_result_text.insert("end", f"⚠️ {pattern}\n")
                if threats["content_threats"]:
                    for threat in threats["content_threats"]:
                        self.system_result_text.insert("end", f"⚠️ {threat}\n")
            
            self.show_threat_management_window()
        
        self.system_progress_bar.set(1.0)
        self.system_progress_label.configure(text="Progression: 100%")
        
        self.stats["scan_end_time"] = datetime.datetime.now()
        duration = (self.stats["scan_end_time"] - self.stats["scan_start_time"]).total_seconds()
        stats_text = f"Fichiers analysés: {self.stats['files_scanned']} | "
        stats_text += f"Menaces trouvées: {self.stats['threats_found']} | "
        stats_text += f"Durée: {duration:.2f} secondes"
        self.system_stats_label.configure(text=stats_text)
        
        self.status_bar.configure(text="Analyse du système terminée")
        self.scan_running = False
    
    def _handle_scan_error(self, error_message):
        """Gérer les erreurs d'analyse"""
        if hasattr(self, 'cancel_scan_button'):
            self.cancel_scan_button.destroy()
            
        self.system_result_text.insert("end", f"\n❌ Erreur lors de l'analyse: {error_message}\n")
        self.status_bar.configure(text="Erreur lors de l'analyse du système")
        self.scan_running = False
    
    def cancel_scan(self):
        """Annuler l'analyse en cours"""
        if hasattr(self, 'scan_running') and self.scan_running:
            self.scan_running = False
            self.status_bar.configure(text="Analyse annulée")
            self.system_result_text.insert("end", "\n⚠️ Analyse annulée par l'utilisateur\n")
            
            if hasattr(self, 'cancel_scan_button'):
                self.cancel_scan_button.destroy()
    
    def run(self):
        self.app.mainloop()

    def toggle_realtime_protection(self):
        """Active ou désactive la protection en temps réel"""
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
        """Simule l'activité de protection en temps réel pour démonstration"""
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
        """Ajuste la luminosité d'une couleur hexadécimale"""
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
    app = ModernAntivirusGUI()
    app.run()

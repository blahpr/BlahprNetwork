import tkinter as tk
import os, io, zipfile, urllib.parse
from http.server import SimpleHTTPRequestHandler
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import os
import socket
import threading
import http.server
import socketserver
import time
import sys
import webbrowser
import re
import random
import html
import urllib.parse
import zipfile
import io
import shutil
import socketserver

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

data_file_path = resource_path("data/some_file.txt")

def get_app_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_executable_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))
    
APP_DIR = get_app_dir()
DATA_DIR = os.path.join(APP_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
BLOCKLIST_FILE = os.path.join(DATA_DIR, "blocked_ips.txt")
BLOCKED_FILES_PATH = os.path.join(DATA_DIR, "blocked_files.txt")
IP_LOG_FILE = os.path.join(DATA_DIR, "connection_log.txt")
DOWNLOAD_LOG_FILE = os.path.join(DATA_DIR, "download_log.txt")
THEME_FILE = os.path.join(DATA_DIR, "theme_settings.txt")
IP_NAME_FILE = os.path.join(DATA_DIR, "ip_names.txt")
ICON_PATH = resource_path(os.path.join("images", "BLAHPR.ico"))

current_downloads = set()

class LoggingHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    blocked_ips = set()
    blocked_files = set()
    ip_log = set()

    EXCLUDED_NAMES = {
        "$RECYCLE.BIN",
        "DumpStack.log.tmp",
        "Recovery",
        "pagefile.sys",
        "System Volume Information",
        "Config.Msi"
    }

    def do_GET(self):
        client_ip = self.client_address[0]
        if client_ip in self.blocked_ips:
            self.send_error(403, "Forbidden: IP blocked.")
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.endswith("/__zip__"):
            self.handle_zip_download(parsed.path)
            return

        requested_path = self.translate_path(self.path)
        if requested_path in getattr(self, 'blocked_files', set()):
            self.send_error(403, "Forbidden: File blocked by server.")
            return

        self.log_ip(client_ip)
        try:
            current_downloads.add(client_ip)
            super().do_GET()
        except ConnectionResetError:
            pass
        finally:
            current_downloads.discard(client_ip)

    def log_ip(self, ip):
        if ip in self.ip_log:
            return
        self.ip_log.add(ip)
        if os.path.exists(IP_LOG_FILE):
            with open(IP_LOG_FILE, 'r') as f:
                logged = {line.strip() for line in f}
            if ip in logged:
                return
        with open(IP_LOG_FILE, 'a') as f:
            f.write(ip + "\n")

    def send_head(self):
        path = self.translate_path(self.path)
        if os.path.isfile(path):
            ip = self.client_address[0]
            with open(DOWNLOAD_LOG_FILE, 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {ip} downloaded {os.path.basename(path)}\n")
        return super().send_head()

    def log_message(self, format, *args):
        return

    def handle_zip_download(self, zip_path):
        decoded_path = urllib.parse.unquote(zip_path)
        if decoded_path.endswith("/__zip__"):
            decoded_path = decoded_path.removesuffix("/__zip__")
        folder_path = self.translate_path(decoded_path)

        print(f"ZIP request for: {zip_path}")
        print(f"Decoded path: {decoded_path}")
        print(f"Translated system path: {folder_path}")

        if not os.path.isdir(folder_path):
            self.send_error(404, "Folder not found")
            return

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_path):
                rel_root = os.path.relpath(root, folder_path)
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.normpath(os.path.join(rel_root, file))
                    if os.path.isfile(full_path):
                        zipf.write(full_path, rel_path)

        zip_buffer.seek(0)
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(folder_path)}.zip"')
        self.send_header("Content-Length", str(len(zip_buffer.getvalue())))
        self.end_headers()
        self.wfile.write(zip_buffer.read())

    def list_directory(self, path):
        try:
            file_list = [f for f in os.listdir(path) if f not in self.EXCLUDED_NAMES]
        except OSError:
            self.send_error(403, "Directory listing failed")
            return None

        file_list.sort(key=lambda a: a.lower())
        display_path = urllib.parse.unquote(self.path)
        encoded_path = html.escape(display_path)
        title = f"BLAHPR {encoded_path}"

        def format_size(size):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} PB"

        html_output = [f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>{title}</title>
                <style>
                    body {{
                        background-color: #282a36;
                        color: #f8f8f2;
                        font-family: 'Segoe UI', sans-serif;
                        margin: 0;
                        padding: 20px;
                    }}
                    h1 {{
                        font-size: 1.5em;
                        border-bottom: 2px solid #44475a;
                        padding-bottom: 0.3em;
                    }}
                    a {{
                        color: #8be9fd;
                        text-decoration: none;
                    }}
                    a:hover {{
                        color: #50fa7b;
                        text-decoration: underline;
                    }}
                    ul {{
                        list-style-type: none;
                        padding: 0;
                    }}
                    li {{
                        display: flex;
                        justify-content: space-between;
                        padding: 6px 10px;
                        margin: 2px 0;
                        background: #44475a;
                        border-radius: 5px;
                        transition: background 0.2s;
                    }}
                    li:hover {{
                        background: #6272a4;
                    }}
                    .parent {{
                        font-weight: bold;
                    }}
                    .size {{
                        color: #bd93f9;
                        font-size: 0.9em;
                        white-space: nowrap;
                    }}
                    .size a {{
                        margin-left: 8px;
                        color: #ff79c6;
                    }}
                </style>
            </head>
            <body>
                <h1>{title}</h1>
                <ul>
        """]

        # Fix parent directory link — add trailing slash and correct HTML tag
        if self.path.rstrip('/') != '':
            parent = os.path.dirname(self.path.rstrip('/'))
            parent = parent if parent.endswith('/') else parent + '/'
            parent_link = urllib.parse.quote(parent)
            html_output.append(f'<li class="parent"><a href="{parent_link}">⬅️ Parent Directory</a><span class="size"></span></li>')

        for name in file_list:
            fullname = os.path.join(path, name)
            display_name = name + "/" if os.path.isdir(fullname) else name
            linkname = urllib.parse.quote(name)

            size_display = ""
            zip_link = ""
            if os.path.isdir(fullname):
                zip_url = urllib.parse.quote(name + "/__zip__")
                zip_link = f'<a href="{zip_url}">[📦 ZIP]</a>'
                size_display = ""  # no size for folders
            elif os.path.isfile(fullname):
                size_display = format_size(os.path.getsize(fullname))

            html_output.append(f'''
                <li>
                    <a href="{linkname}">{html.escape(display_name)}</a>
                    <span class="size">{html.escape(size_display)}{' ' + zip_link if zip_link else ''}</span>
                </li>
            ''')

        html_output.append("""
                </ul>
            </body>
            </html>
        """)

        encoded = "\n".join(html_output).encode("utf-8", "surrogateescape")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        return None

class GUIBlahpr_Net(tk.Tk):
    def __init__(self):
        super().__init__()

        self.themes = {
            "Light": {"bg": "white", "fg": "black"},
            "Dark": {"bg": "#2e2e2e", "fg": "white"},
            "Blue": {"bg": "#add8e6", "fg": "black"},
            "Midnight": {"bg": "#121212", "fg": "#e0e0e0"},
            "Solarized Light": {"bg": "#fdf6e3", "fg": "#657b83"},
            "Solarized Dark": {"bg": "#002b36", "fg": "#839496"},
            "Monokai": {"bg": "#272822", "fg": "#f8f8f2"},
            "Dracula": {"bg": "#282a36", "fg": "#f8f8f2"},
            "Nord": {"bg": "#2e3440", "fg": "#d8dee9"},
            "Gruvbox Light": {"bg": "#fbf1c7", "fg": "#3c3836"},
            "Gruvbox Dark": {"bg": "#282828", "fg": "#ebdbb2"},
            "Forest": {"bg": "#1b3c2f", "fg": "#dcecc9"},
            "Ocean": {"bg": "#011f4b", "fg": "#b3cde0"},
            "Sunset": {"bg": "#ffccbc", "fg": "#4e342e"},
            "Mint": {"bg": "#e0f2f1", "fg": "#004d40"},
            "Lavender": {"bg": "#f3e5f5", "fg": "#4a148c"},
            "Peach": {"bg": "#ffe0b2", "fg": "#6d4c41"},
            "Slate": {"bg": "#708090", "fg": "#f5f5f5"},
            "Sand": {"bg": "#f4e7d3", "fg": "#6d4c41"},
            "Cloud": {"bg": "#e0f7fa", "fg": "#006064"},
            "Charcoal": {"bg": "#36454f", "fg": "#f0f0f0"},
            "Rose": {"bg": "#ffe4e1", "fg": "#8b0000"},
            "Sky": {"bg": "#87ceeb", "fg": "#000080"},
            "Graphite": {"bg": "#2f4f4f", "fg": "#ffffff"},
            "Neon": {"bg": "#1a1a1a", "fg": "#39ff14"},
            "Royal": {"bg": "#4169e1", "fg": "#ffffff"},
            "Pumpkin": {"bg": "#ff7518", "fg": "#4b1c00"},
            "Steel": {"bg": "#7a8b8b", "fg": "#ffffff"},
            "Bubblegum": {"bg": "#ffc0cb", "fg": "#8b008b"},
            "Jungle": {"bg": "#2e4600", "fg": "#a2c523"},
            "Shadow": {"bg": "#1c1c1c", "fg": "#dcdcdc"},
            "Ivory": {"bg": "#fffff0", "fg": "#333333"},
            "Paper": {"bg": "#f5f5f5", "fg": "#212121"},
        }
        self.current_theme = "Light"
        self.load_theme()

        self.ip_names = {}
        self.blocked_files = set()
        self.title("Blahpr Networks INC.")
        self.geometry("630x735")
        self.resizable(True, True)
        self.iconbitmap(ICON_PATH)
        self.create_menu()
        self.verbose = tk.BooleanVar()
        self.httpd = None
        self.server_thread = None
        self.shared_folder = None
        self.port = tk.IntVar(value=8080)
        self.bind_ip = tk.StringVar(value=self.get_default_ip())

        self.tree_states = set()
        self.create_widgets()
        self.setup_themes()
        
        self.load_blocklist()
        self.load_blocked_files()
        self.load_ip_names()
        self.update_downloader_list()

    def save_theme(self):
        try:
            with open(THEME_FILE, 'w') as f:
                f.write(self.current_theme)
        except Exception as e:
            self.log_to_console(f"Error saving theme: {e}")

    def load_theme(self):
        if os.path.exists(THEME_FILE):
            try:
                with open(THEME_FILE, 'r') as f:
                    theme = f.read().strip()
                    if theme in self.themes:
                        self.current_theme = theme
            except Exception as e:
                self.log_to_console(f"Error loading theme: {e}")

    def setup_themes(self):
        self.style = ttk.Style(self)
        self.style.theme_use('clam')  # Base ttk theme
        self.apply_theme(self.current_theme)

    def apply_theme(self, theme_name):
        theme = self.themes.get(theme_name, self.themes["Light"])
        self.current_theme = theme_name
        bg = theme["bg"]
        fg = theme["fg"]

        # Configure main window bg
        self.configure(bg=bg)

        # Configure ttk styles for common widgets
        self.style.configure('TFrame', background=bg)
        self.style.configure('TLabel', background=bg, foreground=fg)
        self.style.configure('TButton', background=bg, foreground=fg)
        self.style.configure('Treeview', background=bg, foreground=fg, fieldbackground=bg)
        self.style.configure('TEntry', fieldbackground=bg, foreground=fg)

        # For Text and Listbox widgets, set their colors manually
        self.console.configure(bg=bg, fg=fg, insertbackground=fg)
        self.ip_listbox.configure(bg=bg, fg=fg, selectbackground=fg, selectforeground=bg)
        self.download_listbox.configure(bg=bg, fg=fg, selectbackground=fg, selectforeground=bg)

        # Recursively configure classic tk widgets colors
        def recursive_configure(widget):
            # Skip ttk widgets, handled by style
            if isinstance(widget, (tk.Listbox, tk.Text, tk.Entry)):
                try:
                    widget.configure(bg=bg, fg=fg)
                except Exception:
                    pass
            for child in widget.winfo_children():
                recursive_configure(child)
        recursive_configure(self)

        self.update_theme_menu_check()
        self.save_theme()
        self.log_to_console(f"Theme changed to {theme_name}")

    def update_theme_menu_check(self):
        for index, theme in enumerate(self.theme_names):
            label = f"✓ {theme}" if theme == self.current_theme else theme
            self.theme_menu.entryconfig(index, label=label)

    def on_mousewheel_theme(self, event):
        idx = self.theme_names.index(self.current_theme)
        if event.delta > 0:
            idx = (idx - 1) % len(self.theme_names)
        else:
            idx = (idx + 1) % len(self.theme_names)
        self.apply_theme(self.theme_names[idx])

    def is_valid_local_ip(self, ip):
        try:
            socket.inet_aton(ip)
        except socket.error:
            return False

        try:
            local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        except socket.gaierror:
            local_ips = []

        return ip in local_ips or ip == "127.0.0.1" or ip == "0.0.0.0"

    def create_widgets(self):
        # Top Control Frame
        control_frame = ttk.LabelFrame(self, text="Controls")
        control_frame.pack(fill='x', padx=5, pady=5)

        # Folder and Log Controls
        ttk.Button(control_frame, text="Share Folder", command=self.select_and_share_folder).pack(side='left', padx=5, pady=5)
        ttk.Button(control_frame, text="Refresh IP Log", command=self.refresh_ip_list).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Clear Download Log", command=self.clear_download_log).pack(side='left', padx=5)

        # Shortcut Controls
        ttk.Button(control_frame, text="Create Desktop Shortcut", command=self.create_desktop_shortcut).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Delete Old Shortcuts", command=self.delete_old_shortcuts).pack(side='left', padx=5)

        # IP/Port Entry + Server
        ip_port_frame = ttk.Frame(self)
        ip_port_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(ip_port_frame, text="IP:").pack(side='left', padx=(0, 2))
        self.ip_entry = ttk.Entry(ip_port_frame, textvariable=self.bind_ip, width=14)
        self.ip_entry.pack(side='left')

        ttk.Label(ip_port_frame, text="Port:").pack(side='left', padx=(10, 2))
        self.port_entry = ttk.Entry(ip_port_frame, textvariable=self.port, width=6)
        self.port_entry.pack(side='left')

        ttk.Button(ip_port_frame, text="Suggest IP & Port", command=self.suggest_ip_port).pack(side='left', padx=10)
        self.start_server_button = ttk.Button(ip_port_frame, text="Start Server", command=self.toggle_server, state='disabled')
        self.start_server_button.pack(side='left', padx=5)

        # Console Output
        self.console = scrolledtext.ScrolledText(self, height=1, state='disabled')
        self.console.pack(fill='x', expand=False, padx=5, pady=(0, 5))

        # Connected IPs
        ip_frame = ttk.LabelFrame(self, text="Connected IPs (right-click to rename, click to block/unblock)")
        ip_frame.pack(fill='x', padx=5, pady=5)
        self.ip_listbox = tk.Listbox(ip_frame, height=3)
        self.ip_listbox.pack(fill='x', padx=5, pady=5)
        self.ip_listbox.bind("<Button-1>", self.toggle_block_ip)
        self.ip_listbox.bind("<Button-3>", self.rename_ip)

        # Downloading Now
        downloading_frame = ttk.LabelFrame(self, text="Currently Downloading")
        downloading_frame.pack(fill='x', padx=5, pady=5)
        self.download_listbox = tk.Listbox(downloading_frame, height=3)
        self.download_listbox.pack(fill='x', padx=5, pady=5)

        ttk.Button(self, text="View Download Log", command=self.show_download_log).pack(pady=5)

        # Shared Folder Tree
        tree_frame = ttk.LabelFrame(self, text="Shared Folder Contents")
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.tree = ttk.Treeview(tree_frame)
        self.tree.pack(fill='both', expand=True, padx=5, pady=5)
        self.tree.bind("<Button-3>", self.tree_context_menu)

        # Tree Control Buttons
        bottom_buttons = ttk.Frame(tree_frame)
        bottom_buttons.pack(fill='x', pady=5, padx=5)
        ttk.Button(bottom_buttons, text="Refresh View", command=self.refresh_tree).pack(side='left')
        ttk.Button(bottom_buttons, text="Clear Blocked Files", command=self.clear_blocked_files).pack(side='right')

    def create_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="How to Use BlahprNet", command=self.show_usage_help)
        help_menu.add_separator()
        help_menu.add_command(label="IP Address Info", command=self.show_ip_info)
        help_menu.add_separator()
        help_menu.add_command(label="Visit GitHub Repo", command=self.open_github)
        menubar.add_cascade(label="Help", menu=help_menu)

        # Theme Menu
        self.theme_menu = tk.Menu(menubar, tearoff=0)
        self.theme_names = list(self.themes.keys())

        for theme in self.theme_names:
            self.theme_menu.add_command(
                label=theme,
                command=lambda t=theme: self.apply_theme(t)
            )

        self.update_theme_menu_check()
        menubar.add_cascade(label="Theme", menu=self.theme_menu)

        # Optional: Mouse wheel to cycle themes
        self.bind_all("<Control-MouseWheel>", self.on_mousewheel_theme)

    def open_github(self):
        webbrowser.open("https://github.com/BLAHPR")

    def find_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    def get_best_local_ip_and_port(self):
        # Get the best local IP (not loopback)
        ip = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))  # Google's DNS
                ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'  # fallback
        
        # Find an open random port
        while True:
            port = random.randint(49152, 65535)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind((ip, port))
                    return ip, port
                except OSError:
                    continue  # Try another port

    def suggest_ip_port(self):
        ip, port = self.get_best_local_ip_and_port()
        self.bind_ip.set(ip)
        self.port.set(port)

        # Output message to the console text widget
        self.console.config(state='normal')
        self.console.insert('end', f"Suggested IP: {ip}, Port: {port}\n")
        self.console.see('end')
        self.console.config(state='disabled')

    def show_usage_help(self):
        help_text = (
            "📘 BlahprNet Usage Guide\n\n"
            "🖱️ Mouse Controls:\n"
            "  - Ctrl + Mouse Wheel: Cycle through themes.\n"
            "  - Right-click IP: Rename IP.\n"
            "  - Left-click IP: Toggle block/unblock.\n"
            "  - Right-click file in folder tree: Block/Unblock file access.\n\n"
            "🧰 Other Controls:\n"
            "  - 'Share Folder': Choose folder to share.\n"
            "  - 'Start Server': Start file-sharing server.\n"
            "  - 'View Download Log': View downloaded file history.\n"
            "  - 'Clear Download Log': Erase download history.\n"
            "  - 'Create Desktop Shortcut': Makes a .url link to your server.\n\n"
            "🎨 Themes:\n"
            "  - Use the 'Theme' menu to choose a color theme.\n"
            "  - Use Ctrl + Scroll Wheel to cycle through themes.\n\n"
            "🌐 IP Tips:\n"
            "  - Bind IP must be your local or public IP address.\n"
            "  - Click Help → IP Address Info for IP format guidance.\n\n"
            "🔒 Blocking:\n"
            "  - Blocked IPs will receive 403 Forbidden errors.\n"
            "  - Blocked files won't be downloadable.\n"
        )
        messagebox.showinfo("How to Use BlahprNet", help_text)

    def show_ip_info(self):
        info_text = (
            "IPv4 Address Format:\n"
            " - Four numbers (octets) separated by dots, each 0-255.\n"
            " - Example: 192.168.1.1 or 65.67.116.114\n\n"
            "Common Reserved / Private Ranges:\n"
            " - 10.0.0.0 to 10.255.255.255 (Private)\n"
            " - 172.16.0.0 to 172.31.255.255 (Private)\n"
            " - 192.168.0.0 to 192.168.255.255 (Private)\n"
            " - 127.0.0.0 to 127.255.255.255 (Loopback)\n"
            " - 0.0.0.0 (This host)\n\n"
            "You can generally use any valid public IP address you own or your local LAN IP."
        )
        messagebox.showinfo("IP Address Info", info_text)

    def toggle_server(self):
        if self.httpd:
            self.stop_server()
        else:
            self.start_server()

    def stop_server(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd = None
            self.server_thread = None
            self.start_server_button.config(text="Start Server")
            self.log_to_console("Server stopped.")

    def get_available_local_ips(self):
        hostname = socket.gethostname()
        try:
            ips = socket.gethostbyname_ex(hostname)[2]
            return [ip for ip in ips if not ip.startswith("127.")]
        except socket.gaierror:
            return []

    def start_server(self):
        if not self.shared_folder:
            messagebox.showerror("Error", "No folder selected.")
            return
        bind_ip = self.ip_entry.get().strip()
        port = int(self.port_entry.get().strip())

        if not self.is_valid_local_ip(bind_ip):
            messagebox.showerror("Invalid IP", f"The IP address {bind_ip} is not available on this machine.")
            return

        self.start_http_server(self.shared_folder, bind_ip, port)

        self.start_server_button.config(text="Stop Server")
        self.log_to_console(f"Sharing folder at:")
        self.log_to_console(f"  ▶ http://{bind_ip}:{port}/")

    def start_http_server(self, directory, ip, port):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception as e:
                print(f"Error shutting down server: {e}")
            self.httpd = None

        # Capture blocked files snapshot
        blocked_files_copy = self.blocked_files.copy()

        class CustomHandler(LoggingHTTPRequestHandler):
            blocked_files = blocked_files_copy

        LoggingHTTPRequestHandler.blocked_ips = self.load_blocklist()
        LoggingHTTPRequestHandler.ip_log = set()

        os.chdir(directory)
        self.httpd = socketserver.ThreadingTCPServer((ip, port), CustomHandler)
        self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.server_thread.start()

    def get_default_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_usable_local_ips(self):
        try:
            hostname = socket.gethostname()
            ips = socket.gethostbyname_ex(hostname)[2]
            return list(set(ip for ip in ips if not ip.startswith("127.")))
        except Exception:
            return []

    def log_to_console(self, msg):
        if hasattr(self, "console") and self.console:
            self.console.configure(state='normal')
            self.console.insert(tk.END, msg + "\n")
            self.console.see(tk.END)
            self.console.configure(state='disabled')

    def clear_download_log(self):
        if os.path.exists(DOWNLOAD_LOG_FILE):
            os.remove(DOWNLOAD_LOG_FILE)
        messagebox.showinfo("Log Cleared", "Download log cleared.")

    def select_and_share_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.shared_folder = folder
            self.log_to_console("Folder selected. Ready to start server.")
            self.start_server_button.config(state='normal')
            self.refresh_tree()

    def refresh_ip_list(self):
        self.ip_listbox.delete(0, tk.END)
        unique_ips = set()
        if os.path.exists(IP_LOG_FILE):
            with open(IP_LOG_FILE, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip not in unique_ips:
                        unique_ips.add(ip)
                        tag = "[BLOCKED]" if ip in LoggingHTTPRequestHandler.blocked_ips else "[ALLOWED]"
                        name = self.ip_names.get(ip, "")
                        display = f"{tag} {ip}" + (f" ({name})" if name else "")
                        self.ip_listbox.insert(tk.END, display)

    def toggle_block_ip(self, event):
        selection = self.ip_listbox.curselection()
        if not selection:
            return
        text = self.ip_listbox.get(selection[0])
        ip = text.split()[1]
        if ip in LoggingHTTPRequestHandler.blocked_ips:
            LoggingHTTPRequestHandler.blocked_ips.remove(ip)
        else:
            LoggingHTTPRequestHandler.blocked_ips.add(ip)
        self.save_blocklist()
        self.refresh_ip_list()

    def rename_ip(self, event):
        index = self.ip_listbox.nearest(event.y)
        if index == -1:
            return
        text = self.ip_listbox.get(index)
        ip = text.split()[1]
        new_name = simpledialog.askstring("Rename IP", f"Enter name for {ip}:")
        if new_name:
            self.ip_names[ip] = new_name.strip()
            self.save_ip_names()
            self.refresh_ip_list()

    def load_ip_names(self):
        if os.path.exists(IP_NAME_FILE):
            with open(IP_NAME_FILE, 'r') as f:
                self.ip_names = dict(line.strip().split(",", 1) for line in f if "," in line)

    def save_ip_names(self):
        with open(IP_NAME_FILE, 'w') as f:
            for ip, name in self.ip_names.items():
                f.write(f"{ip},{name}\n")

    def load_blocklist(self):
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE, 'r') as f:
                LoggingHTTPRequestHandler.blocked_ips = set(line.strip() for line in f)
        return LoggingHTTPRequestHandler.blocked_ips

    def save_blocklist(self):
        with open(BLOCKLIST_FILE, 'w') as f:
            for ip in LoggingHTTPRequestHandler.blocked_ips:
                f.write(ip + "\n")

    def load_blocked_files(self):
        if os.path.exists(BLOCKED_FILES_PATH):
            with open(BLOCKED_FILES_PATH, 'r') as f:
                self.blocked_files = set(line.strip() for line in f)

    def save_blocked_files(self):
        with open(BLOCKED_FILES_PATH, 'w') as f:
            for path in self.blocked_files:
                f.write(path + "\n")

    def clear_blocked_files(self):
        self.blocked_files.clear()
        self.save_blocked_files()
        self.refresh_tree()
        if self.httpd:
            self.start_http_server(self.shared_folder, self.bind_ip.get(), self.port.get())

    def tree_context_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return
        self.tree.selection_set(item_id)
        path = self.get_full_tree_path(item_id)

        menu = tk.Menu(self, tearoff=0)
        if path in self.blocked_files:
            menu.add_command(label="Unblock", command=lambda: self.unblock_file(path))
        else:
            menu.add_command(label="Block", command=lambda: self.block_file(path))
        menu.post(event.x_root, event.y_root)

    def block_file(self, path):
        self.blocked_files.add(path)
        self.save_blocked_files()
        self.refresh_tree()
        if self.httpd:
            threading.Thread(target=self.start_http_server, args=(
                self.shared_folder, self.bind_ip.get(), self.port.get()
            ), daemon=True).start()

    def unblock_file(self, path):
        self.blocked_files.discard(path)
        self.save_blocked_files()
        self.refresh_tree()
        if self.httpd:
            threading.Thread(target=self.start_http_server, args=(
                self.shared_folder, self.bind_ip.get(), self.port.get()
            ), daemon=True).start()

    def get_full_tree_path(self, item_id):
        parts = []
        while item_id:
            parts.insert(0, self.tree.item(item_id)['text'].replace("[BLOCKED] ", ""))
            item_id = self.tree.parent(item_id)
        return os.path.abspath(os.path.join(*parts))

    def update_downloader_list(self):
        self.download_listbox.delete(0, tk.END)
        for ip in sorted(current_downloads):
            self.download_listbox.insert(tk.END, ip)
        self.after(2000, self.update_downloader_list)

    def show_download_log(self):
        if os.path.exists(DOWNLOAD_LOG_FILE):
            with open(DOWNLOAD_LOG_FILE, 'r') as f:
                log = f.read()
        else:
            log = "No downloads yet."
        messagebox.showinfo("Download Log", log)

    def refresh_tree(self):
        self.tree_states = set()
        def save_expansion(item):
            if self.tree.item(item, "open"):
                self.tree_states.add(self.get_full_tree_path(item))
            for child in self.tree.get_children(item):
                save_expansion(child)
        save_expansion("")

        self.tree.delete(*self.tree.get_children())
        if not self.shared_folder:
            return
        root = self.tree.insert("", "end", text=self.shared_folder, open=True)
        self.populate_tree(self.shared_folder, root)

    def populate_tree(self, path, parent):
        try:
            for item in os.listdir(path):
                abspath = os.path.abspath(os.path.join(path, item))
                label = "[BLOCKED] " + item if abspath in self.blocked_files else item
                node = self.tree.insert(parent, 'end', text=label, open=abspath in self.tree_states)
                if os.path.isdir(abspath):
                    self.populate_tree(abspath, node)
        except PermissionError:
            pass

    def create_desktop_shortcut(self):
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()

        if not ip or not port:
            messagebox.showerror("Error", "Please enter both IP and Port.")
            return

        # Replace dots in IP with underscores for filename safety
        safe_ip = ip.replace('.', '_')
        shortcut_name = f"BlahprNet_{safe_ip}_{port}.url"

        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        shortcut_path = os.path.join(desktop, shortcut_name)

        url = f"http://{ip}:{port}"

        try:
            with open(shortcut_path, 'w') as f:
                f.write(f"[InternetShortcut]\nURL={url}\n")
            self.log_to_console(f"Shortcut created: {shortcut_path}")
            messagebox.showinfo("Shortcut Created", f"Shortcut created:\n{shortcut_path}")
        except Exception as e:
            self.log_to_console(f"Failed to create shortcut: {e}")
            messagebox.showerror("Error", f"Failed to create shortcut:\n{e}")

    def delete_old_shortcuts(self):
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        self.log_to_console(f"Scanning Desktop at: {desktop}")

        try:
            files = os.listdir(desktop)
        except Exception as e:
            messagebox.showerror("Error", f"Unable to access Desktop:\n{e}")
            return

        # Collect all matching shortcuts
        matching = []
        for f in files:
            if f.startswith("BlahprNet") and f.endswith(".url"):
                full_path = os.path.join(desktop, f)
                matching.append(full_path)

        if not matching:
            messagebox.showinfo("No Shortcuts", "No BlahprNet .url shortcuts found on your Desktop.")
            return

        self.log_to_console(f"Found {len(matching)} matching shortcuts:")
        for f in matching:
            self.log_to_console(f)

        confirm = messagebox.askyesno(
            "Delete Shortcuts",
            f"Found {len(matching)} BlahprNet shortcut(s).\n\nDo you want to delete them all?"
        )
        if not confirm:
            return

        deleted = 0
        for path in matching:
            try:
                os.remove(path)
                deleted += 1
                self.log_to_console(f"Deleted: {path}")
            except Exception as e:
                self.log_to_console(f"Failed to delete {path}: {e}")

        messagebox.showinfo("Done", f"{deleted} shortcut(s) deleted.")

    def randomize_ip_port(self):
        # Smart Local IP ranges
        ip_ranges = [
            (10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
            (172, random.randint(16, 31), random.randint(0, 255), random.randint(1, 254)),
            (192, 168, random.randint(0, 255), random.randint(1, 254))
        ]
        chosen_ip = random.choice(ip_ranges)
        ip = ".".join(map(str, chosen_ip))

        # Safe high-numbered port range
        port = random.randint(1024, 65535)

        # Update GUI fields
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, ip)
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, str(port))

        self.log_to_console(f"Randomized IP: {ip}, Port: {port}")

        # Update preview, if present
        if hasattr(self, 'update_shortcut_preview'):
            self.update_shortcut_preview()

if __name__ == "__main__":
    app = GUIBlahpr_Net()
    app.mainloop()

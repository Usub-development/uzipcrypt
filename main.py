#!/usr/bin/env python3
"""
Encrypted ZIP Manager
─────────────────────
A GUI application for working with AES-256-CBC encrypted ZIP archives.

Architecture:
  • ZIP layer  — standard zipfile with LZMA compression (no ZIP-level encryption)
  • AES layer  — AES-256-CBC + HMAC-SHA256 wraps the entire ZIP as a binary blob
  • Container  — custom .enczip file format with header, salt, IV, HMAC, ciphertext

File format (.enczip):
  ┌──────────────────────────────────────────┐
  │ magic       8 bytes   "ENCZIP01"         │
  │ mode        1 byte    0x00=pass, 0x01=key│
  │ salt       32 bytes   PBKDF2 salt         │
  │ iv         16 bytes   AES-CBC IV           │
  │ hmac       32 bytes   HMAC-SHA256(ct)      │
  │ ciphertext  …         AES-256-CBC(ZIP)     │
  └──────────────────────────────────────────┘

Dependencies:
  pip install cryptography

Usage:
  python encrypted_zip_manager.py [--archive path.enczip] [--editor /usr/bin/code]
"""

import argparse
import hashlib
import hmac as hmac_mod
import io
import json
import os
import platform
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import zipfile
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
except ImportError:
    print("cryptography is required:  pip install cryptography")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  AES-256-CBC Encrypted Container
# ═══════════════════════════════════════════════════════════════════════════

MAGIC = b"ENCZIP01"
MODE_PASSPHRASE = 0x00
MODE_RAW_KEY    = 0x01
HEADER_SIZE     = 8 + 1 + 32 + 16 + 32   # 89 bytes


class CryptoError(Exception):
    pass


class EncryptedContainer:
    """
    Read / write AES-256-CBC encrypted containers.

    Passphrase mode:  key + hmac_key derived via PBKDF2-SHA256 (300k iterations)
    Raw-key mode:     caller supplies 32-byte key; HMAC key = SHA-256("hmac-" + key)
    """

    PBKDF2_ITERATIONS = 300_000

    @staticmethod
    def derive_from_passphrase(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
        dk = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), salt,
            EncryptedContainer.PBKDF2_ITERATIONS, dklen=64
        )
        return dk[:32], dk[32:]

    @staticmethod
    def keys_from_raw(raw_key: bytes) -> tuple[bytes, bytes]:
        hmac_key = hashlib.sha256(b"hmac-" + raw_key).digest()
        return raw_key, hmac_key

    @classmethod
    def encrypt(cls, plaintext: bytes, *,
                passphrase: str | None = None,
                raw_key: bytes | None = None,
                iv: bytes | None = None) -> bytes:
        if raw_key:
            mode = MODE_RAW_KEY
            salt = b"\x00" * 32
            aes_key, hmac_key = cls.keys_from_raw(raw_key)
        elif passphrase:
            mode = MODE_PASSPHRASE
            salt = os.urandom(32)
            aes_key, hmac_key = cls.derive_from_passphrase(passphrase, salt)
        else:
            raise ValueError("Provide passphrase or raw_key")

        if iv is None:
            iv = os.urandom(16)
        if len(iv) != 16:
            raise ValueError(f"IV must be 16 bytes, got {len(iv)}")

        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        mac = hmac_mod.new(hmac_key, ciphertext, hashlib.sha256).digest()

        return MAGIC + struct.pack("B", mode) + salt + iv + mac + ciphertext

    @classmethod
    def decrypt(cls, container: bytes, *,
                passphrase: str | None = None,
                raw_key: bytes | None = None) -> bytes:
        if len(container) < HEADER_SIZE:
            raise CryptoError("File too small to be an encrypted container")

        magic = container[:8]
        if magic != MAGIC:
            raise CryptoError("Not an ENCZIP file (invalid magic header)")

        mode  = container[8]
        salt  = container[9:41]
        iv    = container[41:57]
        mac   = container[57:89]
        ciphertext = container[89:]

        if mode == MODE_RAW_KEY:
            if not raw_key:
                raise CryptoError("This file was encrypted with a raw key, not a passphrase")
            aes_key, hmac_key = cls.keys_from_raw(raw_key)
        elif mode == MODE_PASSPHRASE:
            if not passphrase:
                raise CryptoError("This file was encrypted with a passphrase")
            aes_key, hmac_key = cls.derive_from_passphrase(passphrase, salt)
        else:
            raise CryptoError(f"Unknown encryption mode: 0x{mode:02x}")

        expected_mac = hmac_mod.new(hmac_key, ciphertext, hashlib.sha256).digest()
        if not hmac_mod.compare_digest(mac, expected_mac):
            raise CryptoError("HMAC verification failed — wrong password/key or corrupted file")

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    @classmethod
    def encrypt_to_file(cls, path: str, plaintext: bytes, **kwargs):
        data = cls.encrypt(plaintext, **kwargs)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)

    @classmethod
    def decrypt_file(cls, path: str, **kwargs) -> bytes:
        with open(path, "rb") as f:
            return cls.decrypt(f.read(), **kwargs)

    @classmethod
    def get_file_info(cls, path: str) -> dict:
        with open(path, "rb") as f:
            header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE or header[:8] != MAGIC:
            return {"valid": False}
        mode = header[8]
        iv = header[41:57]
        fsize = os.path.getsize(path)
        return {
            "valid": True,
            "mode": "passphrase" if mode == MODE_PASSPHRASE else "raw_key",
            "iv": iv.hex(),
            "ciphertext_size": fsize - HEADER_SIZE,
            "total_size": fsize,
        }


# ═══════════════════════════════════════════════════════════════════════════
#  ZIP helpers (compression only, no encryption)
# ═══════════════════════════════════════════════════════════════════════════

def zip_create_empty() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_LZMA):
        pass
    return buf.getvalue()


def zip_list(zip_bytes: bytes) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        return [i for i in zf.infolist() if not i.is_dir()]


def zip_read_file(zip_bytes: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        return zf.read(name)


def zip_add_files(zip_bytes: bytes, files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf_in:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_LZMA) as zf_out:
            for item in zf_in.infolist():
                if item.is_dir() or item.filename in files:
                    continue
                zf_out.writestr(item, zf_in.read(item.filename))
            for name, data in files.items():
                zf_out.writestr(name, data)
    return buf.getvalue()


def zip_delete_files(zip_bytes: bytes, names: set[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf_in:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_LZMA) as zf_out:
            for item in zf_in.infolist():
                if item.is_dir() or item.filename in names:
                    continue
                zf_out.writestr(item, zf_in.read(item.filename))
    return buf.getvalue()


def zip_extract_file(zip_bytes: bytes, name: str, dest_dir: str) -> str:
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        zf.extract(name, dest_dir)
    return os.path.join(dest_dir, name)


def zip_extract_all(zip_bytes: bytes, dest_dir: str):
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        zf.extractall(dest_dir)


# ═══════════════════════════════════════════════════════════════════════════
#  Utility
# ═══════════════════════════════════════════════════════════════════════════

def human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{nbytes} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


def parse_hex(text: str, expected_len: int) -> bytes | None:
    text = text.strip()
    if not text:
        return None
    try:
        data = bytes.fromhex(text)
        if len(data) != expected_len:
            raise ValueError(f"Expected {expected_len} bytes ({expected_len*2} hex chars), got {len(data)}")
        return data
    except ValueError as exc:
        messagebox.showerror("Invalid hex", str(exc))
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  Editor Registry
# ═══════════════════════════════════════════════════════════════════════════

CONFIG_PATH = os.path.join(Path.home(), ".enczip_editors.json")


class EditorRegistry:
    def __init__(self, fallback_editor: str | None = None):
        self.fallback: str = fallback_editor or self._detect_fallback()
        self.ext_map: dict[str, str] = {}
        self._load_config()
        if not self.ext_map:
            self.ext_map = self._detect_system_defaults()
            self._save_config()

    def _load_config(self):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.ext_map = data.get("ext_map", {})
            self.fallback = data.get("fallback", self.fallback)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _save_config(self):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump({"fallback": self.fallback, "ext_map": self.ext_map},
                          f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def get_editor(self, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()
        return self.ext_map.get(ext, self.fallback)

    def set_editor(self, ext: str, editor_path: str):
        ext = ext.lower() if ext.startswith(".") else f".{ext.lower()}"
        self.ext_map[ext] = editor_path
        self._save_config()

    def set_fallback(self, editor_path: str):
        self.fallback = editor_path
        self._save_config()

    @staticmethod
    def _detect_fallback() -> str:
        system = platform.system()
        if system == "Windows":
            return "notepad.exe"
        if system == "Darwin":
            return "open"
        for ed in ("xdg-open", "code", "gedit", "kate", "nano", "vi"):
            if shutil.which(ed):
                return ed
        return "vi"

    def _detect_system_defaults(self) -> dict[str, str]:
        system = platform.system()
        if system == "Darwin":
            return self._detect_macos()
        elif system == "Windows":
            return self._detect_windows()
        else:
            return self._detect_linux()

    def _detect_macos(self) -> dict[str, str]:
        exts = [".txt",".md",".json",".py",".js",".html",".css",".xml",".csv",
                ".sh",".docx",".doc",".xlsx",".xls",".pptx",".ppt",".pdf",
                ".png",".jpg",".jpeg",".gif",".svg",".mp3",".mp4",".mov"]
        r = {}
        for ext in exts:
            app = self._macos_app(ext)
            r[ext] = app if app else "open"
        return r

    @staticmethod
    def _macos_app(ext: str) -> str | None:
        try:
            if shutil.which("duti"):
                r = subprocess.run(["duti","-x",ext.lstrip(".")],
                                   capture_output=True, text=True, timeout=3)
                if r.returncode == 0 and r.stdout.strip():
                    name = r.stdout.strip().split("\n")[0].strip()
                    if name:
                        return f'open -a "{name}"'
        except Exception:
            pass
        return None

    def _detect_windows(self) -> dict[str, str]:
        exts = [".txt",".md",".json",".py",".js",".html",".css",".xml",".csv",
                ".docx",".doc",".xlsx",".xls",".pptx",".ppt",".pdf",
                ".png",".jpg",".jpeg",".gif",".svg",".mp3",".mp4"]
        r = {}
        for ext in exts:
            app = self._windows_app(ext)
            if app:
                r[ext] = app
        return r

    @staticmethod
    def _windows_app(ext: str) -> str | None:
        try:
            r = subprocess.run(["cmd","/c",f"assoc {ext}"],
                               capture_output=True, text=True, timeout=3)
            if r.returncode != 0:
                return None
            ftype = r.stdout.strip().split("=", 1)[-1]
            r2 = subprocess.run(["cmd","/c",f"ftype {ftype}"],
                                capture_output=True, text=True, timeout=3)
            if r2.returncode != 0:
                return None
            cmd = r2.stdout.strip().split("=", 1)[-1]
            cmd = cmd.replace('"%1"', "").replace("%1", "").strip().strip('"')
            return cmd if cmd else None
        except Exception:
            return None

    def _detect_linux(self) -> dict[str, str]:
        if not shutil.which("xdg-mime"):
            return {}
        mime_map = {
            ".txt": "text/plain", ".md": "text/markdown", ".json": "application/json",
            ".py": "text/x-python", ".js": "text/javascript", ".html": "text/html",
            ".css": "text/css", ".xml": "application/xml", ".csv": "text/csv",
            ".sh": "application/x-shellscript",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".doc": "application/msword",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".xls": "application/vnd.ms-excel",
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".ppt": "application/vnd.ms-powerpoint",
            ".pdf": "application/pdf",
            ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".gif": "image/gif", ".svg": "image/svg+xml",
            ".mp3": "audio/mpeg", ".mp4": "video/mp4",
        }
        r = {}
        for ext, mime in mime_map.items():
            app = self._linux_app(mime)
            if app:
                r[ext] = app
        return r

    @staticmethod
    def _linux_app(mime: str) -> str | None:
        try:
            r = subprocess.run(["xdg-mime","query","default",mime],
                               capture_output=True, text=True, timeout=3)
            desktop = r.stdout.strip()
            if not desktop:
                return None
            for base in ("/usr/share/applications",
                         "/usr/local/share/applications",
                         os.path.expanduser("~/.local/share/applications")):
                path = os.path.join(base, desktop)
                if os.path.isfile(path):
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if line.startswith("Exec="):
                                cmd = line[5:].strip().split("%")[0].strip().strip('"')
                                return cmd if cmd else None
        except Exception:
            pass
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  Main Application
# ═══════════════════════════════════════════════════════════════════════════

class EncryptedZipManager(tk.Tk):
    TITLE = "Encrypted ZIP Manager  [AES-256-CBC]"

    def __init__(self, archive_path: str | None = None, editor_path: str | None = None):
        super().__init__()
        self.title(self.TITLE)
        self.geometry("960x640")
        self.minsize(720, 460)
        self.configure(bg="#1e1e2e")

        self.archive_path: str | None = archive_path
        self.editors = EditorRegistry(fallback_editor=editor_path)

        # Crypto state
        self.passphrase: str | None = None
        self.raw_key: bytes | None = None   # 32 bytes
        self.raw_iv: bytes | None = None    # 16 bytes

        self.tmp_dir = tempfile.mkdtemp(prefix="enczip_")

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if self.archive_path and os.path.isfile(self.archive_path):
            self._ask_credentials()

    # ── Crypto helpers ──────────────────────────────────────────────────

    def _crypto_kwargs(self, for_encrypt: bool = False) -> dict:
        kw: dict = {}
        if self.raw_key:
            kw["raw_key"] = self.raw_key
        elif self.passphrase:
            kw["passphrase"] = self.passphrase
        if for_encrypt and self.raw_iv:
            kw["iv"] = self.raw_iv
        return kw

    def _has_credentials(self) -> bool:
        return bool(self.passphrase or self.raw_key)

    def _read_zip(self) -> bytes:
        return EncryptedContainer.decrypt_file(self.archive_path, **self._crypto_kwargs())

    def _write_zip(self, zip_bytes: bytes):
        EncryptedContainer.encrypt_to_file(
            self.archive_path, zip_bytes, **self._crypto_kwargs(for_encrypt=True)
        )

    # ── UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        bg      = "#1e1e2e"
        surface = "#2a2a3c"
        accent  = "#7c3aed"
        text_fg = "#e2e2e8"
        dim     = "#888898"

        style.configure(".",       background=bg, foreground=text_fg, fieldbackground=surface)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=text_fg, font=("Segoe UI", 10))
        style.configure("Dim.TLabel", background=bg, foreground=dim, font=("Segoe UI", 9))
        style.configure("Head.TLabel", background=bg, foreground=text_fg, font=("Segoe UI", 14, "bold"))
        style.configure("TButton", background=accent, foreground="#ffffff", font=("Segoe UI", 10),
                        borderwidth=0, padding=(12, 6))
        style.map("TButton", background=[("active", "#6d28d9")])
        style.configure("Treeview", background=surface, foreground=text_fg,
                        fieldbackground=surface, rowheight=26, font=("Consolas", 10))
        style.configure("Treeview.Heading", background="#33334a", foreground=text_fg,
                        font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground=surface, foreground=text_fg, insertcolor=text_fg)

        # Toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=12, pady=(12, 4))
        ttk.Label(toolbar, text="\U0001F512 Encrypted ZIP Manager", style="Head.TLabel").pack(side="left")
        btns = ttk.Frame(toolbar)
        btns.pack(side="right")
        for txt, cmd in [("New", self._new_archive), ("Open", self._open_archive),
                         ("Settings", self._open_settings)]:
            ttk.Button(btns, text=txt, command=cmd).pack(side="left", padx=4)

        # Crypto info bar
        self.lbl_crypto = ttk.Label(self, text="", style="Dim.TLabel")
        self.lbl_crypto.pack(fill="x", padx=12, pady=2, anchor="w")

        # Info bar
        info = ttk.Frame(self)
        info.pack(fill="x", padx=12, pady=2)
        self.lbl_archive = ttk.Label(info, text="No archive loaded", style="Dim.TLabel")
        self.lbl_archive.pack(side="left")
        self.lbl_stats = ttk.Label(info, text="", style="Dim.TLabel")
        self.lbl_stats.pack(side="right")

        # File list
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=4)
        cols = ("name", "size", "compressed", "modified")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("name", text="Name", anchor="w")
        self.tree.heading("size", text="Size", anchor="e")
        self.tree.heading("compressed", text="Compressed", anchor="e")
        self.tree.heading("modified", text="Modified", anchor="w")
        self.tree.column("name", width=380, anchor="w")
        self.tree.column("size", width=100, anchor="e")
        self.tree.column("compressed", width=100, anchor="e")
        self.tree.column("modified", width=180, anchor="w")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self._edit_selected())

        # Action bar
        actions = ttk.Frame(self)
        actions.pack(fill="x", padx=12, pady=(4, 12))
        for txt, cmd in [("New File",      self._new_file),
                         ("Add Files",     self._add_files),
                         ("Extract",       self._extract_selected),
                         ("Edit in Editor",self._edit_selected),
                         ("Delete",        self._delete_selected),
                         ("Extract All",   self._extract_all)]:
            ttk.Button(actions, text=txt, command=cmd).pack(side="left", padx=4)

    # ── Credentials dialog ──────────────────────────────────────────────

    def _ask_credentials(self):
        dlg = tk.Toplevel(self)
        dlg.title("Unlock / Set Encryption")
        dlg.geometry("520x330")
        dlg.configure(bg="#1e1e2e")
        dlg.transient(self)
        dlg.grab_set()

        row = 0
        ttk.Label(dlg, text="Mode 1 — Passphrase (key derived via PBKDF2):").grid(
            row=row, column=0, columnspan=2, padx=12, pady=(12, 2), sticky="w")
        row += 1
        ttk.Label(dlg, text="Passphrase:").grid(row=row, column=0, padx=12, pady=4, sticky="w")
        ent_pass = ttk.Entry(dlg, show="\u2022", width=44)
        ent_pass.grid(row=row, column=1, padx=12, pady=4)

        row += 1
        ttk.Label(dlg, text="Mode 2 — Raw AES-256 key + IV:").grid(
            row=row, column=0, columnspan=2, padx=12, pady=(12, 2), sticky="w")
        row += 1
        ttk.Label(dlg, text="Key (64 hex = 32 bytes):").grid(row=row, column=0, padx=12, pady=4, sticky="w")
        ent_key = ttk.Entry(dlg, width=44)
        ent_key.grid(row=row, column=1, padx=12, pady=4)
        row += 1
        ttk.Label(dlg, text="IV  (32 hex = 16 bytes):").grid(row=row, column=0, padx=12, pady=4, sticky="w")
        ent_iv = ttk.Entry(dlg, width=44)
        ent_iv.grid(row=row, column=1, padx=12, pady=4)

        row += 1
        if self.archive_path and os.path.isfile(self.archive_path):
            info = EncryptedContainer.get_file_info(self.archive_path)
            if info.get("valid"):
                info_text = (f"Encrypted with: {info['mode']}  |  "
                             f"IV: {info['iv']}  |  "
                             f"Data: {human_size(info['ciphertext_size'])}")
            else:
                info_text = "\u26A0 File does not have ENCZIP header"
            ttk.Label(dlg, text=info_text, style="Dim.TLabel").grid(
                row=row, column=0, columnspan=2, padx=12, pady=4)
            row += 1

        def on_ok():
            pp = ent_pass.get().strip()
            hk = ent_key.get().strip()
            hi = ent_iv.get().strip()

            if hk:
                key = parse_hex(hk, 32)
                if key is None:
                    return
                iv = parse_hex(hi, 16) if hi else None
                if hi and iv is None:
                    return
                self.raw_key = key
                self.raw_iv = iv
                self.passphrase = None
            elif pp:
                self.passphrase = pp
                self.raw_key = None
                self.raw_iv = None
            else:
                messagebox.showwarning("Input required", "Enter a passphrase or hex key + IV.")
                return
            dlg.destroy()
            self._load_archive()

        ttk.Button(dlg, text="Unlock / Create", command=on_ok).grid(
            row=row, column=0, columnspan=2, pady=12)
        ent_pass.focus_set()
        dlg.bind("<Return>", lambda e: on_ok())

    # ── Settings ────────────────────────────────────────────────────────

    def _open_settings(self):
        dlg = tk.Toplevel(self)
        dlg.title("Settings \u2014 Editor Associations")
        dlg.geometry("720x520")
        dlg.configure(bg="#1e1e2e")
        dlg.transient(self)
        dlg.grab_set()

        top = ttk.Frame(dlg)
        top.pack(fill="x", padx=12, pady=(12, 4))
        ttk.Label(top, text="Default editor:").pack(side="left")
        ent_fb = ttk.Entry(top, width=40)
        ent_fb.insert(0, self.editors.fallback)
        ent_fb.pack(side="left", padx=8)
        ttk.Button(top, text="Browse\u2026", command=lambda: self._browse_into(ent_fb)).pack(side="left")

        ttk.Label(dlg, text="Extension \u2192 Editor:", style="Dim.TLabel").pack(
            anchor="w", padx=12, pady=(8, 2))

        tf = ttk.Frame(dlg)
        tf.pack(fill="both", expand=True, padx=12, pady=4)
        cols = ("ext", "editor")
        tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse", height=14)
        tree.heading("ext", text="Extension", anchor="w")
        tree.heading("editor", text="Editor / Command", anchor="w")
        tree.column("ext", width=100)
        tree.column("editor", width=560)
        vsb = ttk.Scrollbar(tf, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        for ext in sorted(self.editors.ext_map):
            tree.insert("", "end", iid=ext, values=(ext, self.editors.ext_map[ext]))

        br = ttk.Frame(dlg)
        br.pack(fill="x", padx=12, pady=4)

        def add_m():
            self._ext_editor_dialog(dlg, tree)
        def edit_m():
            s = tree.selection()
            if s:
                self._ext_editor_dialog(dlg, tree, s[0], self.editors.ext_map.get(s[0], ""))
        def del_m():
            s = tree.selection()
            if s:
                tree.delete(s[0])
        def redetect():
            det = self.editors._detect_system_defaults()
            for ext in sorted(det):
                if tree.exists(ext):
                    tree.item(ext, values=(ext, det[ext]))
                else:
                    tree.insert("", "end", iid=ext, values=(ext, det[ext]))

        ttk.Button(br, text="Add\u2026", command=add_m).pack(side="left", padx=4)
        ttk.Button(br, text="Edit\u2026", command=edit_m).pack(side="left", padx=4)
        ttk.Button(br, text="Delete", command=del_m).pack(side="left", padx=4)
        ttk.Button(br, text="Re-detect from OS", command=redetect).pack(side="left", padx=12)
        tree.bind("<Double-1>", lambda e: edit_m())

        pw = ttk.Frame(dlg)
        pw.pack(fill="x", padx=12, pady=4)
        ttk.Label(pw, text="Encryption:").pack(side="left")
        ttk.Button(pw, text="Change\u2026",
                   command=lambda: [dlg.destroy(), self._ask_credentials()]).pack(side="left", padx=12)

        bottom = ttk.Frame(dlg)
        bottom.pack(fill="x", padx=12, pady=(4, 12))

        def save_all():
            fb = ent_fb.get().strip()
            if fb:
                self.editors.set_fallback(fb)
            new_map = {}
            for iid in tree.get_children():
                v = tree.item(iid, "values")
                new_map[v[0]] = v[1]
            self.editors.ext_map = new_map
            self.editors._save_config()
            dlg.destroy()

        ttk.Button(bottom, text="Save", command=save_all).pack(side="right", padx=4)
        ttk.Button(bottom, text="Cancel", command=dlg.destroy).pack(side="right", padx=4)

    def _browse_into(self, entry: ttk.Entry):
        p = filedialog.askopenfilename(title="Select Executable")
        if p:
            entry.delete(0, "end")
            entry.insert(0, p)

    def _ext_editor_dialog(self, parent, tree, ext="", editor=""):
        d = tk.Toplevel(parent)
        d.title("Extension \u2192 Editor")
        d.geometry("500x140")
        d.configure(bg="#1e1e2e")
        d.transient(parent)
        d.grab_set()
        ttk.Label(d, text="Extension:").grid(row=0, column=0, padx=12, pady=(12,4), sticky="w")
        ent_ext = ttk.Entry(d, width=12)
        ent_ext.insert(0, ext)
        ent_ext.grid(row=0, column=1, padx=4, pady=(12,4), sticky="w")
        ttk.Label(d, text="Editor:").grid(row=1, column=0, padx=12, pady=4, sticky="w")
        ent_ed = ttk.Entry(d, width=40)
        ent_ed.insert(0, editor)
        ent_ed.grid(row=1, column=1, padx=4, pady=4)
        ttk.Button(d, text="Browse\u2026", command=lambda: self._browse_into(ent_ed)).grid(
            row=1, column=2, padx=4, pady=4)
        def confirm():
            e = ent_ext.get().strip()
            ed = ent_ed.get().strip()
            if not e or not ed:
                return
            if not e.startswith("."):
                e = f".{e}"
            e = e.lower()
            if tree.exists(e):
                tree.item(e, values=(e, ed))
            else:
                tree.insert("", "end", iid=e, values=(e, ed))
            d.destroy()
        ttk.Button(d, text="Save", command=confirm).grid(row=2, column=0, columnspan=3, pady=8)
        (ent_ext if not ext else ent_ed).focus_set()
        d.bind("<Return>", lambda ev: confirm())

    # ── Archive operations ──────────────────────────────────────────────

    def _new_archive(self):
        path = filedialog.asksaveasfilename(
            title="Create New Encrypted Archive",
            defaultextension=".enczip",
            filetypes=[("Encrypted ZIP", "*.enczip"), ("All", "*.*")]
        )
        if not path:
            return
        self.archive_path = path
        self._ask_credentials()

    def _open_archive(self):
        path = filedialog.askopenfilename(
            title="Open Encrypted Archive",
            filetypes=[("Encrypted ZIP", "*.enczip"), ("All", "*.*")]
        )
        if not path:
            return
        self.archive_path = path
        self._ask_credentials()

    def _load_archive(self):
        self.tree.delete(*self.tree.get_children())
        if not self.archive_path:
            return

        self.title(f"{self.TITLE}  \u2014  {os.path.basename(self.archive_path)}")
        self.lbl_archive.configure(text=self.archive_path)

        mode_str = "Raw Key" if self.raw_key else "Passphrase \u2192 PBKDF2"
        iv_str = f"IV: {self.raw_iv.hex()}" if self.raw_iv else "IV: auto (random)"
        self.lbl_crypto.configure(
            text=f"\U0001F510 AES-256-CBC + HMAC-SHA256  |  {mode_str}  |  {iv_str}"
        )

        if not os.path.isfile(self.archive_path):
            try:
                self._write_zip(zip_create_empty())
                self.lbl_stats.configure(text="Empty archive (new)")
            except Exception as exc:
                messagebox.showerror("Error", f"Cannot create archive:\n{exc}")
            return

        try:
            zip_bytes = self._read_zip()
            infos = zip_list(zip_bytes)
            total = 0
            for i in infos:
                total += i.file_size
                mod = datetime(*i.date_time).strftime("%Y-%m-%d %H:%M:%S") if i.date_time else ""
                self.tree.insert("", "end", iid=i.filename, values=(
                    i.filename, human_size(i.file_size),
                    human_size(i.compress_size), mod,
                ))
            self.lbl_stats.configure(text=f"{len(infos)} files  \u2022  {human_size(total)}")
        except CryptoError as exc:
            messagebox.showerror("Decryption Failed", str(exc))
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _selected_names(self) -> list[str]:
        return list(self.tree.selection())

    # ── New file ────────────────────────────────────────────────────────

    def _new_file(self):
        if not self.archive_path or not self._has_credentials():
            messagebox.showinfo("No archive", "Create or open an archive first.")
            return
        dlg = tk.Toplevel(self)
        dlg.title("New File")
        dlg.geometry("480x200")
        dlg.configure(bg="#1e1e2e")
        dlg.transient(self)
        dlg.grab_set()

        ttk.Label(dlg, text="File name:").grid(row=0, column=0, padx=12, pady=(16,4), sticky="w")
        ent_n = ttk.Entry(dlg, width=40)
        ent_n.grid(row=0, column=1, padx=12, pady=(16,4))
        ent_n.insert(0, "new_file.txt")
        ttk.Label(dlg, text="Folder:").grid(row=1, column=0, padx=12, pady=4, sticky="w")
        ent_f = ttk.Entry(dlg, width=40)
        ent_f.grid(row=1, column=1, padx=12, pady=4)
        var_open = tk.BooleanVar(value=True)
        ttk.Checkbutton(dlg, text="Open in editor", variable=var_open).grid(
            row=2, column=0, columnspan=2, pady=8)

        def on_create():
            name = ent_n.get().strip()
            folder = ent_f.get().strip().strip("/\\")
            if not name:
                return
            arcname = f"{folder}/{name}" if folder else name
            templates = {
                ".json": b"{\n  \n}\n", ".xml": b'<?xml version="1.0"?>\n<root/>\n',
                ".html": b"<!DOCTYPE html>\n<html>\n<body>\n\n</body>\n</html>\n",
                ".md": b"# \n", ".py": b"#!/usr/bin/env python3\n\n",
                ".sh": b"#!/usr/bin/env bash\n\n",
            }
            content = templates.get(os.path.splitext(name)[1].lower(), b"")
            try:
                zb = self._read_zip() if os.path.isfile(self.archive_path) else zip_create_empty()
                zb = zip_add_files(zb, {arcname: content})
                self._write_zip(zb)
                self._load_archive()
                dlg.destroy()
                if var_open.get() and self.tree.exists(arcname):
                    self.tree.selection_set(arcname)
                    self.tree.focus(arcname)
                    self._edit_selected()
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        ttk.Button(dlg, text="Create", command=on_create).grid(row=3, column=0, columnspan=2, pady=12)
        ent_n.focus_set()
        ent_n.select_range(0, ent_n.index("."))
        dlg.bind("<Return>", lambda e: on_create())

    # ── Add files ───────────────────────────────────────────────────────

    def _add_files(self):
        if not self.archive_path or not self._has_credentials():
            messagebox.showinfo("No archive", "Create or open an archive first.")
            return
        paths = filedialog.askopenfilenames(title="Add Files")
        if not paths:
            return
        try:
            zb = self._read_zip() if os.path.isfile(self.archive_path) else zip_create_empty()
            files = {}
            for p in paths:
                with open(p, "rb") as f:
                    files[os.path.basename(p)] = f.read()
            zb = zip_add_files(zb, files)
            self._write_zip(zb)
            self._load_archive()
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    # ── Extract ─────────────────────────────────────────────────────────

    def _extract_selected(self):
        names = self._selected_names()
        if not names:
            messagebox.showinfo("Nothing selected", "Select files to extract.")
            return
        dest = filedialog.askdirectory(title="Extract To")
        if not dest:
            return
        try:
            zb = self._read_zip()
            for n in names:
                zip_extract_file(zb, n, dest)
            messagebox.showinfo("Done", f"Extracted {len(names)} file(s) to:\n{dest}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _extract_all(self):
        if not self.archive_path:
            return
        dest = filedialog.askdirectory(title="Extract All To")
        if not dest:
            return
        try:
            zip_extract_all(self._read_zip(), dest)
            messagebox.showinfo("Done", f"Extracted to:\n{dest}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    # ── Delete ──────────────────────────────────────────────────────────

    def _delete_selected(self):
        names = self._selected_names()
        if not names:
            return
        if not messagebox.askyesno("Confirm", f"Delete {len(names)} file(s)?"):
            return
        try:
            zb = zip_delete_files(self._read_zip(), set(names))
            self._write_zip(zb)
            self._load_archive()
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    # ── Edit ────────────────────────────────────────────────────────────

    def _edit_selected(self):
        names = self._selected_names()
        if not names:
            messagebox.showinfo("Nothing selected", "Select a file to edit.")
            return
        name = names[0]
        try:
            zb = self._read_zip()
            data = zip_read_file(zb, name)
            tmp_file = os.path.join(self.tmp_dir, os.path.basename(name))
            with open(tmp_file, "wb") as f:
                f.write(data)
            orig_mtime = os.path.getmtime(tmp_file)

            editor = self.editors.get_editor(name).strip()
            if editor.endswith(".app"):
                cmd = ["open", "-a", editor, tmp_file]
            elif " " in editor and not editor.startswith('"'):
                if any(p.startswith("-") for p in editor.split()[1:]):
                    cmd = shlex.split(editor) + [tmp_file]
                else:
                    cmd = [editor, tmp_file]
            else:
                cmd = shlex.split(editor) + [tmp_file]
            subprocess.Popen(cmd)

            threading.Thread(target=self._watch, args=(name, tmp_file, orig_mtime),
                             daemon=True).start()
        except Exception as exc:
            messagebox.showerror("Edit error", str(exc))

    def _watch(self, arcname: str, tmp_file: str, orig_mtime: float):
        time.sleep(1)
        last = orig_mtime
        idle = 0
        while True:
            time.sleep(1)
            if not os.path.exists(tmp_file):
                break
            mt = os.path.getmtime(tmp_file)
            if mt != last:
                last = mt
                idle = 0
                time.sleep(0.5)
                self._reimport(arcname, tmp_file)
            else:
                idle += 1
            if idle > 1800:
                break

    def _reimport(self, arcname: str, tmp_file: str):
        try:
            with open(tmp_file, "rb") as f:
                new_data = f.read()
            zb = zip_add_files(self._read_zip(), {arcname: new_data})
            self._write_zip(zb)
            self.after(0, self._load_archive)
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Re-import error", str(exc)))

    # ── Cleanup ─────────────────────────────────────────────────────────

    def _on_close(self):
        try:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Encrypted ZIP Manager [AES-256-CBC]")
    parser.add_argument("--archive", "-a", help="Path to .enczip archive")
    parser.add_argument("--editor", "-e", help="Default editor path")
    args = parser.parse_args()
    app = EncryptedZipManager(archive_path=args.archive, editor_path=args.editor)
    app.mainloop()


if __name__ == "__main__":
    main()

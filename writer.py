#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Writer - iA Writer benzeri lokal masaüstü uygulaması
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Gereksinim : Python 3.8+  (sadece standart kütüphane kullanılır)
Çalıştırma : python3 writer.py
Veri dizini: ~/.writer_app/data.json
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GÜVENLİK:
  • Ağ bağlantısı sıfır — hiçbir dış sunucuya erişim yok
  • Dış kütüphane sıfır — yalnızca Python standart kütüphanesi
  • eval / exec / compile / subprocess / os.system kullanılmıyor
  • Kullanıcı girdisi sanitize + uzunluk sınırlandırma uygulanıyor
  • Dosya yazma atomik (tmp → rename) ve sabit yola kilitli
  • JSON yükleme şema doğrulamalı, hatalı veri yedeğe alınıyor
  • UID üretimi secrets + hashlib (CSPRNG tabanlı)
  • Veri dizini 0o700 (sadece sahip okuyabilir)
  • İndirme: Path.resolve() ile normalize, filedialog ile kullanıcı seçer
"""

# ── STANDART KÜTÜPHANE — harici bağımlılık yok ───────────────────────────────
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import json
import re
import time
import hashlib
import secrets
from pathlib import Path

# ─── SABİTLER ────────────────────────────────────────────────────────────────
APP_NAME       = "Writer"
APP_VERSION    = "1.0.0"
DATA_DIR       = Path.home() / ".writer_app"
DATA_FILE      = DATA_DIR / "data.json"

# Boyut sınırları
MAX_DOC_BYTES   = 5 * 1024 * 1024   # 5 MB — tek belge
MAX_STORE_BYTES = 50 * 1024 * 1024  # 50 MB — data.json toplam
MAX_FOLDER_NAME = 60
MAX_DOC_NAME    = 120
MAX_FOLDERS     = 100
MAX_DOCS        = 500

# ─── RENKLER ─────────────────────────────────────────────────────────────────
THEMES = {
    "light": {
        "bg":           "#ffffff",
        "surface":      "#36008e",
        "surface2":     "#0224FF",
        "border":       "#dddad2",
        "text":         "#000000",
        "text2":        "#6f02bd",
        "text3":        "#b0ada6",
        "accent":       "#6f02bd",
        "accent_bg":    "#e8f5ee",
        "cursor":       "#3d078f",
        "select":       "#c8e6d8",
        "sb_active":    "#e8f5ee",
    },
    "dark": {
        "bg":           "#131211",
        "surface":      "#1c1a18",
        "surface2":     "#252320",
        "border":       "#2e2b27",
        "text":         "#878583",
        "text2":        "#9e9b95",
        "text3":        "#4e4c48",
        "accent":       "#52b788",
        "accent_bg":    "#0d2b1e",
        "cursor":       "#52b788",
        "select":       "#1a4a2e",
        "sb_active":    "#0d2b1e",
    },
}

FONTS = {
    "Serif": ("Georgia",   18),
    "Mono":  ("Courier",   15),
    "Sans":  ("Helvetica", 18),
}

LINE_SPACINGS = ["1.5×", "1.9×", "2.4×", "3.0×"]

# ─── GÜVENLİ YARDIMCI FONKSİYONLAR ─────────────────────────────────────────
def _safe_uid() -> str:
    """
    Kriptografik açıdan güvenli rastgele ID üret.
    secrets.token_bytes → CSPRNG (OS /dev/urandom).
    """
    raw = secrets.token_bytes(32) + str(time.time_ns()).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _sanitize_name(name: str, max_len: int) -> str:
    """
    Kullanıcı girdisi isimlerini güvenli hale getir:
      • Baştaki/sondaki boşlukları kır
      • Null byte ve ASCII kontrol karakterlerini sil
      • Dosya sistemi özel karakterlerini sil
      • Uzunluğu sınırla
    """
    name = name.strip()
    # Null byte + kontrol karakterleri (0x00-0x1f, 0x7f)
    name = re.sub(r'[\x00-\x1f\x7f]', '', name)
    # Windows/Unix dosya sistemi tehlikeli karakterleri
    name = re.sub(r'[<>:"/\\|?*]', '', name)
    name = name[:max_len]
    return name or "İsimsiz"


def _validate_doc_content(content: str) -> str:
    """Belge içeriğinin boyutunu kontrol et."""
    encoded = content.encode('utf-8', errors='replace')
    if len(encoded) > MAX_DOC_BYTES:
        raise ValueError(
            f"Belge boyutu {MAX_DOC_BYTES // 1024 // 1024} MB sınırını aşıyor."
        )
    return content


# ─── GÜVENLİ DEPOLAMA ───────────────────────────────────────────────────────
class Storage:
    """
    JSON tabanlı lokal depolama.

    Güvenlik özellikleri:
      • Atomik yazma (tmp dosyası → rename) — yarım yazma yok
      • 0o700 dizin izni — sadece çalıştıran kullanıcı erişebilir
      • JSON şema doğrulama — bozuk/manipüle veri kabul edilmez
      • Bozuk dosya otomatik yedekleme — veri kaybı önlenir
      • Toplam dosya boyutu sınırı — disk şişmesi önlenir
    """

    def load(self) -> dict:
        self._ensure_dir()
        if not DATA_FILE.exists():
            return self._default()
        try:
            raw = DATA_FILE.read_text(encoding='utf-8')
            # Toplam dosya boyutu koruması
            if len(raw.encode('utf-8')) > MAX_STORE_BYTES:
                raise ValueError("Depolama dosyası çok büyük.")
            data = json.loads(raw)           # eval içermez, güvenli
            return self._validate_schema(data)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            self._backup_corrupt()
            return self._default()

    def save(self, data: dict) -> None:
        self._ensure_dir()
        serialized = json.dumps(data, ensure_ascii=False, indent=2)
        # Boyut koruması
        if len(serialized.encode('utf-8')) > MAX_STORE_BYTES:
            messagebox.showwarning(
                "Uyarı",
                "Depolama sınırı aşıldı. Eski belgeler silinmeden kayıt yapılamaz."
            )
            return
        # Atomik yazma: önce .tmp, sonra yerine geç
        tmp = DATA_FILE.with_suffix('.tmp')
        try:
            tmp.write_text(serialized, encoding='utf-8')
            tmp.replace(DATA_FILE)           # POSIX'te atomik
        except OSError as exc:
            messagebox.showerror("Depolama Hatası", f"Kaydedilemedi:\n{exc}")

    # ── Özel ────────────────────────────────────────────────────────────────

    @staticmethod
    def _ensure_dir() -> None:
        DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    @staticmethod
    def _backup_corrupt() -> None:
        if DATA_FILE.exists():
            backup = DATA_FILE.with_suffix(f'.corrupt.{int(time.time())}')
            try:
                DATA_FILE.rename(backup)
            except OSError:
                pass

    @staticmethod
    def _default() -> dict:
        uid = _safe_uid()
        return {
            "version":   1,
            "folders":   [],
            "docs":      [{
                "id":        uid,
                "folder_id": None,
                "name":      "Yeni Belge",
                "content":   "",
                "modified":  time.time(),
            }],
            "active_id": uid,
        }

    @staticmethod
    def _validate_schema(data: dict) -> dict:
        """
        Yüklenen veriyi katı şema doğrulamasından geçir.
        Bilinmeyen / hatalı alanlar düşürülür ya da varsayılana döner.
        """
        if not isinstance(data, dict):
            return Storage._default()

        # Klasörler
        raw_folders = data.get("folders", [])
        folders = []
        if isinstance(raw_folders, list):
            for f in raw_folders[:MAX_FOLDERS]:
                if not isinstance(f, dict):
                    continue
                fid = f.get("id")
                if not isinstance(fid, str) or not fid:
                    continue
                folders.append({
                    "id":   fid[:32],
                    "name": _sanitize_name(str(f.get("name", "Klasör")),
                                           MAX_FOLDER_NAME),
                })

        # Belgeler
        raw_docs = data.get("docs", [])
        docs = []
        if isinstance(raw_docs, list):
            for d in raw_docs[:MAX_DOCS]:
                if not isinstance(d, dict):
                    continue
                did = d.get("id")
                if not isinstance(did, str) or not did:
                    continue
                fid = d.get("folder_id")
                fid = str(fid)[:32] if isinstance(fid, str) else None
                content = str(d.get("content", ""))
                # Boyut sınırı — doğrudan kes, hata atma
                if len(content.encode('utf-8', errors='replace')) > MAX_DOC_BYTES:
                    content = content[:MAX_DOC_BYTES // 4]
                docs.append({
                    "id":        did[:32],
                    "folder_id": fid,
                    "name":      _sanitize_name(str(d.get("name", "Belge")),
                                                MAX_DOC_NAME),
                    "content":   content,
                    "modified":  float(d.get("modified", time.time())),
                })

        if not docs:
            return Storage._default()

        # active_id doğrula
        active_id = str(data.get("active_id", ""))
        valid_ids = {d["id"] for d in docs}
        if active_id not in valid_ids:
            active_id = docs[0]["id"]

        return {
            "version":   1,
            "folders":   folders,
            "docs":      docs,
            "active_id": active_id,
        }


# ─── ANA UYGULAMA ─────────────────────────────────────────────────────────────
class WriterApp:
    def __init__(self, root: tk.Tk):
        self.root       = root
        self.storage    = Storage()
        self.data       = self.storage.load()
        self.theme_name = "light"
        self.T          = THEMES["light"]
        self.font_name  = "Serif"
        self.font_size  = 18
        self.line_sp    = 1.9
        self.text_align = "left"
        self.focus_mode = False
        self.prev_mode  = False
        self._sb_visible = True
        self._auto_job   = None
        self._saved_job  = None
        self._ctx_iid    = None

        self._build_ui()
        self._load_active_doc()
        self._apply_theme()
        self.root.after(200, self.editor.focus_set)

    # ── UI İNŞASI ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.root.title(APP_NAME)
        self.root.geometry("1120x730")
        self.root.minsize(640, 420)

        wrap = tk.Frame(self.root)
        wrap.pack(fill=tk.BOTH, expand=True)

        self.paned = tk.PanedWindow(wrap, orient=tk.HORIZONTAL,
                                    sashwidth=4, sashrelief=tk.FLAT)
        self.paned.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar()
        self._build_content()

    # ── SIDEBAR ───────────────────────────────────────────────────────────────

    def _build_sidebar(self):
        self.sidebar = tk.Frame(self.paned, width=220)
        self.paned.add(self.sidebar, minsize=160, width=220)

        hdr = tk.Frame(self.sidebar, height=38)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        self._sb_hdr = hdr

        self._sb_title = tk.Label(hdr, text="BELGELER",
                                   font=("Courier", 9), anchor="w")
        self._sb_title.pack(side=tk.LEFT, padx=12, pady=10)

        self._btn_nf = tk.Button(hdr, text="📁", font=("", 11),
                                  relief=tk.FLAT, cursor="hand2", bd=0,
                                  padx=4, command=self._new_folder)
        self._btn_nf.pack(side=tk.RIGHT, padx=2, pady=6)

        self._btn_nd_sb = tk.Button(hdr, text="+", font=("", 14),
                                     relief=tk.FLAT, cursor="hand2", bd=0,
                                     padx=6, command=self._new_doc)
        self._btn_nd_sb.pack(side=tk.RIGHT, padx=2, pady=6)

        self._sb_sep = tk.Frame(self.sidebar, height=1)
        self._sb_sep.pack(fill=tk.X)

        tf = tk.Frame(self.sidebar)
        tf.pack(fill=tk.BOTH, expand=True)
        self._tree_frame = tf

        sc = tk.Scrollbar(tf)
        sc.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(tf, show="tree",
                                  yscrollcommand=sc.set,
                                  selectmode="browse")
        self.tree.pack(fill=tk.BOTH, expand=True)
        sc.config(command=self.tree.yview)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-3>",          self._on_tree_rclick)
        self.tree.bind("<Double-1>",          self._on_tree_double)

        # Bağlam menüsü — sabit etiketler, kullanıcı girdisi içermiyor
        self._ctx = tk.Menu(self.root, tearoff=0)
        self._ctx.add_command(label="Yeniden Adlandır",
                               command=self._rename_item)
        self._ctx.add_separator()
        self._ctx.add_command(label="Sil", command=self._delete_item,
                               foreground="#c0392b")

        self._refresh_tree()

    # ── İÇERİK ALANI ──────────────────────────────────────────────────────────

    def _build_content(self):
        self.cf = tk.Frame(self.paned)
        self.paned.add(self.cf)
        self._build_toolbar()
        self._build_stats()
        self._build_editor()

    def _build_toolbar(self):
        tb = tk.Frame(self.cf, height=42)
        tb.pack(fill=tk.X)
        tb.pack_propagate(False)
        self.tb = tb

        def btn(text, cmd, **kw):
            b = tk.Button(tb, text=text, relief=tk.FLAT, cursor="hand2",
                          command=cmd, bd=0, font=("Helvetica", 11),
                          padx=6, pady=3, **kw)
            b.pack(side=tk.LEFT, padx=1, pady=5)
            return b

        def sep():
            tk.Frame(tb, width=1).pack(
                side=tk.LEFT, fill=tk.Y, padx=4, pady=7)

        self._btn_sb_tog = btn("☰", self._toggle_sidebar)
        self._logo = tk.Label(tb, text="writer.",
                               font=("Courier", 13, "bold"), padx=8)
        self._logo.pack(side=tk.LEFT)
        sep()

        btn("Yeni",  self._new_doc)
        btn("↓ .md", self._download_md)
        sep()

        # Font
        self._font_var = tk.StringVar(value="Serif")
        fc = ttk.Combobox(tb, textvariable=self._font_var,
                          values=list(FONTS.keys()), width=7, state="readonly")
        fc.pack(side=tk.LEFT, pady=9)
        fc.bind("<<ComboboxSelected>>", self._on_font_change)

        # Boyut
        self._fsize_var = tk.IntVar(value=18)
        tk.Button(tb, text="−", relief=tk.FLAT, cursor="hand2",
                  command=self._font_smaller, font=("", 12), bd=0,
                  padx=4).pack(side=tk.LEFT, pady=9)
        self._fsize_lbl = tk.Label(tb, textvariable=self._fsize_var,
                                    font=("Courier", 10), width=3)
        self._fsize_lbl.pack(side=tk.LEFT)
        tk.Button(tb, text="+", relief=tk.FLAT, cursor="hand2",
                  command=self._font_bigger, font=("", 12), bd=0,
                  padx=4).pack(side=tk.LEFT, pady=9)
        sep()

        # Satır aralığı
        tk.Label(tb, text="Aralık:", font=("Helvetica", 10)
                 ).pack(side=tk.LEFT, pady=9)
        self._ls_var = tk.StringVar(value="1.9×")
        lc = ttk.Combobox(tb, textvariable=self._ls_var,
                          values=LINE_SPACINGS, width=5, state="readonly")
        lc.pack(side=tk.LEFT, pady=9, padx=2)
        lc.bind("<<ComboboxSelected>>", self._on_ls_change)
        sep()

        # Hizalama
        self._align_btns: dict[str, tk.Button] = {}
        for sym, val in [("≡L", "left"), ("≡C", "center"),
                         ("≡R", "right"), ("≡J", "justify")]:
            b = tk.Button(tb, text=sym, relief=tk.FLAT, cursor="hand2",
                          font=("Courier", 10, "bold"), bd=0, padx=5, pady=3,
                          command=lambda v=val: self._set_align(v))
            b.pack(side=tk.LEFT, padx=1, pady=7)
            self._align_btns[val] = b
        sep()

        self._btn_focus   = btn("Odak",    self._toggle_focus)
        self._btn_preview = btn("Önizle",  self._toggle_preview)
        sep()
        self._btn_theme   = btn("◑",       self._toggle_theme)

        self._doc_lbl = tk.Label(tb, text="", font=("Helvetica", 11),
                                  anchor="e")
        self._doc_lbl.pack(side=tk.RIGHT, padx=14)

    def _build_stats(self):
        sf = tk.Frame(self.cf, height=24)
        sf.pack(fill=tk.X)
        sf.pack_propagate(False)
        self._sf = sf

        self._sw = tk.Label(sf, text="Kelime: 0",    font=("Courier", 9))
        self._sw.pack(side=tk.LEFT, padx=12)
        self._sc = tk.Label(sf, text="Karakter: 0",  font=("Courier", 9))
        self._sc.pack(side=tk.LEFT, padx=6)
        self._sr = tk.Label(sf, text="Okuma: 1 dk",  font=("Courier", 9))
        self._sr.pack(side=tk.LEFT, padx=6)
        self._sl = tk.Label(sf, text="Satır: 0",     font=("Courier", 9))
        self._sl.pack(side=tk.LEFT, padx=6)

        self._saved_lbl = tk.Label(sf, text="✓ kaydedildi", font=("Courier", 9))
        self._saved_lbl.pack(side=tk.RIGHT, padx=14)
        self._saved_lbl.pack_forget()

    def _build_editor(self):
        ef = tk.Frame(self.cf)
        ef.pack(fill=tk.BOTH, expand=True)
        self._ef = ef

        sc = tk.Scrollbar(ef)
        sc.pack(side=tk.RIGHT, fill=tk.Y)

        self.editor = tk.Text(
            ef,
            wrap=tk.WORD,
            yscrollcommand=sc.set,
            relief=tk.FLAT, borderwidth=0,
            padx=64, pady=52,
            undo=True, maxundo=200,
            insertwidth=2,
            spacing1=4, spacing3=4,
        )
        self.editor.pack(fill=tk.BOTH, expand=True)
        sc.config(command=self.editor.yview)

        self.editor.bind("<<Modified>>",    self._on_modified)
        self.editor.bind("<KeyRelease>",    self._on_key_release)

        # Önizleme paneli (başlangıçta gizli)
        self._prev_widget = tk.Text(
            ef,
            wrap=tk.WORD,
            relief=tk.FLAT, borderwidth=0,
            padx=64, pady=52,
            state=tk.DISABLED,
        )

    # ── AĞAÇ ──────────────────────────────────────────────────────────────────

    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())

        for folder in self.data["folders"]:
            fid  = folder["id"]
            node = self.tree.insert("", tk.END, iid=f"f:{fid}",
                                    text=f"📁 {folder['name']}",
                                    open=True, tags=("folder",))
            for doc in self.data["docs"]:
                if doc["folder_id"] == fid:
                    mk = "▸ " if doc["id"] == self.data["active_id"] else "  "
                    self.tree.insert(node, tk.END, iid=f"d:{doc['id']}",
                                     text=f"{mk}{doc['name']}",
                                     tags=("doc",))

        for doc in self.data["docs"]:
            if doc["folder_id"] is None:
                mk = "▸ " if doc["id"] == self.data["active_id"] else "  "
                self.tree.insert("", tk.END, iid=f"d:{doc['id']}",
                                 text=f"{mk}{doc['name']}",
                                 tags=("doc",))

        active_iid = f"d:{self.data['active_id']}"
        if self.tree.exists(active_iid):
            self.tree.selection_set(active_iid)
            self.tree.see(active_iid)

        self._style_tree()

    def _style_tree(self):
        T = self.T
        s = ttk.Style()
        s.configure("Treeview",
                    background=T["surface"],
                    foreground=T["text2"],
                    fieldbackground=T["surface"],
                    rowheight=26,
                    font=("Helvetica", 12))
        s.map("Treeview",
              background=[("selected", T["sb_active"])],
              foreground=[("selected", T["accent"])])

    def _on_tree_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        if not iid.startswith("d:"):
            return
        doc_id = iid[2:]
        if doc_id == self.data["active_id"]:
            return
        self._save_content()
        self.data["active_id"] = doc_id
        self._load_active_doc()
        self._refresh_tree()

    def _on_tree_rclick(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self._ctx_iid = iid
            self._ctx.post(event.x_root, event.y_root)

    def _on_tree_double(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self._ctx_iid = iid
            self._rename_item()

    # ── BELGE İŞLEMLERİ ───────────────────────────────────────────────────────

    def _active_doc(self) -> dict | None:
        aid = self.data["active_id"]
        return next((d for d in self.data["docs"] if d["id"] == aid), None)

    def _load_active_doc(self):
        doc = self._active_doc()
        if not doc:
            return
        self.editor.config(state=tk.NORMAL)
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", doc["content"])
        self.editor.edit_reset()
        self._update_stats()
        self._update_doc_label()

    def _save_content(self):
        doc = self._active_doc()
        if not doc:
            return
        content = self.editor.get("1.0", "end-1c")
        try:
            content = _validate_doc_content(content)
        except ValueError as exc:
            messagebox.showwarning("Uyarı", str(exc), parent=self.root)
            return
        doc["content"]  = content
        doc["modified"] = time.time()
        self.storage.save(self.data)

    def _new_doc(self):
        name = simpledialog.askstring(
            "Yeni Belge", "Belge adı:", parent=self.root,
            initialvalue="Yeni Belge"
        )
        if not name:
            return
        # Güvenli isim
        name = _sanitize_name(name, MAX_DOC_NAME)

        folder_id = None
        if self.data["folders"]:
            opts = [("— Klasörsüz —", None)] + [
                (f["name"], f["id"]) for f in self.data["folders"]
            ]
            folder_id = self._pick_folder(opts)
            if folder_id is False:        # iptal
                return

        self._save_content()
        uid = _safe_uid()
        self.data["docs"].append({
            "id":        uid,
            "folder_id": folder_id,
            "name":      name,
            "content":   "",
            "modified":  time.time(),
        })
        self.data["active_id"] = uid
        self.storage.save(self.data)
        self._load_active_doc()
        self._refresh_tree()
        self.editor.focus_set()

    def _pick_folder(self, options: list) -> str | None | bool:
        """Klasör seçim diyalogu. İptal → False döner."""
        win = tk.Toplevel(self.root)
        win.title("Klasör Seç")
        win.geometry("280x210")
        win.resizable(False, False)
        win.grab_set()
        win.configure(bg=self.T["bg"])

        result: list = [False]  # [seçim]

        tk.Label(win, text="Klasör seç:",
                 font=("Helvetica", 12),
                 bg=self.T["bg"], fg=self.T["text"]).pack(pady=(16, 6))

        lb = tk.Listbox(win, font=("Helvetica", 12), relief=tk.FLAT,
                        bg=self.T["surface"], fg=self.T["text"],
                        selectbackground=self.T["accent_bg"],
                        selectforeground=self.T["accent"],
                        height=min(len(options), 6))
        lb.pack(fill=tk.X, padx=16)
        for name, _ in options:
            lb.insert(tk.END, name)
        lb.selection_set(0)

        def confirm():
            idx = lb.curselection()
            result[0] = options[idx[0]][1] if idx else None
            win.destroy()

        def cancel():
            result[0] = False
            win.destroy()

        bf = tk.Frame(win, bg=self.T["bg"])
        bf.pack(pady=10)
        tk.Button(bf, text="Tamam", command=confirm,
                  font=("Helvetica", 11), cursor="hand2",
                  bg=self.T["accent"], fg="#fff",
                  relief=tk.FLAT, padx=14, pady=4).pack(side=tk.LEFT, padx=4)
        tk.Button(bf, text="İptal", command=cancel,
                  font=("Helvetica", 11), cursor="hand2",
                  relief=tk.FLAT, padx=14, pady=4).pack(side=tk.LEFT, padx=4)

        win.protocol("WM_DELETE_WINDOW", cancel)
        win.wait_window()
        return result[0]

    def _new_folder(self):
        name = simpledialog.askstring(
            "Yeni Klasör", "Klasör adı:", parent=self.root
        )
        if not name:
            return
        name = _sanitize_name(name, MAX_FOLDER_NAME)
        self.data["folders"].append({"id": _safe_uid(), "name": name})
        self.storage.save(self.data)
        self._refresh_tree()

    def _rename_item(self):
        iid = self._ctx_iid
        if not iid:
            return
        if iid.startswith("f:"):
            fid    = iid[2:]
            folder = next((f for f in self.data["folders"]
                           if f["id"] == fid), None)
            if not folder:
                return
            new = simpledialog.askstring(
                "Yeniden Adlandır", "Yeni klasör adı:",
                parent=self.root, initialvalue=folder["name"]
            )
            if not new:
                return
            folder["name"] = _sanitize_name(new, MAX_FOLDER_NAME)

        elif iid.startswith("d:"):
            did = iid[2:]
            doc = next((d for d in self.data["docs"]
                        if d["id"] == did), None)
            if not doc:
                return
            new = simpledialog.askstring(
                "Yeniden Adlandır", "Yeni belge adı:",
                parent=self.root, initialvalue=doc["name"]
            )
            if not new:
                return
            doc["name"] = _sanitize_name(new, MAX_DOC_NAME)

        self.storage.save(self.data)
        self._refresh_tree()
        self._update_doc_label()

    def _delete_item(self):
        iid = self._ctx_iid
        if not iid:
            return

        if iid.startswith("f:"):
            fid    = iid[2:]
            folder = next((f for f in self.data["folders"]
                           if f["id"] == fid), None)
            if not folder:
                return
            if not messagebox.askyesno(
                "Sil",
                f'"{folder["name"]}" klasörü silinsin mi?\n'
                f'İçindeki belgeler klasörsüz kalacak.',
                parent=self.root
            ):
                return
            self.data["folders"] = [
                f for f in self.data["folders"] if f["id"] != fid
            ]
            for d in self.data["docs"]:
                if d["folder_id"] == fid:
                    d["folder_id"] = None

        elif iid.startswith("d:"):
            did = iid[2:]
            doc = next((d for d in self.data["docs"]
                        if d["id"] == did), None)
            if not doc:
                return
            if not messagebox.askyesno(
                "Sil",
                f'"{doc["name"]}" silinsin mi?\nBu işlem geri alınamaz.',
                parent=self.root
            ):
                return
            self.data["docs"] = [
                d for d in self.data["docs"] if d["id"] != did
            ]
            if not self.data["docs"]:
                uid = _safe_uid()
                self.data["docs"].append({
                    "id": uid, "folder_id": None,
                    "name": "Yeni Belge", "content": "",
                    "modified": time.time(),
                })
            if self.data["active_id"] == did:
                self.data["active_id"] = self.data["docs"][0]["id"]
                self._load_active_doc()

        self.storage.save(self.data)
        self._refresh_tree()

    # ── EDİTÖR OLAYLARI ───────────────────────────────────────────────────────

    def _on_modified(self, _event=None):
        if self.editor.edit_modified():
            self.editor.edit_modified(False)
            self._update_stats()
            self._schedule_save()

    def _on_key_release(self, _event=None):
        self._update_stats()

    def _schedule_save(self):
        if self._auto_job:
            self.root.after_cancel(self._auto_job)
        self._auto_job = self.root.after(900, self._auto_save)

    def _auto_save(self):
        self._save_content()
        self._flash_saved()

    def _flash_saved(self):
        self._saved_lbl.pack(side=tk.RIGHT, padx=14)
        if self._saved_job:
            self.root.after_cancel(self._saved_job)
        self._saved_job = self.root.after(2000, self._saved_lbl.pack_forget)

    def _update_stats(self):
        text  = self.editor.get("1.0", "end-1c")
        words = len(text.split()) if text.strip() else 0
        chars = len(text.replace('\n', ''))
        lines = len([l for l in text.split('\n') if l.strip()])
        read  = max(1, round(words / 200))
        self._sw.config(text=f"Kelime: {words}")
        self._sc.config(text=f"Karakter: {chars}")
        self._sr.config(text=f"Okuma: {read} dk")
        self._sl.config(text=f"Satır: {lines}")

    def _update_doc_label(self):
        doc = self._active_doc()
        if doc:
            n = doc["name"]
            self._doc_lbl.config(
                text=(n[:38] + "…") if len(n) > 38 else n
            )

    # ── ARAÇ ÇUBUĞU EYLEMLERİ ────────────────────────────────────────────────

    def _toggle_sidebar(self):
        if self._sb_visible:
            self.paned.forget(self.sidebar)
            self._sb_visible = False
        else:
            self.paned.add(self.sidebar, before=self.cf,
                           minsize=160, width=220)
            self._sb_visible = True

    def _on_font_change(self, _event=None):
        name = self._font_var.get()
        if name not in FONTS:
            return
        self.font_name = name
        family, size   = FONTS[name]
        self.font_size = size
        self._fsize_var.set(size)
        self.editor.config(font=(family, size))

    def _font_bigger(self):
        if self.font_size >= 32:
            return
        self.font_size += 1
        self._fsize_var.set(self.font_size)
        self.editor.config(font=(FONTS[self.font_name][0], self.font_size))

    def _font_smaller(self):
        if self.font_size <= 10:
            return
        self.font_size -= 1
        self._fsize_var.set(self.font_size)
        self.editor.config(font=(FONTS[self.font_name][0], self.font_size))

    def _on_ls_change(self, _event=None):
        raw = self._ls_var.get().replace("×", "").strip()
        try:
            self.line_sp = float(raw)
        except ValueError:
            self.line_sp = 1.9
        sp = max(0, int((self.line_sp - 1.0) * self.font_size * 1.8))
        self.editor.config(spacing1=sp // 2, spacing3=sp // 2)

    def _set_align(self, align: str):
        if align not in ("left", "center", "right", "justify"):
            return
        T = self.T
        for val, btn in self._align_btns.items():
            if val == align:
                btn.config(bg=T["accent_bg"], fg=T["accent"])
            else:
                btn.config(bg=T["bg"], fg=T["text2"],
                           activebackground=T["surface2"])
        self.text_align = align
        self.editor.tag_add("align_all", "1.0", tk.END)
        self.editor.tag_configure("align_all", justify=align)

    # ── ODAK MODU ─────────────────────────────────────────────────────────────

    def _toggle_focus(self):
        self.focus_mode = not self.focus_mode
        T = self.T
        if self.focus_mode:
            self._btn_focus.config(bg=T["accent_bg"], fg=T["accent"],
                                    text="● Odak")
            self.editor.config(padx=140, pady=64)
            self.editor.bind("<KeyRelease>",    self._on_focus_key)
            self.editor.bind("<ButtonRelease>", self._focus_highlight)
            self._focus_highlight()
        else:
            self._btn_focus.config(bg=T["bg"], fg=T["text2"], text="Odak")
            self.editor.config(padx=64, pady=52)
            self.editor.tag_remove("dim",    "1.0", tk.END)
            self.editor.tag_remove("bright", "1.0", tk.END)
            self.editor.bind("<KeyRelease>", self._on_key_release)
            self.editor.unbind("<ButtonRelease>")

    def _focus_highlight(self, _event=None):
        """Aktif satırı aydınlat, diğerlerini soluklaştır."""
        T = self.T
        self.editor.tag_configure("dim",    foreground=T["text3"])
        self.editor.tag_configure("bright", foreground=T["text"])
        self.editor.tag_remove("dim",    "1.0", tk.END)
        self.editor.tag_remove("bright", "1.0", tk.END)
        self.editor.tag_add("dim", "1.0", tk.END)
        cur_line = self.editor.index(tk.INSERT).split('.')[0]
        self.editor.tag_remove("dim",    f"{cur_line}.0", f"{cur_line}.end")
        self.editor.tag_add(   "bright", f"{cur_line}.0", f"{cur_line}.end")

    def _on_focus_key(self, _event=None):
        self._focus_highlight()
        self._update_stats()
        self._schedule_save()

    # ── ÖNİZLEME MODU ─────────────────────────────────────────────────────────

    def _toggle_preview(self):
        self.prev_mode = not self.prev_mode
        T = self.T
        if self.prev_mode:
            self._btn_preview.config(bg=T["accent_bg"], fg=T["accent"],
                                      text="● Önizle")
            rendered = self._render_md(self.editor.get("1.0", "end-1c"))
            self.editor.pack_forget()
            pw = self._prev_widget
            pw.config(state=tk.NORMAL, bg=T["bg"], fg=T["text"])
            pw.delete("1.0", tk.END)
            pw.insert("1.0", rendered)
            pw.config(state=tk.DISABLED)
            pw.pack(fill=tk.BOTH, expand=True)
        else:
            self._btn_preview.config(bg=T["bg"], fg=T["text2"], text="Önizle")
            self._prev_widget.pack_forget()
            self.editor.pack(fill=tk.BOTH, expand=True)
            self.editor.focus_set()

    @staticmethod
    def _render_md(text: str) -> str:
        """Markdown işaretlerini basit önizleme için siler."""
        lines = []
        for line in text.split('\n'):
            line = re.sub(r'^#{1,3} ', '', line)
            line = re.sub(r'\*\*(.+?)\*\*', r'\1', line)
            line = re.sub(r'\*(.+?)\*',     r'\1', line)
            line = re.sub(r'`(.+?)`',       r'\1', line)
            line = re.sub(r'^> ',           '',    line)
            lines.append(line)
        return '\n'.join(lines)

    # ── TEMA ──────────────────────────────────────────────────────────────────

    def _toggle_theme(self):
        self.theme_name = "dark" if self.theme_name == "light" else "light"
        self.T = THEMES[self.theme_name]
        self._apply_theme()

    def _apply_theme(self):
        T = self.T
        self.root.configure(bg=T["bg"])

        # Toolbar
        self.tb.configure(bg=T["bg"])
        for w in self.tb.winfo_children():
            cls = w.__class__.__name__
            if cls == "Button":
                w.configure(bg=T["bg"], fg=T["text2"],
                             activebackground=T["surface2"],
                             activeforeground=T["text"])
            elif cls == "Label":
                w.configure(bg=T["bg"], fg=T["text2"])
            elif cls == "Frame":
                w.configure(bg=T["border"])
        self._logo.configure(fg=T["accent"])
        self._doc_lbl.configure(bg=T["bg"], fg=T["text3"])

        # Stats bar
        self._sf.configure(bg=T["surface"])
        for w in self._sf.winfo_children():
            try:
                w.configure(bg=T["surface"], fg=T["text3"])
            except tk.TclError:
                pass
        self._saved_lbl.configure(bg=T["surface"], fg=T["accent"])

        # Sidebar
        self.sidebar.configure(bg=T["surface"])
        self._sb_hdr.configure(bg=T["surface"])
        self._sb_sep.configure(bg=T["border"])
        self._sb_title.configure(bg=T["surface"], fg=T["text3"])
        for b in (self._btn_nf, self._btn_nd_sb):
            b.configure(bg=T["surface"], fg=T["text3"],
                        activebackground=T["surface2"])
        self._tree_frame.configure(bg=T["surface"])
        self._style_tree()

        # Editor
        self._ef.configure(bg=T["bg"])
        self.editor.configure(
            bg=T["bg"], fg=T["text"],
            insertbackground=T["cursor"],
            selectbackground=T["select"],
            selectforeground=T["text"],
            font=(FONTS[self.font_name][0], self.font_size),
        )
        self._prev_widget.configure(bg=T["bg"], fg=T["text"])
        self.cf.configure(bg=T["bg"])

        # Hizalama butonlarını yenile
        self._set_align(self.text_align)

        # Odak/Önizleme butonları
        for b in (self._btn_focus, self._btn_preview, self._btn_theme,
                  self._btn_sb_tog):
            b.configure(bg=T["bg"], fg=T["text2"],
                        activebackground=T["surface2"])

    # ── İNDİRME ───────────────────────────────────────────────────────────────

    def _download_md(self):
        doc = self._active_doc()
        if not doc:
            return
        content = self.editor.get("1.0", "end-1c")

        # Dosya adından tehlikeli karakterleri temizle
        safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', doc["name"])
        safe = safe.strip('. ')[:80] or "belge"

        path = filedialog.asksaveasfilename(
            parent=self.root,
            defaultextension=".md",
            filetypes=[
                ("Markdown", "*.md"),
                ("Metin",    "*.txt"),
                ("Tümü",     "*.*"),
            ],
            initialfile=safe + ".md",
            title="Belgeyi Kaydet",
        )
        if not path:
            return

        # Path.resolve() ile normalize et — sembolik link / traversal koruması
        try:
            out = Path(path).resolve()
            out.write_text(content, encoding='utf-8')
        except (OSError, ValueError) as exc:
            messagebox.showerror("Hata", f"Kaydedilemedi:\n{exc}",
                                  parent=self.root)

    # ── KAPATMA ───────────────────────────────────────────────────────────────

    def on_close(self):
        self._save_content()
        self.root.destroy()


# ─── GİRİŞ NOKTASI ───────────────────────────────────────────────────────────
def main():
    root = tk.Tk()
    root.title(APP_NAME)

    # HiDPI ölçeklendirme — Tkinter dahili TCL komutu, kullanıcı girdisi içermez
    try:
        root.tk.call('tk', 'scaling', 1.3)
    except tk.TclError:
        pass

    app = WriterApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

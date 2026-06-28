#!/usr/bin/env python3
"""
Procvičování skládání hlaviček síťových protokolů.
Spustit: python app.py
"""

import tkinter as tk
import random

# ── Data: protokoly → seznam (název_pole, počet_bitů) ─────────────────────────
PROTOCOLS = {
    "IPv4": [
        ("Verze", 4), ("IHL", 4), ("Typ služby (TOS/DSCP)", 8), ("Total Length", 16),
        ("Identifikátor", 16), ("Příznaky", 3), ("Posun fragmentu", 13),
        ("TTL", 8), ("Protokol", 8), ("Kontrolní součet záhlaví", 16),
        ("Zdrojová IP adresa", 32), ("Cílová IP adresa", 32), ("Options", 32),
    ],
    "TCP": [
        ("Zdrojový port", 16), ("Cílový port", 16),
        ("Sequence Number", 32), ("Acknowledgment Number", 32),
        ("Data Offset", 4), ("Rezervováno", 6),
        ("Řídící bity (URG/ACK/PSH/RST/SYN/FIN)", 6), ("Window", 16),
        ("Checksum", 16), ("Urgentní ukazatel", 16), ("Options + výplň", 32),
    ],
    "UDP": [
        ("Zdrojový port", 16), ("Cílový port", 16),
        ("Délka", 16), ("Kontrolní součet", 16),
    ],
    "OSPF": [
        ("Verze OSPF", 8), ("Typ paketu", 8), ("Délka paketu", 16),
        ("Router ID", 32), ("Area ID", 32),
        ("Checksum", 16), ("Autentizace", 80),   # AuType(16) + Auth data(64)
    ],
    "Ethernet": [
        ("Preambule + SFD", 64), ("Cílová MAC", 48), ("Zdrojová MAC", 48),
        ("Typ/Délka", 16), ("Data (Payload)", 32), ("FCS", 32),
    ],
    "MPLS": [
        ("Hodnota návěští", 20), ("EXP / QoS", 3),
        ("S – Bottom of Stack", 1), ("TTL", 8),
    ],
    "RADIUS": [
        ("Code", 8), ("Identifier", 8), ("Length", 16), ("Authenticator", 128),
    ],
    "IPv6": [
        ("Verze", 4), ("Třída provozu", 8), ("Označení toku", 20),
        ("Délka dat", 16), ("Další záhlaví", 8), ("Limit skoků", 8),
        ("Zdrojová adresa", 128),
        ("Cílová adresa", 128),
    ],
    "PPPoE": [
        # RFC 2516 – fixní záhlaví (6 B = 48 b)
        ("Verze", 4), ("Typ", 4), ("Kód", 8), ("Session ID", 16),
        ("Délka", 16),
    ],
    "GRE": [
        # RFC 2784 – povinné záhlaví (4 B = 32 b)
        ("Příznak kont. součtu", 1), ("Rezervováno GRE", 12), ("Verze GRE", 3),
        ("Typ protokolu", 16),
    ],
    "IPSec AH": [
        # RFC 4302 – pevná část záhlaví
        ("Další záhlaví", 8), ("Délka záhlaví", 8), ("Rezervováno", 16),
        ("Security Parameters Index (SPI)", 32),
        ("Sekvenční číslo", 32),
        ("Integrity Check Value (ICV)", 96),   # HMAC-SHA-1 → 96 b
    ],
    "IPSec ESP": [
        # RFC 4303 – záhlaví + trailer (bez proměnné části)
        ("Security Parameters Index (SPI)", 32),
        ("Sekvenční číslo", 32),
        ("Inicializační vektor (IV)", 64),       # AES-CBC příklad
        ("Šifrovaná data (Payload)", 32),
        ("Výplň (Padding)", 16), ("Délka výplně", 8), ("Další záhlaví", 8),
        ("Integrity Check Value (ICV)", 96),
    ],
}

UNDEFINED = []  # všechny protokoly mají definovaná pole

# ── Konstanty vzhledu ──────────────────────────────────────────────────────────
CW        = 640    # šířka schématu v px
ROW_H     = 44     # výška jednoho řádku schématu
RULER_H   = 20     # výška číselníku bitů nahoře
BPR       = 32     # bitů na jeden řádek
TW, TH    = 80, 56 # rozměry dlaždice v zásobníku
TRAY_H    = TH + 26

C_BG      = "#f0f2f8"
C_EMPTY   = "#dde4f0"  # prázdné pole
C_ETXT    = "#8899bb"
C_SNAP    = "#4caf50"  # správně umístěné pole (zelená)
C_STXT    = "#ffffff"
C_TILE    = "#5c7cfa"  # dlaždice v zásobníku
C_TTXT    = "#ffffff"
C_DONE    = "#b8c0d4"  # použitá dlaždice
C_DTXT    = "#8891aa"
C_HOVER   = "#fff9c4"  # zvýrazněné cílové pole při tažení
C_PLACED  = "#c8d8f8"  # pole s vloženou (dosud neohodnocenou) dlaždicí
C_PTXT    = "#223355"  # text ve vloženém poli
C_WRONG   = "#ffcdd2"  # špatně umístěná dlaždice (po "Ukázat chyby")
C_WTXT    = "#c62828"


class App:
    def __init__(self, root):
        self.root = root
        root.title("Procvičování hlaviček protokolů")
        root.configure(bg=C_BG)
        root.minsize(900, 560)

        self.targets      = []    # cílová pole ve schématu
        self.tiles        = []    # dlaždice v zásobníku
        self.drag         = None  # aktivní drag: {"tile", "motion_id", "release_id"}
        self.drag_win     = None  # plovoucí Toplevel během dragu
        self.hover_target = None  # aktuálně zvýrazněné cílové pole

        self._build_ui()

    # ── Layout ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                               bg=C_BG, sashwidth=5, sashrelief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Levý panel – scrollovatelný seznam protokolů
        left = tk.Frame(pane, bg=C_BG)
        pane.add(left, minsize=130, width=155)

        tk.Label(left, text="Protokoly", bg=C_BG,
                 font=("Segoe UI", 11, "bold")).pack(pady=(4, 3))

        lb_f = tk.Frame(left, bg=C_BG)
        lb_f.pack(fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(lb_f)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.lb = tk.Listbox(lb_f, yscrollcommand=sb.set,
                              font=("Segoe UI", 10), activestyle="none",
                              selectbackground=C_TILE, selectforeground="white",
                              bg="white", relief=tk.FLAT, bd=1)
        sb.config(command=self.lb.yview)
        self.lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for p in list(PROTOCOLS) + UNDEFINED:
            self.lb.insert(tk.END, p)
        self.lb.bind("<<ListboxSelect>>", self._on_select)

        # Pravý panel – schéma + zásobník
        right = tk.Frame(pane, bg=C_BG)
        pane.add(right, minsize=600)

        # Horní lišta: název protokolu, průběh, reset
        top = tk.Frame(right, bg=C_BG)
        top.pack(fill=tk.X, padx=4, pady=(2, 0))
        self.lbl_name = tk.Label(top, text="← Vyber protokol ze seznamu",
                                  bg=C_BG, font=("Segoe UI", 13, "bold"))
        self.lbl_name.pack(side=tk.LEFT)
        self.lbl_errors = tk.Label(top, text="", bg=C_BG,
                                    font=("Segoe UI", 10), fg="#e53935")
        self.lbl_errors.pack(side=tk.RIGHT, padx=4)
        self.lbl_prog = tk.Label(top, text="", bg=C_BG,
                                  font=("Segoe UI", 10), fg="#666")
        self.lbl_prog.pack(side=tk.RIGHT, padx=6)
        _bkw = dict(bg="#e4e8f4", relief=tk.FLAT, font=("Segoe UI", 9),
                    cursor="hand2", bd=1, padx=4)
        tk.Button(top, text="Ukázat řešení", command=self._show_solution, **_bkw).pack(side=tk.RIGHT, padx=2)
        tk.Button(top, text="Ukázat chyby",  command=self._show_errors,   **_bkw).pack(side=tk.RIGHT, padx=2)
        tk.Button(top, text="Zkontrolovat",  command=self._check,          **_bkw).pack(side=tk.RIGHT, padx=2)
        tk.Button(top, text="↺ Reset",       command=self._reset,          **_bkw).pack(side=tk.RIGHT, padx=2)

        # Canvas pro schéma – výška se nastaví dynamicky po načtení protokolu
        sch_f = tk.Frame(right, bg=C_BG)
        sch_f.pack(fill=tk.X, padx=4, pady=4)
        sch_sb = tk.Scrollbar(sch_f, orient=tk.VERTICAL)
        self.sch = tk.Canvas(sch_f, bg="white", width=CW, height=1,
                               yscrollcommand=sch_sb.set,
                               highlightthickness=1,
                               highlightbackground="#c0c8d8")
        sch_sb.config(command=self.sch.yview)
        sch_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.sch.pack(side=tk.LEFT)

        tk.Frame(right, height=2, bg="#c0c8d8").pack(fill=tk.X, padx=4)

        tk.Label(right,
                 text="Přetáhni dlaždici na správné pole v hlavičce:",
                 bg=C_BG, font=("Segoe UI", 9, "italic"),
                 fg="#666").pack(anchor="w", padx=8, pady=(3, 0))

        # Zásobník dlaždic – grid zalamující do řádků, šířka = šířka schématu
        tray_f = tk.Frame(right, bg="#e8ecf4", relief=tk.SUNKEN, bd=1)
        tray_f.pack(fill=tk.X, padx=4)
        self.tray = tk.Canvas(tray_f, bg="#e8ecf4", width=CW, height=1,
                               highlightthickness=0)
        self.tray.pack(anchor="w")

        # Hláška po správném složení
        self.lbl_done = tk.Label(right, text="", bg=C_BG,
                                  font=("Segoe UI", 11, "bold"), fg="#4caf50")
        self.lbl_done.pack(pady=3)

    # ── Výběr / reset protokolu ────────────────────────────────────────────────
    def _on_select(self, _=None):
        sel = self.lb.curselection()
        if sel:
            self._load(self.lb.get(sel[0]))

    def _reset(self):
        sel = self.lb.curselection()
        if sel:
            self._load(self.lb.get(sel[0]))

    def _load(self, name):
        self._cancel_drag()
        self.sch.delete("all")
        self.tray.delete("all")
        self.targets.clear()
        self.tiles.clear()
        self.hover_target = None
        self.lbl_name.config(text=name)
        self.lbl_done.config(text="")
        self.lbl_prog.config(text="")
        self.lbl_errors.config(text="")
        self.sch.bind("<Button-1>", self._schema_click)

        if name in UNDEFINED:
            self.sch.create_text(CW // 2, 90,
                                  text="Pole nejsou definována",
                                  font=("Segoe UI", 14), fill="#aaa")
            return

        fields = PROTOCOLS[name]
        self._draw_schema(fields)
        self._draw_tray(self._build_tray_items(fields))
        self._refresh_progress()
        self._resize_window()

    def _cancel_drag(self):
        """Zruší probíhající drag (např. při přepnutí protokolu)."""
        self._clear_hover()
        if self.drag_win:
            self.drag_win.destroy()
            self.drag_win = None
        if self.drag:
            self._return_tile(self.drag["tile"])
            try:
                self.root.unbind("<B1-Motion>",       self.drag["motion_id"])
                self.root.unbind("<ButtonRelease-1>",  self.drag["release_id"])
            except Exception:
                pass
            self.drag = None

    # ── Schéma hlavičky (cílová pole) ─────────────────────────────────────────
    def _draw_schema(self, fields):
        cv  = self.sch
        ppb = CW / BPR  # pixelů na bit

        # Číselník: čárky a čísla každé 4 bity
        for b in range(0, BPR + 1, 4):
            x = b * ppb
            cv.create_line(x, 0, x, RULER_H, fill="#ccc")
        for b in range(0, BPR, 4):
            cv.create_text((b + 2) * ppb, RULER_H // 2,
                            text=str(b), font=("Segoe UI", 7), fill="#bbb")

        row = 0   # aktuální řádek
        col = 0   # bitový offset na aktuálním řádku

        for name, bits in fields:
            remaining = bits
            first     = True
            while remaining > 0:
                avail = BPR - col
                chunk = min(remaining, avail)
                x1 = col * ppb
                y1 = RULER_H + row * ROW_H
                x2 = x1 + chunk * ppb
                y2 = y1 + ROW_H

                r = cv.create_rectangle(x1, y1, x2, y2,
                                         fill=C_EMPTY, outline="#7a8ab0")
                # Prázdné pole — název se zobrazí až po správném přetažení dlaždice
                t = cv.create_text((x1+x2)/2, (y1+y2)/2,
                                    text="", font=("Segoe UI", 8),
                                    fill=C_ETXT, width=(x2-x1)-6)

                self.targets.append({
                    "rect": r, "txt": t,
                    "field_name": name,
                    "bits": bits,        # celková šířka pole
                    "first": first,      # první chunk pole
                    "x": x1, "y": y1,
                    "w": chunk * ppb, "h": ROW_H,
                    "placed_tile": None, # dlaždice aktuálně vložená do tohoto chunku
                })

                first  = False
                col   += chunk
                remaining -= chunk
                if col >= BPR:
                    col = 0
                    row += 1

        # Nastav scroll region na celou výšku schématu
        rows_used = row + (1 if col > 0 else 0)
        total_h   = RULER_H + rows_used * ROW_H + 8
        cv.config(scrollregion=(0, 0, CW, total_h))
        self.sch.config(height=total_h)

    # ── Sestavení dlaždic: správná pole + distraktori ─────────────────────────
    def _build_tray_items(self, fields):
        """Vrátí zamíchaný seznam (name, bits, is_distractor) pro zásobník."""
        current_names = {name for name, _ in fields}

        # Sbírej unikátní pole ze všech ostatních protokolů
        seen, pool = set(), []
        for proto_fields in PROTOCOLS.values():
            for n, b in proto_fields:
                if n not in current_names and n not in seen:
                    seen.add(n)
                    pool.append((n, b))

        n_dist  = min(5, len(pool))
        distract = random.sample(pool, n_dist)

        items  = [(n, b, False) for n, b in fields]
        items += [(n, b, True)  for n, b in distract]
        random.shuffle(items)
        return items

    # ── Zásobník dlaždic ───────────────────────────────────────────────────────
    def _draw_tray(self, items):
        # items: seznam trojic (name, bits, is_distractor)
        cv  = self.tray
        PAD = 8
        tiles_per_row = max(1, (CW - PAD) // (TW + PAD))
        col = row = 0

        for name, bits, is_distractor in items:
            x = PAD + col * (TW + PAD)
            y = PAD + row * (TH + PAD)

            r = cv.create_rectangle(x, y, x+TW, y+TH,
                                     fill=C_TILE, outline="#3a5bd0",
                                     tags=("tile",))
            t = cv.create_text(x+TW/2, y+TH/2-7,
                                text=name, font=("Segoe UI", 7, "bold"),
                                fill=C_TTXT, width=TW-10, tags=("tile",))
            b = cv.create_text(x+TW/2, y+TH-10,
                                text="", font=("Segoe UI", 7),
                                fill="#c0ccff", tags=("tile",))

            tile = {"rect": r, "txt": t, "blbl": b,
                    "field_name": name, "bits": bits,
                    "is_distractor": is_distractor,
                    "placed": False, "placed_group": None}
            self.tiles.append(tile)

            for item in (r, t, b):
                cv.tag_bind(item, "<Button-1>",
                             lambda e, tl=tile: self._drag_start(e, tl))

            col += 1
            if col >= tiles_per_row:
                col = 0
                row += 1

        n_rows  = row + (1 if col > 0 else 0)
        tray_h  = PAD + n_rows * (TH + PAD)
        cv.config(width=CW, height=tray_h,
                  scrollregion=(0, 0, CW, tray_h))

    # ── Drag & Drop ────────────────────────────────────────────────────────────
    def _drag_start(self, event, tile):
        if tile["placed"] or self.drag:
            return

        # Zesvětli dlaždici v zásobníku
        self.tray.itemconfig(tile["rect"], fill="#8ea8f8")

        # Plovoucí okno sledující kurzor
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.wm_attributes("-topmost", True)
        try:
            win.wm_attributes("-alpha", 0.88)
        except Exception:
            pass
        self.drag_win = win

        frm = tk.Frame(win, bg=C_TILE, bd=2, relief=tk.RAISED)
        frm.pack(fill=tk.BOTH, expand=True)
        tk.Label(frm, text=tile["field_name"], bg=C_TILE, fg=C_TTXT,
                 font=("Segoe UI", 8, "bold"),
                 wraplength=TW-8, justify=tk.CENTER).pack(expand=True)
        win.geometry(f"{TW}x{TH}+{event.x_root - TW//2}+{event.y_root - TH//2}")

        # Globální handlery platí po celou dobu dragu (i mimo tray canvas)
        mid = self.root.bind("<B1-Motion>",      self._drag_motion,   add="+")
        rid = self.root.bind("<ButtonRelease-1>", self._drag_release,  add="+")
        self.drag = {"tile": tile, "motion_id": mid, "release_id": rid}

    def _drag_motion(self, event):
        if not self.drag or not self.drag_win:
            return
        self.drag_win.geometry(
            f"+{event.x_root - TW//2}+{event.y_root - TH//2}")
        self._update_hover(event)

    def _drag_release(self, event):
        if not self.drag:
            return

        tile = self.drag["tile"]
        mid  = self.drag["motion_id"]
        rid  = self.drag["release_id"]

        self._clear_hover()
        if self.drag_win:
            self.drag_win.destroy()
            self.drag_win = None
        try:
            self.root.unbind("<B1-Motion>",      mid)
            self.root.unbind("<ButtonRelease-1>", rid)
        except Exception:
            pass
        self.drag = None

        # Puštěno nad schématem → vlož do pole pod kurzorem
        cv = self.sch
        sx, sy = cv.winfo_rootx(), cv.winfo_rooty()
        if (sx <= event.x_root <= sx + cv.winfo_width() and
                sy <= event.y_root <= sy + cv.winfo_height()):
            cx = cv.canvasx(event.x_root - sx)
            cy = cv.canvasy(event.y_root - sy)
            hit = next(
                (t for t in self.targets
                 if t["x"] <= cx <= t["x"] + t["w"]
                 and t["y"] <= cy <= t["y"] + t["h"]),
                None)
            if hit:
                self._place_tile(tile, hit["field_name"])
                return

        # Puštěno mimo schéma → vrátit do zásobníku
        self._return_tile(tile)

    # ── Hover: zvýraznění cílového pole pod kurzorem ──────────────────────────
    def _clear_hover(self):
        """Odstraní zvýraznění aktuálně podsvíceného pole a obnoví správnou barvu."""
        if self.hover_target:
            t = self.hover_target
            if t["placed_tile"] is not None:
                self.sch.itemconfig(t["rect"], fill=C_PLACED, outline="#5c7cfa")
            else:
                self.sch.itemconfig(t["rect"], fill=C_EMPTY, outline="#7a8ab0")
            self.hover_target = None

    def _update_hover(self, event):
        """Zvýrazní nezaplněné pole pod kurzorem; ostatní odzvýrazní."""
        cv = self.sch
        sx, sy = cv.winfo_rootx(), cv.winfo_rooty()
        new_hover = None
        if (sx <= event.x_root <= sx + cv.winfo_width() and
                sy <= event.y_root <= sy + cv.winfo_height()):
            cx = cv.canvasx(event.x_root - sx)
            cy = cv.canvasy(event.y_root - sy)
            new_hover = next(
                (t for t in self.targets
                 if t["x"] <= cx <= t["x"] + t["w"]
                 and t["y"] <= cy <= t["y"] + t["h"]),
                None)

        if new_hover is self.hover_target:
            return  # beze změny

        self._clear_hover()
        if new_hover:
            self.sch.itemconfig(new_hover["rect"],
                                fill=C_HOVER, outline="#f9a825")
            self.hover_target = new_hover

    # ── Volné skládání ─────────────────────────────────────────────────────────
    def _place_tile(self, tile, field_name):
        """Vloží dlaždici do pole field_name; starou dlaždici případně vrátí do zásobníku."""
        # Pokud pole obsazené jinou dlaždicí → tu vrátit
        old = next((t["placed_tile"] for t in self.targets
                    if t["field_name"] == field_name
                    and t["placed_tile"] is not None), None)
        if old is not None and old is not tile:
            self._clear_field(field_name)
            self._return_tile(old)

        # Pokud dlaždice byla v jiném poli → to pole vyčistit
        if tile["placed_group"] and tile["placed_group"] != field_name:
            self._clear_field(tile["placed_group"])

        # Vložit do všech chunků pole
        bits = tile["bits"]
        for t in self.targets:
            if t["field_name"] == field_name:
                t["placed_tile"] = tile
                label = f"{tile['field_name']}\n{bits} b" if t["first"] else f"↩ {tile['field_name']}"
                self.sch.itemconfig(t["rect"], fill=C_PLACED, outline="#5c7cfa")
                self.sch.itemconfig(t["txt"], text=label, fill=C_PTXT,
                                    font=("Segoe UI", 8))

        # Zamknout dlaždici v zásobníku
        tile["placed"]       = True
        tile["placed_group"] = field_name
        cv = self.tray
        cv.itemconfig(tile["rect"], fill=C_DONE, outline="#aaa")
        cv.itemconfig(tile["txt"],  fill=C_DTXT)
        for item in (tile["rect"], tile["txt"], tile["blbl"]):
            cv.tag_unbind(item, "<Button-1>")

        self._refresh_progress()

    def _clear_field(self, field_name):
        """Vizuálně i datově vyčistí pole; nesahá na dlaždici."""
        for t in self.targets:
            if t["field_name"] == field_name:
                t["placed_tile"] = None
                self.sch.itemconfig(t["rect"], fill=C_EMPTY, outline="#7a8ab0")
                self.sch.itemconfig(t["txt"],  text="", fill=C_ETXT,
                                    font=("Segoe UI", 8))

    def _return_tile(self, tile):
        """Vrátí dlaždici zpět do zásobníku; nesahá na pole."""
        tile["placed"]       = False
        tile["placed_group"] = None
        cv = self.tray
        cv.itemconfig(tile["rect"], fill=C_TILE, outline="#3a5bd0")
        cv.itemconfig(tile["txt"],  fill=C_TTXT)
        for item in (tile["rect"], tile["txt"], tile["blbl"]):
            cv.tag_unbind(item, "<Button-1>")
            cv.tag_bind(item, "<Button-1>",
                        lambda e, tl=tile: self._drag_start(e, tl))

    def _schema_click(self, event):
        """Kliknutí na schéma — pokud je v poli dlaždice, zvedni ji pro přetažení."""
        if self.drag:
            return
        cx = self.sch.canvasx(event.x)
        cy = self.sch.canvasy(event.y)
        hit = next(
            (t for t in self.targets
             if t["x"] <= cx <= t["x"] + t["w"]
             and t["y"] <= cy <= t["y"] + t["h"]
             and t["placed_tile"] is not None),
            None)
        if hit is None:
            return
        tile = hit["placed_tile"]
        self._clear_field(tile["placed_group"])
        self._return_tile(tile)
        self._drag_start(event, tile)

    # ── Akční tlačítka ─────────────────────────────────────────────────────────
    def _check(self):
        """Spočítá a zobrazí počet špatně obsazených polí (prázdná se nepočítají)."""
        wrong = sum(1 for t in self.targets
                    if t["first"]
                    and t["placed_tile"] is not None
                    and t["placed_tile"]["field_name"] != t["field_name"])
        all_n = len({t["field_name"] for t in self.targets})
        occ_n = len({t["field_name"] for t in self.targets
                     if t["placed_tile"] is not None})
        if wrong == 0 and occ_n == all_n:
            self.lbl_errors.config(text="Vše správně!")
            self.lbl_done.config(text="Skvěle! Hlavička je správně složena.")
        else:
            self.lbl_errors.config(text=f"Chyby: {wrong}")
            self.lbl_done.config(text="")

    def _show_errors(self):
        """Obarví pole: zelená = správně umístěná dlaždice, červená = špatně."""
        for t in self.targets:
            if t["placed_tile"] is None:
                continue
            if t["placed_tile"]["field_name"] == t["field_name"]:
                self.sch.itemconfig(t["rect"], fill=C_SNAP,  outline="#2e7d32")
                self.sch.itemconfig(t["txt"],  fill=C_STXT,  font=("Segoe UI", 8, "bold"))
            else:
                self.sch.itemconfig(t["rect"], fill=C_WRONG, outline="#c62828")
                self.sch.itemconfig(t["txt"],  fill=C_WTXT,  font=("Segoe UI", 8, "bold"))

    def _show_solution(self):
        """Doplní správné dlaždice do všech polí a obarví schéma zeleně."""
        # Vrátit vše do zásobníku a vyčistit schéma
        for tile in self.tiles:
            if tile["placed"]:
                tile["placed"]       = False
                tile["placed_group"] = None
                self.tray.itemconfig(tile["rect"], fill=C_TILE, outline="#3a5bd0")
                self.tray.itemconfig(tile["txt"],  fill=C_TTXT)
                for item in (tile["rect"], tile["txt"], tile["blbl"]):
                    self.tray.tag_unbind(item, "<Button-1>")
                    self.tray.tag_bind(item, "<Button-1>",
                                       lambda e, tl=tile: self._drag_start(e, tl))
        for t in self.targets:
            t["placed_tile"] = None
            self.sch.itemconfig(t["rect"], fill=C_EMPTY, outline="#7a8ab0")
            self.sch.itemconfig(t["txt"],  text="", fill=C_ETXT, font=("Segoe UI", 8))

        # Vložit správné dlaždice (rovnou zeleně)
        done = set()
        for t in self.targets:
            fn = t["field_name"]
            if fn in done:
                continue
            done.add(fn)
            tile = next((tl for tl in self.tiles
                         if tl["field_name"] == fn and not tl["is_distractor"]), None)
            if tile is None:
                continue
            bits = t["bits"]
            for chunk in self.targets:
                if chunk["field_name"] == fn:
                    chunk["placed_tile"] = tile
                    label = f"{fn}\n{bits} b" if chunk["first"] else f"↩ {fn}"
                    self.sch.itemconfig(chunk["rect"], fill=C_SNAP,  outline="#2e7d32")
                    self.sch.itemconfig(chunk["txt"],  text=label,   fill=C_STXT,
                                        font=("Segoe UI", 8, "bold"))
            tile["placed"]       = True
            tile["placed_group"] = fn
            self.tray.itemconfig(tile["rect"], fill=C_DONE, outline="#aaa")
            self.tray.itemconfig(tile["txt"],  fill=C_DTXT)
            for item in (tile["rect"], tile["txt"], tile["blbl"]):
                self.tray.tag_unbind(item, "<Button-1>")

        self._refresh_progress()
        self.lbl_done.config(text="Toto je správné řešení.")

    def _refresh_progress(self):
        all_f = {t["field_name"] for t in self.targets}
        occ_f = {t["field_name"] for t in self.targets if t["placed_tile"] is not None}
        n, d  = len(all_f), len(occ_f)
        self.lbl_prog.config(text=f"{d}/{n} obsazeno" if self.targets else "")

    def _resize_window(self):
        """Přizpůsobí okno přesné výšce schématu + zásobníku."""
        schema_h = int(self.sch.cget("height"))
        tray_h   = int(self.tray.cget("height"))
        # Fixní overhead: horní lišta, popisky, rámy, dekorace okna OS
        OVERHEAD = 140
        win_h    = schema_h + tray_h + OVERHEAD
        win_w    = CW + 200  # levý panel (155) + sash (5) + scrollbar + okraje
        self.root.geometry(f"{win_w}x{win_h}")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()

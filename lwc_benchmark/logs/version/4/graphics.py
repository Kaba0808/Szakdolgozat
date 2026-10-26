# -*- coding: utf-8 -*-
"""
graphics.py - a szakdolgozat abrainak es osszesito tablazatanak eloallitasa
==========================================================================

Bemenet: a Tera Term naplofajljai optimalizacios szintenkent (a mappaban):
    meres-O0.*, meres-O2.*, meres-O3.*, meres-Ofast.*, meres-Os.*, meres-Oz.*
    (barmilyen kiterjesztessel; a FAJLOK szotarban atirhato),
    valamint a memoria.py altal irt memoria.csv (a 7. abrahoz; ha nincs, kimarad).

Algoritmusnevek a naplokban: AES-128 (a tervezok referenciakodja, rijndael.c),
SPECK-128, LEA-128, Ascon-AEAD128, valamint kiegeszitokent AES-tiny es AES-tinyCTR
(tiny-AES-c ECB es CTR modban).

Minden naplobol az UTOLSO teljes futas CSV-sorait olvassa (a RESET elotti
felbeszakadt indulasokat kihagyja), es meresenkent a 10 kor MEDIANJAT veszi.

Kimenet (az abrak/ mappaba):
    osszesito_median.csv   - minden szint, algoritmus, muvelet, meret:
                             median, min, max, CPB, kB/s
    1_skalazodas.pdf/png   - titkositasi ido az uzenetmeret fuggvenyeben (-O3)
    2_cpb_O3.pdf/png       - fajlagos koltseg 1024 B-on (-O3)
    3_cpb_hoterkep.pdf/png - CPB minden optimalizacios szinten (hoterkep)
    4_relativ_O3.pdf/png   - koltseg az -O3-hoz viszonyitva (pontdiagram)
    5_kulcsgeneralas.pdf/png
    6_ascon_vs_aes.pdf/png - az Ascon-AEAD128 es az AES osszevetese rovid uzeneteken (-O3)
    7_meret_sebesseg.pdf/png - kodmeret es fajlagos koltseg egyutt (szintenkent)

A LaTeX-be a .pdf valtozatot erdemes betenni (vektoros, eles nyomtatasban).
A feliratokat a program automatikusan helyezi el ugy, hogy ne fedjek egymast,
a jelolopontokat es a jelmagyarazatot (cimke_elhelyezo).
Futtatas:  python graphics.py
"""
import csv
import os
import re
import statistics
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm, LinearSegmentedColormap
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

# ---------------------------------------------------------------------------
# Beallitasok
# ---------------------------------------------------------------------------
F_CPU = 80_000_000          # Hz
MAPPA = "."                 # ahol a naplok vannak
KIMENET = "abrak"
MEMORIA = "memoria.csv"     # a memoria.py kimenete (a MAPPA-ban)

# szint -> naplofajl (elotag; a kiterjesztes mindegy)
FAJLOK = {
    "-O0":    "meres-O0",
    "-O2":    "meres-O2",
    "-O3":    "meres-O3",
    "-Ofast": "meres-Ofast",
    "-Os":    "meres-Os",
    "-Oz":    "meres-Oz",
}
# Cortex-M4-en a GCC -Os es -Oz mellett azonos kodot general (meresileg is
# ciklusra azonos), ezert az abrakon egy oszlopkent szerepelnek.
SZINTEK_ABRA = ["-O0", "-O2", "-O3", "-Ofast", "-Os/-Oz"]

MERETEK = [16, 64, 256, 1024]

# Algoritmusok: megjelenitett nev, szin (validalt kategorikus paletta, fix
# sorrend), jelolo es vonaltipus (masodlagos kodolas: szintevesztes, fekete-feher nyomtatas)
ALGO = {
    "AES-128":   dict(nev="AES-128",       szin="#2a78d6", jelolo="o", vonal="-"),
    "SPECK-128": dict(nev="SPECK-128",     szin="#eb6834", jelolo="s", vonal="-"),
    "LEA-128":   dict(nev="LEA-128",       szin="#1baf7a", jelolo="^", vonal="--"),
    "Ascon-AEAD128": dict(nev="Ascon-AEAD128",     szin="#eda100", jelolo="D", vonal="-"),
}
# Kiegeszito osszevetes: ugyanaz az AES-128 a tiny-AES-c implementacioval
# (semleges szurke, hogy ne versenyezzen a negy fo algoritmus szineivel)
KIEG = {
    "AES-tiny":    dict(nev="AES-128 (tiny-AES-c)",      szin="#898781", jelolo="o", vonal=":"),
    "AES-tinyCTR": dict(nev="AES-128 (tiny-AES-c, CTR)", szin="#898781", jelolo="o", vonal="--"),
}
MIND = {**ALGO, **KIEG}
# Sorok a hoterkephez es a relativ abrahoz (algoritmus, muvelet, felirat)
SOROK = [
    ("AES-128",     "Encrypt", "AES-128 titkosítás"),
    ("AES-128",     "Decrypt", "AES-128 visszafejtés"),
    ("SPECK-128",   "Encrypt", "SPECK-128 titkosítás"),
    ("SPECK-128",   "Decrypt", "SPECK-128 visszafejtés"),
    ("LEA-128",     "Encrypt", "LEA-128 titkosítás"),
    ("LEA-128",     "Decrypt", "LEA-128 visszafejtés"),
    ("Ascon-AEAD128",   "Encrypt", "Ascon-AEAD128 titkosítás"),
    ("Ascon-AEAD128",   "Decrypt", "Ascon-AEAD128 visszafejtés"),
    ("AES-tiny",    "Encrypt", "tiny-AES-c titkosítás"),
    ("AES-tiny",    "Decrypt", "tiny-AES-c visszafejtés"),
    ("AES-tinyCTR", "Encrypt", "tiny-AES-c CTR (mindkét irány)"),
]

# Diagram-"kronika": visszafogott racs es tengely, egyseges tinta
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
KEK = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.edgecolor": AXIS,
    "axes.labelcolor": INK2,
    "axes.linewidth": 0.8,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.6,
    "grid.linestyle": "-",
    "xtick.color": INK2,
    "ytick.color": INK2,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "legend.frameon": False,
    "legend.fontsize": 8,
    "savefig.bbox": "tight",
    "savefig.dpi": 300,
    "pdf.fonttype": 42,
})
SZELES = 6.3   # hüvelyk = kb. 160 mm, a dolgozat szedestukre


# ---------------------------------------------------------------------------
# Magyar szamformatum: tizedesvesszo, ezres tagolas keskeny szokozzel
# ---------------------------------------------------------------------------
def hu(x, tizedes=1):
    s = f"{x:,.{tizedes}f}".replace(",", " ").replace(".", ",")
    return s


def hu_auto(x, _=None):
    if x >= 100:
        return hu(x, 0)
    if x >= 1:
        return hu(x, 1).rstrip("0").rstrip(",")
    return hu(x, 3).rstrip("0").rstrip(",")


# ---------------------------------------------------------------------------
# Beolvasas
# ---------------------------------------------------------------------------
SOR = re.compile(r"^(\d+),([A-Za-z][A-Za-z0-9-]*),(\w+),(\d+),(\d+)\s*$")


def beolvas(utvonal):
    """Az utolso teljes futas soraibol meresenkent a korok ertekeinek listaja."""
    with open(utvonal, encoding="utf-8", errors="replace") as f:
        sorok = f.read().splitlines()
    fejlecek = [i for i, s in enumerate(sorok) if s.startswith("Futas,Algoritmus")]
    if not fejlecek:
        raise ValueError(f"{utvonal}: nincs 'Futas,Algoritmus' fejlec")
    adat = defaultdict(list)
    for s in sorok[fejlecek[-1] + 1:]:
        m = SOR.match(s)
        if m:
            _, algo, muv, meret, ciklus = m.groups()
            adat[(algo, muv, int(meret))].append(int(ciklus))
    korok = {len(v) for v in adat.values()}
    if len(korok) != 1:
        raise ValueError(f"{utvonal}: hianyos futas (korszamok: {korok})")
    return adat


def fajl_keres(elotag):
    for nev in sorted(os.listdir(MAPPA)):
        if nev.startswith(elotag + "."):
            return os.path.join(MAPPA, nev)
    raise FileNotFoundError(f"Nem talalom: {elotag}.* a(z) {MAPPA} mappaban")


def betolt_mind():
    nyers = {szint: beolvas(fajl_keres(elotag)) for szint, elotag in FAJLOK.items()}
    med = {}
    for szint, adat in nyers.items():
        med[szint] = {k: statistics.median(v) for k, v in adat.items()}
    # -Os es -Oz osszevonasa (ellenorzes: tenyleg azonosak-e)
    elteres = max(abs(med["-Os"][k] - med["-Oz"][k]) / max(1, med["-Oz"][k]) for k in med["-Oz"])
    print(f"-Os vs -Oz legnagyobb relativ elteres: {elteres:.4%}")
    med["-Os/-Oz"] = med["-Os"]
    return nyers, med


def osszesito_csv(nyers, ut):
    with open(ut, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Szint", "Algoritmus", "Muvelet", "Meret_B", "Median_ciklus",
                    "Min", "Max", "Elteres_%", "CPB", "Atvitel_kBps", "Ido_ms"])
        for szint, adat in nyers.items():
            for (algo, muv, meret), v in sorted(adat.items()):
                m = statistics.median(v)
                cpb = m / meret if meret else ""
                kbps = meret * F_CPU / m / 1000 if (meret and m) else ""
                w.writerow([szint, algo, muv, meret, m, min(v), max(v),
                            round((max(v) - min(v)) / m * 100, 4) if m else 0,
                            round(cpb, 2) if cpb != "" else "",
                            round(kbps, 1) if kbps != "" else "",
                            round(m / F_CPU * 1000, 4)])


def ment(fig, nev):
    for kit in ("pdf", "png"):
        fig.savefig(os.path.join(KIMENET, f"{nev}.{kit}"))
    plt.close(fig)
    print("  ", nev)



# ---------------------------------------------------------------------------
# Feliratok elhelyezese atfedes nelkul
# ---------------------------------------------------------------------------
def _pt2px(fig, pt):
    return pt * fig.dpi / 72.0


def cimke_elhelyezo(ax, elemek, akadalyok=(), meret=6.5, szin=None, tavok=(6, 10, 16, 24), jelolopontok=None):
    """Pontfeliratok elhelyezese ugy, hogy ne fedjek egymast, a jelolopontokat,
    a tengely szelet es a megadott akadalyokat (pl. jelmagyarazat).

    elemek:    [(x, y, szoveg), ...] adatkoordinatakban (a felirat horgonypontja)
    jelolopontok: az osszes kirajzolt jelolo [(x, y), ...]; egyik felirat sem takarhatja
               (ha nincs megadva, az elemek pontjai)
    akadalyok: tovabbi tiltott teruletek (matplotlib Bbox, kepernyo-koordinata)
    A jeloltek: jobbra, balra, fole, ala, majd atlosan, egyre tavolabb; ha a felirat
    messzebb kerul a ponttol, vekony osszekoto vonalat kap."""
    from matplotlib.transforms import Bbox
    fig = ax.figure
    fig.canvas.draw()
    rend = fig.canvas.get_renderer()
    tengely = ax.get_window_extent(rend)
    r = _pt2px(fig, 5.0)                       # a jelolo "sugara" pixelben
    pontok = [ax.transData.transform((x, y)) for x, y, _ in elemek]
    jp = jelolopontok if jelolopontok is not None else [(x, y) for x, y, _ in elemek]
    jelolok = [Bbox.from_extents(px - r, py - r, px + r, py + r)
               for px, py in (ax.transData.transform(p) for p in jp)]
    foglalt = list(akadalyok)
    irany = [(1, 0, "left", "center"), (-1, 0, "right", "center"), (0, 1, "center", "bottom"),
             (0, -1, "center", "top"), (0.75, 0.75, "left", "bottom"), (0.75, -0.75, "left", "top"),
             (-0.75, 0.75, "right", "bottom"), (-0.75, -0.75, "right", "top")]
    # a surubb helyeken levo pontokat helyezzuk el eloszor
    def suruseg(i):
        px, py = pontok[i]
        return -sum(1 for qx, qy in pontok if abs(qx - px) + abs(qy - py) < _pt2px(fig, 40))
    for i in sorted(range(len(elemek)), key=suruseg):
        x, y, szoveg = elemek[i]
        legjobb = None
        for tav in tavok:
            for dx, dy, ha, va in irany:
                t = ax.annotate(szoveg, (x, y), xytext=(dx * tav, dy * tav), textcoords="offset points",
                                ha=ha, va=va, fontsize=meret, color=szin or INK2, zorder=5)
                bb = t.get_window_extent(rend).expanded(1.06, 1.15)
                ut = sum(bb.overlaps(b) for b in foglalt)
                ut += sum(bb.overlaps(b) for b in jelolok)
                kint = not (tengely.x0 <= bb.x0 and bb.x1 <= tengely.x1 and tengely.y0 <= bb.y0 and bb.y1 <= tengely.y1)
                if ut == 0 and not kint:
                    legjobb = (t, bb, tav)
                    break
                t.remove()
            if legjobb:
                break
        if legjobb is None:                    # vegso esetben a legkisebb utkozesu jobb oldali hely
            t = ax.annotate(szoveg, (x, y), xytext=(tavok[-1], 0), textcoords="offset points",
                            ha="left", va="center", fontsize=meret, color=szin or INK2, zorder=5)
            legjobb = (t, t.get_window_extent(rend), tavok[-1])
        t, bb, tav = legjobb
        if tav > tavok[1]:
            ax.annotate("", (x, y), xytext=t.get_position(), textcoords="offset points",
                        arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.6, shrinkA=0, shrinkB=r * 72 / fig.dpi))
        foglalt.append(bb)
    return foglalt


def jelmagyarazat_felul(ax, ncols):
    """Jelmagyarazat a rajzterulet folott, a tengelyen kivul (nem takarhat adatot)."""
    return ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncols=ncols,
                     handlelength=2.2, columnspacing=1.6, borderaxespad=0.2)


# ---------------------------------------------------------------------------
# 1. Skalazodas az uzenetmerettel (-O3)
# ---------------------------------------------------------------------------
def abra_skalazodas(med, szint="-O3"):
    """A LEA es a SPECK gorbeje szinte egybeesik, ezert a nevek nem a vonalak
    vegere, hanem a rajzterulet folotti jelmagyarazatba kerulnek; a LEA
    szaggatott vonala es eltero jeloloje miatt mindketto kivehető."""
    fig, ax = plt.subplots(figsize=(SZELES, 3.5))
    for kulcs, st in ALGO.items():
        y = [med[szint][(kulcs, "Encrypt", m)] / F_CPU * 1000 for m in MERETEK]
        ax.plot(MERETEK, y, color=st["szin"], ls=st["vonal"], lw=1.8,
                marker=st["jelolo"], ms=6, mfc=st["szin"], mec="white", mew=1.0, zorder=3,
                label=st["nev"])
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(MERETEK, [f"{m} B" for m in MERETEK])
    ax.minorticks_off()
    ax.yaxis.set_major_formatter(FuncFormatter(hu_auto))
    ax.set_xlabel("Üzenetméret")
    ax.set_ylabel("Titkosítási idő 80 MHz-en\n(ms, log. skála)")
    ax.set_xlim(12, 1024 * 1.35)
    jelmagyarazat_felul(ax, len(ALGO))
    ment(fig, "1_skalazodas")


# ---------------------------------------------------------------------------
# 2. Fajlagos koltseg 1024 B-on (-O3) - vizszintes csoportositott oszlopok
# ---------------------------------------------------------------------------
def abra_cpb(med, szint="-O3"):
    algok = list(ALGO) + ["AES-tiny"]
    fig, ax = plt.subplots(figsize=(SZELES, 3.3))
    h = 0.36
    maxv = max(med[szint][(a, m, 1024)] / 1024 for a in algok for m in ("Encrypt", "Decrypt"))
    for i, (muv, felirat, szin) in enumerate([("Encrypt", "titkosítás", KEK[5]),
                                              ("Decrypt", "visszafejtés", KEK[2])]):
        for j, a in enumerate(algok):
            cpb = med[szint][(a, muv, 1024)] / 1024
            y = j + (i - 0.5) * (h + 0.04)
            ax.barh(y, cpb, height=h, color=szin, label=felirat if j == 0 else None, zorder=3)
            ax.text(cpb + maxv * 0.012, y, hu(cpb), va="center", ha="left", fontsize=7.5, color=INK2)
    ax.set_yticks(range(len(algok)), [MIND[a]["nev"] for a in algok])
    ax.invert_yaxis()
    ax.set_xlabel(f"Fajlagos költség, ciklus/bájt (1024 B, {szint})")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: hu(x, 0)))
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, maxv * 1.13)              # hely az ertekfeliratoknak
    jelmagyarazat_felul(ax, 2)
    ment(fig, "2_cpb_O3")


# ---------------------------------------------------------------------------
# 3. Hoterkep: CPB minden optimalizacios szinten
# ---------------------------------------------------------------------------
def abra_hoterkep(med):
    import numpy as np
    M = np.array([[med[s][(a, m, 1024)] / 1024 for s in SZINTEK_ABRA] for a, m, _ in SOROK])
    cmap = LinearSegmentedColormap.from_list("kek", KEK)
    fig, ax = plt.subplots(figsize=(SZELES, 4.6))
    im = ax.imshow(M, cmap=cmap, norm=LogNorm(vmin=M.min(), vmax=M.max()), aspect="auto")
    for i in range(M.shape[0]):
        legjobb = M[i, 1:].min()                  # a legjobb optimalizalt szint
        for j in range(M.shape[1]):
            v = M[i, j]
            sotet = im.norm(v) > 0.55
            ax.text(j, i, hu(v, 0 if v >= 1000 else 1), ha="center", va="center", fontsize=7.5,
                    color="white" if sotet else INK,
                    fontweight="bold" if (j > 0 and v == legjobb) else "normal")
    ax.set_xticks(range(len(SZINTEK_ABRA)), SZINTEK_ABRA)
    ax.set_yticks(range(len(SOROK)), [s[2] for s in SOROK])
    ax.tick_params(length=0)
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xticks(np.arange(-0.5, M.shape[1]), minor=True)
    ax.set_yticks(np.arange(-0.5, M.shape[0]), minor=True)
    ax.grid(which="minor", color="white", linewidth=2)
    ax.tick_params(which="minor", length=0)
    ax.xaxis.tick_top()
    cb = fig.colorbar(im, ax=ax, pad=0.02, fraction=0.04)
    cb.set_label("ciklus/bájt (log. skála)", color=INK2)
    cb.ax.yaxis.set_major_formatter(FuncFormatter(hu_auto))
    cb.ax.yaxis.set_minor_formatter(NullFormatter())
    cb.outline.set_visible(False)
    ment(fig, "3_cpb_hoterkep")


# ---------------------------------------------------------------------------
# 4. Relativ koltseg az -O3-hoz kepest (pontdiagram)
# ---------------------------------------------------------------------------
def abra_relativ(med, alap="-O3"):
    # a harom szint jeloloi kicsit eltolva (-O2 felul, -Ofast kozepen, -Os/-Oz alul),
    # igy a 100 % kozeleben egybeeso ertekek sem takarjak egymast
    szintek = [("-O2", "o", KEK[2], 6.5, -0.2), ("-Ofast", "|", INK, 9, 0.0), ("-Os/-Oz", "D", KEK[6], 6, 0.2)]
    fig, ax = plt.subplots(figsize=(SZELES, 4.4))
    ax.axvline(100, color=MUTED, lw=0.9, zorder=1)
    minden = []
    for i, (a, m, _) in enumerate(SOROK):
        ertekek = [med[s][(a, m, 1024)] / med[alap][(a, m, 1024)] * 100 for s, *_ in szintek]
        minden += ertekek
        ax.plot([min(ertekek + [100]), max(ertekek + [100])], [i, i], color=GRID, lw=6, zorder=2,
                solid_capstyle="round", alpha=0.8)
        for (s, jel, szin, ms, eltol), v in zip(szintek, ertekek):
            ax.plot(v, i + eltol, marker=jel, ms=ms, color=szin, mec="white" if jel != "|" else szin,
                    mew=1.0 if jel != "|" else 1.6, ls="none", zorder=4 if jel == "|" else 3,
                    label=s if i == 0 else None)
    ax.set_yticks(range(len(SOROK)), [s[2] for s in SOROK])
    ax.invert_yaxis()
    ax.set_ylim(len(SOROK) - 0.5, -0.6)
    lo, hi = min(minden + [100]), max(minden + [100])
    tart = hi - lo
    ax.set_xlim(lo - tart * 0.06, hi + tart * 0.06)
    ax.set_xlabel(f"Ciklusszám az {alap}-hoz viszonyítva (%, 1024 B); 100 % = {alap}, balra jobb")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: hu(x, 0)))
    ax.grid(axis="y", visible=False)
    jelmagyarazat_felul(ax, 3)
    ment(fig, "4_relativ_O3")


# ---------------------------------------------------------------------------
# 5. Kulcsgeneralas
# ---------------------------------------------------------------------------
def abra_kulcs(med):
    # (kulcs a medianban, felirat); az AES-nel a visszafejto kulcs kulon lepes
    sorok = [(("AES-128", "KeyGen", 0),    "AES-128 (titkosító kulcs)"),
             (("AES-128", "KeyGenDec", 0), "AES-128 (visszafejtő kulcs)"),
             (("SPECK-128", "KeyGen", 0),  "SPECK-128"),
             (("LEA-128", "KeyGen", 0),    "LEA-128"),
             (("AES-tiny", "KeyGen", 0),   "AES-128 (tiny-AES-c)")]
    sorok = [s for s in sorok if s[0] in med["-O3"]]
    szintek = [("-O0", KEK[1]), ("-O3", KEK[3]), ("-Os/-Oz", KEK[6])]
    fig, ax = plt.subplots(figsize=(SZELES, 0.6 + 0.62 * len(sorok)))
    h = 0.26
    maxv = max(med[s][k] for s, _ in szintek for k, _ in sorok)
    for i, (s, szin) in enumerate(szintek):
        for j, (k, _) in enumerate(sorok):
            v = med[s][k]
            y = j + (i - 1) * (h + 0.03)
            ax.barh(y, v, height=h, color=szin, label=s if j == 0 else None, zorder=3)
            ax.text(v + maxv * 0.012, y, hu(v, 0), va="center", fontsize=7.5, color=INK2)
    ax.set_yticks(range(len(sorok)), [f for _, f in sorok])
    ax.invert_yaxis()
    ax.set_xlabel("Kulcsgenerálás, órajelciklus")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: hu(x, 0)))
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, maxv * 1.13)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncols=3)
    # Az Ascon-AEAD128-nak nincs kulon kulcsgeneralasa -> ezt az abra LaTeX-felirata mondja ki
    ment(fig, "5_kulcsgeneralas")


# ---------------------------------------------------------------------------
# 6. Ascon-AEAD128 vs AES rovid uzeneteken (-O3, linearis illesztes); az atfordulasi
#    pontot csak akkor jeloli, ha a ket egyenes a 0-300 B tartomanyban metszi egymast
# ---------------------------------------------------------------------------
def illesztes(med, a, szint, muv="Encrypt"):
    import numpy as np
    y = [med[szint][(a, muv, m)] for m in MERETEK]
    b, c = np.polyfit(MERETEK, y, 1)         # y = b*x + c
    return b, c, y


def atfordulas(med, a, szint, ref="Ascon-AEAD128"):
    """Az az uzenetmeret (bajt), amely felett az Ascon olcsobb, mint az 'a' algoritmus
    (None, ha nincs ilyen pont)."""
    bA, cA, _ = illesztes(med, ref, szint)
    b, c, _ = illesztes(med, a, szint)
    if b <= bA:
        return None
    x = (cA - c) / (b - bA)
    return x if x > 0 else 0.0


def abra_atfordulas(med, szint="-O3", xmax=300):
    import numpy as np
    fig, ax = plt.subplots(figsize=(SZELES, 3.3))
    x = np.linspace(0, xmax, 200)
    jelolesek = []
    for a in ["AES-128", "AES-tiny", "Ascon-AEAD128"]:
        if (a, "Encrypt", 16) not in med[szint]:
            continue
        b, c, y = illesztes(med, a, szint)
        st = MIND[a]
        ax.plot(x, (b * x + c) / 1000, color=st["szin"], ls=st["vonal"], lw=1.6, zorder=2, label=st["nev"])
        pts = [(m, v) for m, v in zip(MERETEK, y) if m <= xmax]
        ax.plot([p[0] for p in pts], [p[1] / 1000 for p in pts], ls="none", marker=st["jelolo"],
                ms=6, color=st["szin"], mec="white", mew=1.0, zorder=3)
        if a != "Ascon-AEAD128":
            xs = atfordulas(med, a, szint)
            print(f"  {a}: {b:.1f} c/B + {c:.0f}; Ascon-nal atfordulas: "
                  + (f"{xs:.1f} B" if xs is not None else "nincs (az Ascon minden meretnel dragabb)"))
            if xs is not None and xs <= xmax:
                jelolesek.append((xs, (b * xs + c) / 1000, st["nev"]))
    bA, cA, _ = illesztes(med, "Ascon-AEAD128", szint)
    print(f"  Ascon-AEAD128: fix koltseg {cA:.0f} ciklus, meredekseg {bA:.1f} c/B")
    ax.set_xlim(0, xmax)
    ax.set_ylim(0)
    ytet = ax.get_ylim()[1]
    for xs, ys, nev in jelolesek:
        # fuggoleges pontozott vonal az atfordulasnal, a felirat a vonal mellett,
        # a rajzterulet felso reszen, ahol rovid uzeneteken nincs adatvonal
        ax.axvline(xs, color=MUTED, lw=0.8, ls=":", zorder=1)
        ax.plot(xs, ys, marker="o", ms=7, mfc="none", mec=INK2, mew=1.0, zorder=4)
        ax.text(xs + xmax * 0.012, ytet * 0.96, f"≈ {hu(xs, 0)} B", rotation=90, ha="left", va="top",
                fontsize=7.5, color=INK2)
    ax.set_xlabel("Üzenetméret (bájt)")
    ax.set_ylabel(f"Titkosítás, ezer ciklus ({szint})")
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: hu(v, 0)))
    jelmagyarazat_felul(ax, 3)
    ment(fig, "6_ascon_vs_aes")


def memoria_beolvas(ut):
    adat = {}
    with open(ut, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            adat[(r["szint"], r["algoritmus"])] = int(r["flash"])
    return adat


def abra_meret_sebesseg(med, mem, algok=None, nevek=None):
    """Optimalizalt szintek (-O2, -O3, -Os/-Oz): x = flash-igeny, y = titkositasi CPB.
    Az -O0-t kihagyja (fejlesztoi beallitas, a skalat torzitana). Az egymashoz nagyon
    kozel eso (atfedo) pontok egy feliratot kapnak (pl. "-O2/-O3/-Os"), a feliratokat
    a cimke_elhelyezo teszi atfedesmentes helyre."""
    import math
    algok = algok or [a for a in list(ALGO) + ["AES-tiny"] if ("-O3", a) in mem]
    szintek = [("-O2", "-O2"), ("-O3", "-O3"), ("-Os", "-Os/-Oz")]
    fig, ax = plt.subplots(figsize=(SZELES, 3.9))
    csoportok = []
    osszes = []
    for a in algok:
        st = MIND[a]
        pts = []
        for s, sm in szintek:
            if (s, a) in mem:
                pts.append((mem[(s, a)], med[sm][(a, "Encrypt", 1024)] / 1024, s))
        osszes += pts
        ax.plot([p[0] for p in pts], [p[1] for p in pts], ls="none", marker=st["jelolo"], ms=7,
                color=st["szin"], mec="white", mew=1.0, zorder=3, label=(nevek or {}).get(a, st["nev"]))
        csoportok.append(pts)
    ax.set_xscale("log")
    ax.set_yscale("log")
    xs = [p[0] for p in osszes]; ys = [p[1] for p in osszes]
    ax.set_xlim(min(xs) / 1.8, max(xs) * 2.2)
    ax.set_ylim(min(ys) / 1.25, max(ys) * 1.25)
    ax.xaxis.set_major_formatter(FuncFormatter(hu_auto))
    ax.yaxis.set_major_formatter(FuncFormatter(hu_auto))
    ax.yaxis.set_minor_formatter(FuncFormatter(hu_auto))
    ax.set_xlabel("Flash-igény (bájt, log. skála)")
    ax.set_ylabel("Titkosítás, ciklus/bájt\n(1024 B, log. skála)")
    ax.tick_params(axis="both", which="both", labelsize=7.5)
    jelmagyarazat_felul(ax, len(algok))
    # csoportositas a kirajzolt kepen: ha egy algoritmus ket pontja kozelebb van egymashoz,
    # mint kb. egy jelolonyi tavolsag, egy kozos feliratot kapnak (pl. "-O2/-O3/-Os")
    fig.canvas.draw()
    kuszob = _pt2px(fig, 9)
    elemek = []
    for pts in csoportok:
        csop = []
        for p in pts:
            pp = ax.transData.transform(p[:2])
            for g in csop:
                if any(math.dist(pp, ax.transData.transform(q[:2])) < kuszob for q in g):
                    g.append(p)
                    break
            else:
                csop.append([p])
        for g in csop:
            gx = math.exp(sum(math.log(p[0]) for p in g) / len(g))
            gy = math.exp(sum(math.log(p[1]) for p in g) / len(g))
            elemek.append((gx, gy, "/".join(p[2] for p in g)))
    cimke_elhelyezo(ax, elemek, meret=6.5, jelolopontok=[p[:2] for p in osszes])
    ment(fig, "7_meret_sebesseg")


if __name__ == "__main__":
    os.makedirs(KIMENET, exist_ok=True)
    nyers, med = betolt_mind()
    osszesito_csv(nyers, os.path.join(KIMENET, "osszesito_median.csv"))
    print("Abrak:")
    abra_skalazodas(med)
    abra_cpb(med)
    abra_hoterkep(med)
    abra_relativ(med)
    abra_kulcs(med)
    abra_atfordulas(med)
    memut = os.path.join(MAPPA, MEMORIA)
    if os.path.exists(memut):
        abra_meret_sebesseg(med, memoria_beolvas(memut))
    else:
        print("  (nincs memoria.csv - a 7. abra kimarad)")
    print("Kesz:", os.path.abspath(KIMENET))

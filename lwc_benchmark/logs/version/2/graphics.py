# -*- coding: utf-8 -*-
"""
graphics.py - a szakdolgozat abrainak es osszesito tablazatanak eloallitasa
==========================================================================

Bemenet: a Tera Term naplofajljai optimalizacios szintenkent (a mappaban):
    meres3-O0.*, meres3-O2.*, meres3-O3.*, meres3-Ofast.*, meres3-Os.*, meres3-Oz.*
    (barmilyen kiterjesztessel; a FAJLOK szotarban atirhato),
    valamint a memoria.py altal irt memoria.csv (a 7. abrahoz; ha nincs, kimarad).

Algoritmusnevek a naplokban: AES-128 (a tervezok referenciakodja, rijndael.c),
SPECK-128, LEA-128, ASCON-128, valamint kiegeszitokent AES-tiny es AES-tinyCTR
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
    6_ascon_vs_aes.pdf/png - az ASCON es az AES osszevetese rovid uzeneteken (-O3)
    7_meret_sebesseg.pdf/png - kodmeret es fajlagos koltseg egyutt (szintenkent)

A LaTeX-be a .pdf valtozatot erdemes betenni (vektoros, eles nyomtatasban).
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
    "-O0":    "meres3-O0",
    "-O2":    "meres3-O2",
    "-O3":    "meres3-O3",
    "-Ofast": "meres3-Ofast",
    "-Os":    "meres3-Os",
    "-Oz":    "meres3-Oz",
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
    "LEA-128":   dict(nev="LEA-128",       szin="#1baf7a", jelolo="^", vonal="-"),
    "ASCON-128": dict(nev="ASCON-128",     szin="#eda100", jelolo="D", vonal="-"),
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
    ("ASCON-128",   "Encrypt", "ASCON-128 titkosítás"),
    ("ASCON-128",   "Decrypt", "ASCON-128 visszafejtés"),
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
# 1. Skalazodas az uzenetmerettel (-O3)
# ---------------------------------------------------------------------------
def abra_skalazodas(med, szint="-O3"):
    fig, ax = plt.subplots(figsize=(SZELES, 3.6))
    vegek = []
    for kulcs, st in ALGO.items():
        y = [med[szint][(kulcs, "Encrypt", m)] / F_CPU * 1000 for m in MERETEK]
        ax.plot(MERETEK, y, color=st["szin"], ls=st["vonal"], lw=2,
                marker=st["jelolo"], ms=6, mfc=st["szin"], mec="white", mew=1.2, zorder=3)
        vegek.append((y[-1], st["nev"], st["szin"]))
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(MERETEK, [f"{m} B" for m in MERETEK])
    ax.minorticks_off()
    ax.yaxis.set_major_formatter(FuncFormatter(hu_auto))
    ax.set_xlabel("Üzenetméret")
    ax.set_ylabel("Titkosítási idő 80 MHz-en (ms, log. skála)")
    ax.set_xlim(12, 1024 * 4.2)
    # kozvetlen feliratok a vonalak vegen, atfedes nelkul
    vegek.sort()
    elozo = None
    for y, nev, szin in vegek:
        ycel = y if elozo is None else max(y, elozo * 1.4)
        ax.annotate(nev, (1024, y), xytext=(1024 * 1.12, ycel), color=INK, fontsize=8,
                    va="center", ha="left", textcoords="data",
                    arrowprops=dict(arrowstyle="-", color=szin, lw=0.8) if abs(ycel - y) / y > 0.02 else None)
        elozo = ycel
    ment(fig, "1_skalazodas")


# ---------------------------------------------------------------------------
# 2. Fajlagos koltseg 1024 B-on (-O3) - vizszintes csoportositott oszlopok
# ---------------------------------------------------------------------------
def abra_cpb(med, szint="-O3"):
    algok = list(ALGO) + ["AES-tiny"]
    fig, ax = plt.subplots(figsize=(SZELES, 3.2))
    h = 0.36
    for i, (muv, felirat, szin) in enumerate([("Encrypt", "titkosítás", KEK[5]),
                                              ("Decrypt", "visszafejtés", KEK[2])]):
        for j, a in enumerate(algok):
            cpb = med[szint][(a, muv, 1024)] / 1024
            y = j + (i - 0.5) * (h + 0.04)
            ax.barh(y, cpb, height=h, color=szin, label=felirat if j == 0 else None, zorder=3)
            ax.text(cpb + 6, y, hu(cpb), va="center", ha="left", fontsize=7.5, color=INK2)
    ax.set_yticks(range(len(algok)), [MIND[a]["nev"] for a in algok])
    ax.invert_yaxis()
    ax.set_xlabel(f"Fajlagos költség, ciklus/bájt (1024 B, {szint})")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: hu(x, 0)))
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(med[szint][(a, m, 1024)] / 1024 for a in algok for m in ("Encrypt", "Decrypt")) * 1.12)
    ax.legend(loc="lower right")
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
    szintek = [("-O2", "o", KEK[2]), ("-Ofast", "|", INK2), ("-Os/-Oz", "D", KEK[6])]
    fig, ax = plt.subplots(figsize=(SZELES, 4.2))
    ax.axvline(100, color=INK2, lw=1, zorder=1)
    ax.text(100.8, -0.85, f"{alap} = 100 %", ha="left", va="center", fontsize=7.5, color=INK2)
    for i, (a, m, _) in enumerate(SOROK):
        ertekek = [med[s][(a, m, 1024)] / med[alap][(a, m, 1024)] * 100 for s, *_ in szintek]
        ax.plot([min(ertekek + [100]), max(ertekek + [100])], [i, i], color=GRID, lw=2, zorder=2)
        for (s, jel, szin), v in zip(szintek, ertekek):
            ax.plot(v, i, marker=jel, ms=7 if jel != "|" else 10, color=szin, mec="white" if jel != "|" else szin,
                    mew=1.2 if jel != "|" else 1.5, ls="none", zorder=3,
                    label=s if i == 0 else None)
    ax.set_yticks(range(len(SOROK)), [s[2] for s in SOROK])
    ax.invert_yaxis()
    ax.set_ylim(len(SOROK) - 0.5, -1.2)
    ax.set_xlabel(f"Ciklusszám az {alap}-hoz viszonyítva (%, 1024 B) – balra jobb")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: hu(x, 0)))
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncols=3)
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
    for i, (s, szin) in enumerate(szintek):
        for j, (k, _) in enumerate(sorok):
            v = med[s][k]
            y = j + (i - 1) * (h + 0.03)
            ax.barh(y, v, height=h, color=szin, label=s if j == 0 else None, zorder=3)
            ax.text(v + 120, y, hu(v, 0), va="center", fontsize=7.5, color=INK2)
    ax.set_yticks(range(len(sorok)), [f for _, f in sorok])
    ax.invert_yaxis()
    ax.set_xlabel("Kulcsgenerálás, órajelciklus")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: hu(x, 0)))
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(med["-O0"][k] for k, _ in sorok) * 1.15)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncols=3)
    # Az ASCON-128-nak nincs kulon kulcsgeneralasa -> ezt az abra LaTeX-felirata mondja ki
    ment(fig, "5_kulcsgeneralas")


# ---------------------------------------------------------------------------
# 6. ASCON vs AES rovid uzeneteken (-O3, linearis illesztes); az atfordulasi
#    pontot csak akkor jeloli, ha a ket egyenes a 0-300 B tartomanyban metszi egymast
# ---------------------------------------------------------------------------
def illesztes(med, a, szint, muv="Encrypt"):
    import numpy as np
    y = [med[szint][(a, muv, m)] for m in MERETEK]
    b, c = np.polyfit(MERETEK, y, 1)         # y = b*x + c
    return b, c, y


def atfordulas(med, a, szint, ref="ASCON-128"):
    """Az a uzenetmeret (bajt), amely felett az ASCON olcsobb, mint az 'a' algoritmus
    (None, ha a meresi tartomanyban nincs ilyen pont)."""
    bA, cA, _ = illesztes(med, ref, szint)
    b, c, _ = illesztes(med, a, szint)
    if b <= bA:
        return None
    x = (cA - c) / (b - bA)
    return x if x > 0 else 0.0


def abra_atfordulas(med, szint="-O3"):
    import numpy as np
    fig, ax = plt.subplots(figsize=(SZELES, 3.2))
    x = np.linspace(0, 300, 200)
    for a in ["AES-128", "AES-tiny", "ASCON-128"]:
        if (a, "Encrypt", 16) not in med[szint]:
            continue
        b, c, y = illesztes(med, a, szint)
        st = MIND[a]
        ax.plot(x, (b * x + c) / 1000, color=st["szin"], ls=st["vonal"], lw=1.5, zorder=2, label=st["nev"])
        pts = [(m, v) for m, v in zip(MERETEK, y) if m <= 300]
        ax.plot([p[0] for p in pts], [p[1] / 1000 for p in pts], ls="none", marker=st["jelolo"],
                ms=6, color=st["szin"], mec="white", mew=1.2, zorder=3)
        if a != "ASCON-128":
            xs = atfordulas(med, a, szint)
            print(f"  {a}: {b:.1f} c/B + {c:.0f}; ASCON-nal atfordulas: "
                  + (f"{xs:.1f} B" if xs is not None else "nincs (az ASCON minden meretnel dragabb)"))
            if xs is not None and xs <= 300:
                ax.axvline(xs, color=st["szin"], lw=0.8, ls=":", zorder=1)
                ax.annotate(f"≈ {hu(xs, 0)} B", (xs, (b * xs + c) / 1000), xytext=(xs + 8, (b * xs + c) / 1000 * 0.45),
                            fontsize=7.5, color=INK, arrowprops=dict(arrowstyle="-", color=INK2, lw=0.8))
    bA, cA, _ = illesztes(med, "ASCON-128", szint)
    print(f"  ASCON-128: fix koltseg {cA:.0f} ciklus, meredekseg {bA:.1f} c/B")
    ax.set_xlim(0, 300)
    ax.set_ylim(0)
    ax.set_xlabel("Üzenetméret (bájt)")
    ax.set_ylabel(f"Titkosítás, ezer ciklus ({szint})")
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: hu(v, 0)))
    ax.legend(loc="upper left")
    ment(fig, "6_ascon_vs_aes")


# ---------------------------------------------------------------------------
# 7. Kodmeret es sebesseg egyutt: minden algoritmus negy szinten (-O0, -O2, -O3, -Os/-Oz)
# ---------------------------------------------------------------------------
def memoria_beolvas(ut):
    adat = {}
    with open(ut, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            adat[(r["szint"], r["algoritmus"])] = int(r["flash"])
    return adat


def abra_meret_sebesseg(med, mem, algok=None, nevek=None):
    """Optimalizalt szintek (-O2, -O3, -Os/-Oz): x = flash-igeny, y = titkositasi CPB.
    Az -O0-t kihagyja (fejlesztoi beallitas, a skalat torzitana); az egybeeso
    pontok szintfeliratait osszevonja (pl. -O2/-O3)."""
    algok = algok or [a for a in list(ALGO) + ["AES-tiny"] if ("-O3", a) in mem]
    szintek = [("-O2", "-O2"), ("-O3", "-O3"), ("-Os", "-Os/-Oz")]
    fig, ax = plt.subplots(figsize=(SZELES, 3.6))
    for a in algok:
        st = MIND[a]
        pts = {}
        for s, sm in szintek:
            if (s, a) in mem:
                xy = (mem[(s, a)], round(med[sm][(a, "Encrypt", 1024)] / 1024, 1))
                pts.setdefault(xy, []).append(sm)
        xs = [xy[0] for xy in pts]
        ys = [xy[1] for xy in pts]
        ax.plot(xs, ys, ls="none", marker=st["jelolo"], ms=7, color=st["szin"], mec="white", mew=1.2,
                zorder=3, label=(nevek or {}).get(a, st["nev"]))
        # a felirat alapesetben a pont jobb oldalan van; ha ugyanannak az algoritmusnak
        # egy masik pontja kozel esik, a felso pont felirata fole, az alsoe ala kerul
        import math
        lista = list(pts.items())
        for (x, y), lst in lista:
            dy = (6, -3)
            for (x2, y2), _ in lista:
                if (x2, y2) == (x, y):
                    continue
                if abs(math.log10(x / x2)) < 0.15 and abs(math.log10(y / y2)) < 0.1:
                    felso = (y > y2) or (y == y2 and x < x2)
                    dy = (5, 5) if felso else (5, -11)
            ax.annotate("/".join(lst).replace("-Os/-Oz", "-Os"), (x, y), xytext=dy,
                        textcoords="offset points", fontsize=6.5, color=INK2)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.xaxis.set_major_formatter(FuncFormatter(hu_auto))
    ax.yaxis.set_major_formatter(FuncFormatter(hu_auto))
    ax.yaxis.set_minor_formatter(FuncFormatter(hu_auto))
    ax.tick_params(axis="y", which="minor", labelsize=7)
    ax.set_xlabel("Flash-igény (bájt, log. skála)")
    ax.set_ylabel("Titkosítás, ciklus/bájt\n(1024 B, log. skála)")
    xl = ax.get_xlim(); ax.set_xlim(xl[0], xl[1] * 1.6)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncols=len(algok))
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

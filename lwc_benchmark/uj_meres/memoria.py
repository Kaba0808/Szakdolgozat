"""
memoria.py - Flash- es veremigeny kiszamitasa a sajat STM32CubeIDE-buildbol

A szakdolgozat 5.4. tablazatanak ertekeit allitja elo a valodi (mert)
buildbol, ugyanazzal a modszerrel, mint a dolgozat:
  * flash = a linker terkepfajljaban (.map) az algoritmusfajlokhoz tartozo,
    a --gc-sections utan megmaradt .text* es .rodata* szakaszok osszege;
  * verem = a GCC -fcallgraph-info=su kimenetebol (.ci) a hivasi lanc menten
    osszegzett legnagyobb ertek a mert belepesi pontokra; a konyvtari
    fuggvenyek (pl. memcpy) 0-val szamitanak, ahogy a dolgozatban.

Hasznalat (minden optimalizacios szint buildje utan egyszer):
    py memoria.py Debug -O3          -> hozzafuzi az eredmenyt a memoria.csv-hez
    py memoria.py --tabla            -> kiirja a LaTeX-tablazat sorait

Algoritmusfajlok: rijndael.c (AES-128 referencia), speck.c, lea.c, ascon128.c,
valamint aes.c (tiny-AES-c, kiegeszito osszevetes).
"""
import collections
import csv
import glob
import os
import re
import sys

# Objektumfajl neve (kiterjesztes nelkul) -> megjelenitett nev.
# AES-128 = a tervezok referenciakodja (rijndael.c), AES-tiny = tiny-AES-c (aes.c, kiegeszito)
ALGOK = ["rijndael", "speck", "lea", "ascon128", "aes"]
NEV = {"rijndael": "AES-128", "speck": "SPECK-128", "lea": "LEA-128",
       "ascon128": "ASCON-128", "aes": "AES-tiny"}

# A main.c altal hivott (mert) fuggvenyek: ezekbol indul a veremszamitas
BELEPES = {
    "rijndael": ["rijndaelKeySetupEnc", "rijndaelKeySetupDec", "rijndaelEncrypt", "rijndaelDecrypt"],
    "speck": ["Speck128128KeySchedule", "Speck128128Encrypt", "Speck128128Decrypt"],
    "lea": ["lea_set_key", "lea_encrypt", "lea_decrypt"],
    "ascon128": ["ascon128_aead_encrypt", "ascon128_aead_decrypt"],
    "aes": ["AES_init_ctx", "AES_ECB_encrypt", "AES_ECB_decrypt",
            "AES_init_ctx_iv", "AES_CTR_xcrypt_buffer"],
}
CSV_FAJL = "memoria.csv"


def flash_meret(map_fajl):
    """Algoritmusonkent a megtartott .text* + .rodata* szakaszok merete bajtban."""
    with open(map_fajl, encoding="utf-8", errors="replace") as f:
        szoveg = f.read()
    if "Linker script and memory map" not in szoveg:
        sys.exit("A .map fajlban nincs 'Linker script and memory map' resz.")
    sorok = szoveg.split("Linker script and memory map", 1)[1].splitlines()

    eredmeny = collections.defaultdict(int)
    fuggvenyek = collections.defaultdict(dict)   # algoritmus -> {szakasz: meret}
    i = 0
    while i < len(sorok):
        sor = sorok[i]
        # 1) szakasznev es adatok egy sorban:  " .text.xyz  0x0800...  0x1c  ./Core/Src/aes.o"
        m = re.match(r"^ (\.\S+)\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+(\S+\.o)\s*$", sor)
        if m:
            szakasz, meret, obj = m.group(1), int(m.group(2), 16), m.group(3)
        else:
            # 2) hosszu szakasznev: a nev sorban, az adatok a kovetkezo sorban
            m = re.match(r"^ (\.\S+)\s*$", sor)
            m2 = re.match(r"^\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+(\S+\.o)\s*$",
                          sorok[i + 1]) if (m and i + 1 < len(sorok)) else None
            if not m2:
                i += 1
                continue
            szakasz, meret, obj = m.group(1), int(m2.group(1), 16), m2.group(2)
            i += 1
        i += 1

        nev = os.path.basename(obj.replace("\\", "/"))[:-2]
        if nev not in ALGOK:
            continue
        if szakasz.startswith(".text") or szakasz.startswith(".rodata"):
            eredmeny[nev] += meret
            fuggvenyek[nev][szakasz] = meret
    return eredmeny, fuggvenyek


def verem_igeny(ci_fajl, belepesi_pontok):
    """Legnagyobb veremhasznalat a hivasi lanc menten (.ci, VCG formatum)."""
    with open(ci_fajl, encoding="utf-8", errors="replace") as f:
        t = f.read()
    meret, kulso, el = {}, set(), collections.defaultdict(set)
    for m in re.finditer(r'node: \{ title: "([^"]+)" label: "([^"]*)"', t):
        b = re.search(r"(\d+) bytes", m.group(2))
        if b:
            meret[m.group(1)] = int(b.group(1))
        else:
            kulso.add(m.group(1))          # kulso (konyvtari) fuggveny
    for m in re.finditer(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"', t):
        el[m.group(1)].add(m.group(2))

    def melyseg(fv, ut=()):
        if fv in kulso or fv in ut:
            return 0
        return meret.get(fv, 0) + max([melyseg(h, ut + (fv,)) for h in el[fv]] or [0])

    # a nem statikus fuggvenyek a .ci-ben elotag nelkul szerepelnek
    return max(melyseg(fv) for fv in belepesi_pontok)


def egy_build(debug_mappa, szint):
    maps = glob.glob(os.path.join(debug_mappa, "*.map"))
    if len(maps) != 1:
        sys.exit(f"Pontosan egy .map fajlt vartam a(z) {debug_mappa} mappaban, talalt: {maps}")
    flash, fuggvenyek = flash_meret(maps[0])
    hianyzik = [NEV[a] for a in ALGOK if flash.get(a, 0) == 0]
    if hianyzik:
        sys.exit("HIBA: a .map fajlban nincs kod ezekhez: " + ", ".join(hianyzik) +
                 ".\nValoszinuleg a legutobbi build (linkeles) nem sikerult, vagy nem ez a szint "
                 "fordult utoljara. Clean + Build utan futtasd ujra; a memoria.csv nem valtozott.")

    sorok = []
    for a in ALGOK:
        ci = glob.glob(os.path.join(debug_mappa, "**", a + ".ci"), recursive=True)
        if not ci:
            sys.exit(f"Nincs {a}.ci - be van kapcsolva a -fcallgraph-info=su kapcsolo?")
        verem = verem_igeny(ci[0], BELEPES[a])
        sorok.append({"szint": szint, "algoritmus": NEV[a], "flash": flash[a], "verem": verem})
        print(f"{szint:7s} {NEV[a]:10s} flash {flash[a]:6d} B   verem {verem:4d} B")
        # a szoveg (5.5, 5.6.3) ellenorzesehez: a 200 bajtnal nagyobb fuggvenyek
        for szak, m in sorted(fuggvenyek[a].items(), key=lambda x: -x[1]):
            if m >= 200:
                print(f"{'':20s}{szak:40s} {m:6d} B")

    regi = []
    if os.path.exists(CSV_FAJL):
        with open(CSV_FAJL, newline="", encoding="utf-8") as f:
            regi = [r for r in csv.DictReader(f) if r["szint"] != szint]
    with open(CSV_FAJL, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["szint", "algoritmus", "flash", "verem"])
        w.writeheader()
        w.writerows(regi + sorok)
    print(f"Mentve: {CSV_FAJL}")


def tabla():
    with open(CSV_FAJL, newline="", encoding="utf-8") as f:
        adat = {(r["szint"], r["algoritmus"]): r for r in csv.DictReader(f)}
    szintek = ["-O0", "-O2", "-O3", "-Os"]
    hu = lambda v: f"{int(v):,}".replace(",", "\\,")
    for a in ALGOK:
        n = NEV[a]
        fl = [hu(adat[(s, n)]["flash"]) if (s, n) in adat else "?" for s in szintek]
        ve = [adat[(s, n)]["verem"] if (s, n) in adat else "?" for s in szintek]
        print(f"        {n} & " + " & ".join(fl + ve) + r" \\ \hline")
    for s in ["-Ofast", "-Oz"]:
        par = {"-Ofast": "-O3", "-Oz": "-Os"}[s]
        if all((s, NEV[a]) in adat and (par, NEV[a]) in adat for a in ALGOK):
            egyezik = all(adat[(s, NEV[a])]["flash"] == adat[(par, NEV[a])]["flash"] for a in ALGOK)
            print(f"% {s} == {par}: {'igen' if egyezik else 'NEM - ellenorizd!'}")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--tabla":
        tabla()
    elif len(sys.argv) == 3:
        egy_build(sys.argv[1], sys.argv[2])
    else:
        print(__doc__)

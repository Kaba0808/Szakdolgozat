# Új mérés: LEA és ASCON a hivatalos etalonkódokkal

Most már mind a négy algoritmus a tervezők vagy a szabványgazda nyilvános kódja. Saját implementáció nincs a mérésben.

| Algoritmus | Fájl | Forrás |
|---|---|---|
| AES-128 | `rijndael.c/h` | a tervezők optimalizált C-kódja (rijndael-alg-fst v3.0) – **nem változott** |
| SPECK 128/128 | `speck.c/h` | NSA Implementation Guide v1.1 – **nem változott** |
| LEA-128 | `lea.c/h` | **új:** a KISA hivatalos C-forráskódja (v1.3, `lea_core.c`) |
| Ascon-AEAD128 | `ascon_aead128.c/h` | **új:** NIST SP 800-232, a tervezők `ascon-c` kódja (`asconaead128/bi32`, 32 bites optimalizált C) |
| AES-tiny | `aes.c/h` | tiny-AES-c (összevetés) – **nem változott** |

Az ASCON típusa is változott: a v1.2-es ASCON-128 helyett most a NIST-szabvány Ascon-AEAD128-at mérjük. A naplóban és az ábrákon a neve ezért `Ascon-AEAD128`.

Ellenőrizve (PC-n és ARM-fordítóval):
- **Ascon-AEAD128:** a hivatalos KAT-fájl mind az 1089 vektora rendben (-O0, -O2, -Os).
- **LEA:**
  - a KISA KCMVP ECB-tesztvektorai (128/192/256 bites kulcs, 30 kulcs) és a specifikáció tesztvektora rendben;
  - 100 000 véletlen kulcson és blokkon bitre egyezik a korábbi saját LEA-val.
- **A projekt:**
  - a `main.c` és a két új fájl hiba és figyelmeztetés nélkül fordul -O0, -O2, -O3 és -Os mellett;
  - a `memoria.py` és a `graphics.py` próbaadatokon lefut.

## 1. Fájlok cseréje a projektben (`Projekt/`)

1. Töröld (vagy zárd ki a buildből): `Src/ascon128.c`, `Inc/ascon128.h`.
2. Másold be, a régieket felülírva:
   - `Src/lea.c`, `Inc/lea.h`;
   - `Src/main.c`.
3. Másold be újként: `Src/ascon_aead128.c`, `Inc/ascon_aead128.h`.
4. `memoria.py` → `Projekt/` (felülírja a régit).
5. `graphics.py` → az új naplómappába (például `lwc_benchmark/logs/version/4/`). Ebben egyetlen változás van: az „ASCON-128” név helyett „Ascon-AEAD128” szerepel.

## 2. Mérés szintenként (ugyanúgy, mint legutóbb)

A sorrend: -O0, -O2, -O3, -Ofast, -Os, -Oz. Minden szinten:

1. Állítsd be a szintet, majd *Project → Clean* és *Build*.
2. `py memoria.py Debug -O0` (a megfelelő szinttel). A régi `memoria.csv` sorait szintenként felülírja, így a végére csak új adat marad benne.
3. Naplózz `meres-O0.csv` néven, töltsd le a programot, nyomd meg a RESET gombot, és várd meg a „Meres befejezve” sort.
4. Ellenőrizd a napló elején, hogy `Onellenorzes: MINDEN OK`. Most ezek a sorok is szerepelnek:
   - `Ascon-AEAD128 KAT (AD nelkul)`;
   - `Ascon-AEAD128 KAT (16 B AD)`;
   - `Ascon-AEAD128 hamis uzenet ... OK (elutasitva)`.

**-O0 mellett:** a tervezők ASCON-kódja szinte mindent kényszerítetten beágyaz, ezért optimalizálás nélkül nagy lesz. Az ASCON önmagában kb. 160 KB flasht és kb. 13 KB vermet igényel, a teljes program kb. 210–230 KB. Ez belefér a 256 KB-os flash-be és a RAM-ba, csak ne lepődj meg rajta. Ha a linker mégis „region FLASH overflowed” hibát adna, szólj.

## 3. Amit küldj el

- a hat naplót (`meres-*.csv`);
- a `memoria.csv`-t;
- ha elkészültek, az ábrákat.

Ezekből átírom a dolgozat LEA- és ASCON-részeit.

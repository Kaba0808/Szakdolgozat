# Új mérés: AES-128 a tervezők referenciakódjával

Ez a mappa a következő méréshez szükséges fájlokat tartalmazza. A fő változás: az AES-128 mostantól a tervezők optimalizált C-kódja (Rijmen–Bosselaers–Barreto, `rijndael-alg-fst.c` v3.0). A tiny-AES-c kiegészítő összevetésként ugyanabban a futásban továbbra is mérődik.

| Algoritmus | Fájl | Forrás |
|---|---|---|
| AES-128 | `rijndael.c` / `rijndael.h` | a tervezők optimalizált referenciakódja (public domain) |
| SPECK 128/128 | `speck.c` / `speck.h` | NSA Implementation Guide v1.1 |
| LEA-128 | `lea.c` / `lea.h` | saját kód a specifikáció alapján |
| ASCON-128 | `ascon128.c` / `ascon128.h` | ascon-c `ascon128v12/ref` |
| AES-tiny (kiegészítő) | `aes.c` / `aes.h` | tiny-AES-c |

A három blokktitkosító ECB-ciklusa most egyformán a `main.c`-ben van: minden 16 bájtos blokkra egy hívás a referenciakód blokkfüggvényére. A LEA-t ezért már nem a `lea_ecb_encrypt` méri, hanem ugyanúgy blokkonként hívjuk, mint a többit.

Ellenőrizve (PC-n és ARM-fordítóval):
- a `rijndael.c` algoritmuskódja bájtra egyezik a FreeBSD-ben megőrzött eredetivel;
- teljesíti a FIPS 197 C.1 és az SP 800-38A F.1.1 tesztvektort;
- 100 000 véletlen kulcson és blokkon egyezik a tiny-AES-c-vel;
- a `main.c` hiba nélkül fordul -O0, -O3 és -Os mellett;
- a `memoria.py` és a `graphics.py` próbaadatokon lefut.

## 1. Fájlok bemásolása a projektbe

1. `Src/rijndael.c` → `Projekt/Src/`
2. `Inc/rijndael.h` → `Projekt/Inc/`
3. `Src/main.c` → `Projekt/Src/` (felülírja a régit; a régi a Gitben megvan)
4. `memoria.py` → `Projekt/` (felülírja a régit)
5. `graphics.py` → abba a mappába, ahová a naplókat mented (például `lwc_benchmark/logs/version/3/`). Ha te is futtatod, a mérések végén a `memoria.csv`-t is másold mellé; ebből készül a 7. ábra.

A `main(old).c` maradjon kizárva a buildből (most is az).

## 2. Mérés szintenként

A sorrend: -O0, -O2, -O3, -Ofast, -Os, -Oz. Minden szinten:

1. Állítsd be a szintet: *Project → Properties → C/C++ Build → Settings → MCU GCC Compiler → Optimization*. Az *Other flags* mezőben maradjon benne a `-fcallgraph-info=su`.
2. *Project → Clean*, majd *Build*.
3. A projekt mappájában futtasd: `py memoria.py Debug -O0` (a megfelelő szinttel). Ez a buildből számolja a flash- és a veremigényt, és hozzáfűzi a `memoria.csv`-hez.
4. Mentsd el a `Debug/Projekt.list` fájlt `Projekt_O0.list` néven (a gépi kód elemzéséhez).
5. Tera Termben (115 200 baud) indíts naplózást `meres3-O0.txt` néven, majd töltsd le a programot, és nyomd meg a RESET gombot.
6. Várd meg a „Meres befejezve” sort. Az -O0 kb. 8 perc, a többi szint 1–2 perc.
7. Ellenőrizd a napló elején:
   - `Forditas:` – -O0, -O1/-O2/-O3, -Ofast vagy -Os/-Oz. **Az -Ofast-nál most „-Ofast”-nak kell megjelennie.**
   - `ART: utasitas-gyorsitotar be, adat-gyorsitotar be, eloolvasas ki`
   - `Onellenorzes: MINDEN OK`
   - a „Meresi tobbletkoltseg” három sora (ez a 4.4.2-es TODO-hoz kell, külön mérés nélkül megvan).

## 3. Kiegészítő mérés: kikapcsolt utasítás-gyorsítótár (ha van rá idő, kb. 5 perc)

Ez igazolná az ASCON-ra vonatkozó gyorsítótár-hipotézist.

1. A `main.c`-ben állítsd át: `#define ICACHE_OFF 1`.
2. Mérj így -O3 és -Os mellett, a naplók neve: `meres3-O3-icoff.txt` és `meres3-Os-icoff.txt`.
3. A napló elején most az `ART: utasitas-gyorsitotar KI ...` sornak kell állnia.
4. A végén állítsd vissza: `#define ICACHE_OFF 0`.

## 4. Amit küldj el

- a hat naplót (`meres3-*.txt`), és ha elkészült, a két `icoff` naplót;
- a `memoria.csv`-t;
- a `Projekt_*.list` fájlokat (nem kötelező).

Ezekből elkészítem az ábrákat, és átírom a dolgozat számait.

## Mi változik a dolgozatban a mérés után

- **3.1.3 és 4.3.1:** az AES-implementáció leírása (T-táblás referenciakód, kb. 10 KB tábla a flash-ben, külön visszafejtő kulcs). A tiny-AES-c rövid kiegészítő alfejezetbe kerül.
- **4.2. táblázat (források):** az AES sora; a LEA ECB-ciklusa a `main.c`-be kerül.
- **5. fejezet:**
  - minden AES-szám;
  - a kulcsgenerálás (az AES-nél két érték: titkosító és visszafejtő kulcs);
  - az ASCON–AES átfordulás, amely a gyorsabb AES miatt akár meg is szűnhet;
  - a memóriatáblázat;
  - az irodalmi összevetés.
  A tiny-AES-c eredményei a megvalósítás hatását bemutató összevetésként maradnak meg.
- **Tartalmi összefoglaló, 7.3 tézisek, ajánlások:** az új arányokkal.
- **4.4.2:** a többletköltség mért értéke a becslés helyére kerül.

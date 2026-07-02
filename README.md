# Szakdolgozat – Lightweight kriptográfiai algoritmusok teljesítmény-elemzése

Ez a repository a szakdolgozatomhoz tartozó forráskódot, benchmarkokat és dokumentációt tartalmazza.  
A projekt célja négy kriptográfiai algoritmus összehasonlítása erőforrás-korlátozott környezetben:

- AES-128
- SPECK-128/128
- LEA-128
- ASCON-128

A vizsgálat fókusza:

- titkosítási és visszafejtési sebesség,
- kulcsgenerálás költsége,
- memóriahasználat,
- kódméret,
- latencia.

## A projekt célja

A szakdolgozat azt vizsgálja, hogy a könnyűsúlyú kriptográfiai algoritmusok milyen előnyt nyújtanak az AES-hez képest STM32 alapú, korlátozott erőforrású eszközön.  
A mérés során a benchmarkok a ciklusszámot és az implementációs költségeket hasonlítják össze.

## Tartalom

A repository fő részei:

- algoritmus implementációk,
- benchmark kód,
- mérési segédfüggvények,
- szakdolgozathoz kapcsolódó dokumentáció,
- később várhatóan mérési eredmények és feldolgozott táblázatok.

## Hogyan működik

A benchmarkok STM32 mikrovezérlőn futnak, STM32CubeIDE környezetben.  
A mérésekhez cikluspontos időmérés használható, és az eredmények soros vagy debug kimeneten kiolvashatók.

A tipikus folyamat:

1. Projekt megnyitása STM32CubeIDE-ben.
2. A kívánt algoritmus és benchmark forrásfájlok beépítése a projektbe.
3. A mérési környezet beállítása.
4. A kód fordítása és feltöltése a mikrovezérlőre.
5. Az eredmények kiolvasása és elemzése.

## Fájlok röviden

- `benchmark.c`, `benchmark.h` – időmérési és segédfüggvények.
- `lea_benchmark.c` – LEA mérési rutinok.
- `main.c` – belépési pont, benchmark futtatás.
- `lea_vs.*`, `lea_*.*` – LEA implementáció és kapcsolódó tesztek.
- további algoritmusfájlok – AES, SPECK és ASCON mérésekhez.

## Fejlesztési környezet

- STM32CubeIDE
- STM32 Nucleo board
- GCC-alapú fordítás
- ST-LINK debugger/programmer

## Hardver

A projektet a NUCLEO-L432KC boardhoz igazítom, amely:

- STM32L432KCU6 mikrokontrollert használ,
- beépített ST-LINK/V2-1 debuggerrel rendelkezik,
- alkalmas DWT-alapú ciklusmérésre,
- jó választás benchmark és kriptográfiai teljesítménymérés céljára.

## Fontos megjegyzések

- A mérési eredmények platformfüggők.
- Az algoritmusok teljesítménye függ az optimalizációs szinttől.
- Az AES, SPECK, LEA és ASCON eltérő belső felépítése miatt a mért értékeket az algoritmusstruktúra is befolyásolja.
- A repo célja kutatási és oktatási használat.

## Célzott kimenet

A végső dolgozatban a repository alapján az alábbiak kerülnek bemutatásra:

- implementációs módszertan,
- mérési eljárás,
- eredménytáblázatok,
- grafikonok,
- összehasonlító értékelés,
- következtetések.

## License

A projekt jelenleg szakdolgozati célra készül.  
Ha később szükséges, itt kerülhet megadásra licencinformáció is.

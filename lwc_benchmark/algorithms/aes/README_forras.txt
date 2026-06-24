================================================================================
AES (Advanced Encryption Standard) - Forráskód dokumentáció
================================================================================

ALGORITMUS NEVE:    AES-128 (Advanced Encryption Standard, 128-bites kulcs)
IMPLEMENTÁCIÓ:      tiny-AES-c
VERZIÓ:             1.0.0 (2019. október)
FORRÁS URL:         https://github.com/kokke/tiny-AES-c
FEJLESZTŐ:          kokke (GitHub)
LETÖLTÉS DÁTUMA:    2026. június 24.
LICENC:             The Unlicense (közkincs, korlátozás nélkül felhasználható)

--------------------------------------------------------------------------------
FELHASZNÁLT FÁJLOK:
--------------------------------------------------------------------------------

  aes.h    - Publikus API, AES_ctx struktúra, függvénydeklarációk
  aes.c    - AES-128 implementáció: key expansion, encrypt, decrypt

--------------------------------------------------------------------------------
AZ IMPLEMENTÁCIÓ INDOKLÁSA:
--------------------------------------------------------------------------------

Az AES hivatalos NIST FIPS 197 szabvány referencia-implementációja asztali
rendszerekre optimalizált memóriatáblákat (lookup table-eket) alkalmaz,
amelyek mikrokontrolleres környezetben (korlátozott Flash/RAM) nem
alkalmazhatók hatékonyan.

A tiny-AES-c implementáció ezzel szemben:
  - kizárólag 8 bites S-box táblát használ (256 byte)
  - nincs dinamikus memóriaallokáció
  - hordozható ANSI C kód, ARM Cortex-M4-re fordítható
  - az embedded rendszerek közösségében de facto referencia-
    implementációnak számít (4000+ GitHub csillag, széles körű
    idézettség beágyazott rendszerekkel foglalkozó publikációkban)
  - ECB, CBC, CTR üzemmódokat tartalmaz

--------------------------------------------------------------------------------
MÉRÉSI KONFIGURÁCIÓ:
--------------------------------------------------------------------------------

- Kulcshossz:    128 bit (AES-128)
- Üzemmód:       ECB (Electronic Codebook)
- Blokk méret:   16 byte
- Függvényhívás: AES_ECB_encrypt() / AES_ECB_decrypt()

--------------------------------------------------------------------------------
MEGJEGYZÉS:
--------------------------------------------------------------------------------

A tiny-AES-c az AES szabvánnyal teljes mértékben kompatibilis eredményt
ad — az NIST FIPS 197 tesztvektoraival minden esetben egyezik a kimenet.
Az implementáció megválasztása tehát nem befolyásolja az összehasonlítás
érvényességét, csupán a mikrokontrolleres korlátokhoz ig
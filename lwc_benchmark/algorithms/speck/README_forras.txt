================================================================================
SPECK - Forráskód dokumentáció
================================================================================

ALGORITMUS NEVE:    SPECK 128/128 (128-bites blokk, 128-bites kulcs)
IMPLEMENTÁCIÓ:      NSA hivatalos referencia implementáció
FORRÁS:             SIMON and SPECK Implementation Guide v1.1
SZERZŐK:            Ray Beaulieu, Douglas Shors, Jason Smith,
                    Stefan Treatman-Clark, Bryan Weeks, Louis Wingers
KIADÓ:              National Security Agency (NSA)
DÁTUM:              2019. január 15.
PDF URL:            https://nsacyber.github.io/simon-speck/implementations/
                    ImplementationGuide1.1.pdf
LETÖLTÉS DÁTUMA:    2026. június 24.
LICENC:             Nyilvános kormányzati dokumentum, szabadon felhasználható

--------------------------------------------------------------------------------
IMPLEMENTÁLT VARIÁNS:
--------------------------------------------------------------------------------

  Speck128/128 — 128-bites blokk, 128-bites kulcs, 32 kör

  A SPECK algoritmuscsaládból ezt a variánst választottuk, mert:
    - 64-bites szavakkal dolgozik → Cortex-M4 32-bites architektúrán
      is hatékony (uint64_t típussal)
    - A 128-bites blokkméret megfelel az AES-sel és az ASCON-128a-val
      való összehasonlításhoz (egységes blokk- és kulcsméret)
    - Ez az egyetlen SPECK variáns, amelyhez az NSA teljes
      körenkénti tesztvektort közöl (Section 16)

--------------------------------------------------------------------------------
FELHASZNÁLT KÓD ALAPJA (PDF fejezetek szerint):
--------------------------------------------------------------------------------

  Section 1:  Típus-aliasok (u8, u64), ROTL64/ROTR64 makrók
  Section 2:  Byte és szó-rendezési elv (little-endian),
              BytesToWords64() és Words64ToBytes() konverziók
  Section 6:  SPECK128 Reference Code:
                - ER64 / DR64 round function makrók
                - Speck128128KeySchedule()
                - Speck128128Encrypt()
                - Speck128128Decrypt()

--------------------------------------------------------------------------------
TESZTVEKTOROK ELLENŐRZÉSE (PDF Section 16 - SPECK128/128):
--------------------------------------------------------------------------------

  pt:  20 6d 61 64 65 20 69 74 20 65 71 75 69 76 61 6c
  k:   00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
  ct:  18 0d 57 5c df fe 60 78 65 32 78 79 51 98 5d a6

  Az implementáció a fenti tesztvektorral ellenőrzött —
  az STM32-n futó kód kimenetét a beágyazott tesztelő rutin
  összehasonlítja az elvárt ct értékkel induláskor.

--------------------------------------------------------------------------------
MÉRÉSI KONFIGURÁCIÓ:
--------------------------------------------------------------------------------

  Kulcshossz:      128 bit (16 byte)
  Blokk mérete:    128 bit (16 byte)
  Körök száma:     32
  Üzemmód:         ECB (egy blokk, ismételt mérés)
  Mért függvény:   speck128_encrypt() / speck128_decrypt()

--------------------------------------------------------------------------------
HIVATKOZÁS A DOLGOZATBAN:
--------------------------------------------------------------------------------

  R. Beaulieu, D. Shors, J. Smith, S. Treatman-Clark, B. Weeks, L. Wingers,
  "SIMON and SPECK Implementation Guide v1.1",
  National Security Agency, Technical Report, 2019. január 15.
  [Online] Elérhető: https://nsacyber.github.io/simon-speck/implementations/
  ImplementationGuide1.1.pdf
  [Letöltve: 2026. június 24.]

================================================================================
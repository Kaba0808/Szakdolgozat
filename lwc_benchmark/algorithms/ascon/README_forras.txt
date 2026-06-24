================================================================================
ASCON - Forráskód dokumentáció
================================================================================

ALGORITMUS NEVE:    ASCON-128a (Authenticated Encryption with Associated Data)
IMPLEMENTÁCIÓ:      ASCON referencia implementáció (ref könyvtár)
VERZIÓ:             v1.2.7 (NIST LWC végleges benyújtás)
FORRÁS URL:         https://github.com/ascon/ascon-c
FEJLESZTŐ:          Christoph Dobraunig, Maria Eichlseder, Florian Mendel,
                    Martin Schläffer (Graz University of Technology / Radboud)
LETÖLTÉS DÁTUMA:    2026. június 24.
LICENC:             Creative Commons CC0 1.0 (közkincs)

--------------------------------------------------------------------------------
ASCON VARIÁNS INDOKLÁSA:
--------------------------------------------------------------------------------

Az ASCON algoritmuscsaládból az ASCON-128a változatot alkalmaztuk, mert:

  - ASCON-128a rate mérete 16 byte (vs. ASCON-128: 8 byte), ezért
    azonos adatmennyiség feldolgozásához kevesebb permutációs lépést
    igényel → magasabb átviteli sebesség (throughput)
  - A belső permutáció erőssége azonos (P12 inicializálás/véglegesítés,
    P8 adatfeldolgozás)
  - Az ASCON-128a az NIST LWC verseny egyik végleges jelöltje volt,
    2023-ban az NIST a teljes ASCON-családot választotta szabványnak
    (NIST SP 800-232 tervezet)
  - A benchmark célja az adatfeldolgozási sebesség mérése, amelyhez
    az ASCON-128a kedvezőbb jellemzőkkel bír

--------------------------------------------------------------------------------
FELHASZNÁLT FÁJLOK (ascon/ref/ alkönyvtár tartalma):
--------------------------------------------------------------------------------

  api.h            - CRYPTO_KEYBYTES (16), CRYPTO_NPUBBYTES (16),
                     CRYPTO_ABYTES (16) konstansok
  ascon.h          - ascon_state_t struktúra (5 × uint64_t)
  crypto_aead.h    - crypto_aead_encrypt() / crypto_aead_decrypt() API
  permutations.h   - P12() és P8() permutáció makrók/függvények
  word.h           - LOADBYTES, STOREBYTES, CLEARBYTES, PAD, DSEP makrók
  encrypt.c        - AEAD titkosítás és hitelesítés implementációja

--------------------------------------------------------------------------------
MÉRÉSI KONFIGURÁCIÓ:
--------------------------------------------------------------------------------

  Variáns:         ASCON-128a
  Kulcshossz:      128 bit (16 byte)
  Nonce:           128 bit (16 byte)
  Tag mérete:      128 bit (16 byte)
  Rate:            16 byte (2 × 64 bit szó)
  Permutáció:      P12 (init/final), P8 (adatfeldolgozás)
  Üzemmód:         AEAD (hitelesített titkosítás, üres AD mezővel)
  Mért függvény:   crypto_aead_encrypt()

--------------------------------------------------------------------------------
MEGJEGYZÉS A printstate() HÍVÁSOKRÓL:
--------------------------------------------------------------------------------

Az eredeti referenciakód debug-céllal tartalmaz printstate() és
printbytes() hívásokat. A benchmark mérés előtt ezeket a hívásokat
feltételes fordítással (#ifdef DEBUG) ki kell kapcsolni, hogy ne
befolyásolják a cikluszám-mérést.

================================================================================
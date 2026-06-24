================================================================================
LEA (Lightweight Encryption Algorithm) - Forráskód dokumentáció
================================================================================

ALGORITMUS NEVE:    LEA (Lightweight Encryption Algorithm)
VERZIÓ:             1.1 (KCMVP referencia implementáció)
FORRÁS URL:         https://seed.kisa.or.kr/kisa/Board/20/detailView.do
FEJLESZTŐ:          KISA (Korea Internet & Security Agency)
LETÖLTÉS DÁTUMA:    2026. június 24.
LICENC:             Public domain / nyilvános referencia implementáció

--------------------------------------------------------------------------------
FELHASZNÁLT FÁJLOK (STM32 benchmarkhoz):
--------------------------------------------------------------------------------

  lea.h              - Publikus API, LEAKEY struktúra, függvénydeklarációk
  lea_locl.h         - Belső makrók: ROL, ROR, loadU32, endianness kezelés
  config.h           - Build-konfigurációs flagek (NO_SIMD, endianness)
  lea_core.c         - Titkosítási mag: key schedule, encrypt, decrypt
  lea_base.c         - initsimd() dispatch, publikus API wrapper-ek
  lea_t_fallback.c   - Fallback dispatch wrapper
  lea_t_generic.c    - Generikus (portable, SIMD-mentes) implementáció
  lea_ecb.h          - ECB üzemmód
  lea_cbc.h          - CBC üzemmód
  lea_ctr.h          - CTR üzemmód
  lea_cfb.h          - CFB üzemmód
  lea_ofb.h          - OFB üzemmód
  lea_cmac.h         - CMAC hitelesítő kód
  lea_ccm.h          - CCM üzemmód
  lea_gcm.h          - GCM üzemmód interfész
  lea_gcm_generic.c  - GCM generikus implementáció

--------------------------------------------------------------------------------
NEM FELHASZNÁLT FÁJLOK (PC-s SIMD optimalizációk, STM32-n nem fordulnak):
--------------------------------------------------------------------------------

  lea_avx2.h, lea_sse2.h, lea_xop.h  - Intel x86 SIMD intrinsics
  lea_neon.h, lea_t_neon.c            - ARM NEON (Cortex-M4-en nincs)
  lea_core_xop.c                      - AMD XOP utasításkészlet
  lea_t_avx2_*.c, lea_t_sse2.c       - PC-s wrapper-ek
  cpu_info.h, cpu_info_arm.c,
  cpu_info_ia32.c, arm_arch.h         - CPU feature detektálás
  lea_gcm_pclmul.c                    - Intel PCLMUL utasítás
  lea_key.h                           - Alternatív inline key schedule
  lea_online.c                        - Streaming (online) API

--------------------------------------------------------------------------------
MEGJEGYZÉSEK:
--------------------------------------------------------------------------------

- Az STM32F4 Cortex-M4 little-endian processzor, ezért a config.h-ban
  az IS_LITTLE_ENDIAN flag aktív, a NO_SIMD flag szintén be van állítva.
- A lea_base.c initsimd() függvénye futásidőben a "generic" ágat
  választja (SIMD-mentes), mivel az STM32-n nincs SSE2/AVX2/NEON.
- A mérések kizárólag ECB módban, 128-bites kulccsal készültek,
  a lea_encrypt() / lea_decrypt() függvények közvetlen hívásával.

================================================================================
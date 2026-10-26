/*
 * lea.h - LEA-128/192/256 blokktitkosito (KS X 3246, ISO/IEC 29192-2:2019)
 *
 * Forras: a KISA (Korea Internet & Security Agency) hivatalos C-forraskodja,
 *   "블록암호 LEA 소스코드 (v1.3)", LEA_C_Standalone_src.zip, src/ konyvtar
 *   (https://seed.kisa.or.kr/kisa/Board/20/detailView.do; modositatlan tukor:
 *   https://github.com/jinahya/kisa-lea, doc/ mappa).
 * Felhasznalasi feltetel (KISA): a LEA szellemi tulajdonjogi dij nelkul
 *   hasznalhato termekek gyartasahoz es ertekesitesehez.
 *
 * A fajl tartalma valtozatlanul: a config.h, valamint a lea.h-bol a LEA_KEY
 * tipus es a lea_set_key prototipusa, a lea_locl.h-bol a lea_encrypt es a
 * lea_decrypt prototipusa. Az uzemmodok (ECB, CBC, CTR, GCM stb.) es a SIMD-
 * valtozatok deklaracioi nem kerultek at, mert a meres a blokkfuggvenyeket hivja.
 */
#ifndef _LEA_HEADER_
#define _LEA_HEADER_

/* ===================== config.h ===================== */
#ifndef _LEA_CONFIG_H_
#define _LEA_CONFIG_H_

#ifndef LEA_LIB
#define LEA_LIB 0
#endif						/*	0 : Standalone 코드를 생성합니다.
								1 :	Visual C++ Library 용 dllexport, dllimport를 사용한 코드를 생성합니다.
								*/

#ifndef LEA_BUILD_DLL
#define LEA_BUILD_DLL 0			/*	0 : dllimport를 적용합니다.
								1 :	dllexport를 적용합니다.
								*/
#endif

#define USE_BUILT_IN	1	/*	0 : 표준 API를 사용하지 않습니다. 커널, 펌웨어 등에 사용 시 적합합니다.
								1 :	표준 API를 사용합니다.
								*/

//#define NO_AVX2
//#define NO_XOP
//#define NO_SSE2
//#define NO_PCLMUL
//#define NO_NEON
//#define NO_SIMD

/// Library Export 매크로
#if LEA_LIB == 0 && !defined(EXPORT)
#	define EXPORT
#elif LEA_LIB == 1 && !defined(EXPORT)
#	ifdef _MSC_VER
#		ifdef LEA_BUILD_DLL
#			define EXPORT __declspec(dllexport)
#		else
#			define EXPORT __declspec(dllimport)
#		endif
#	elif defined(_WIN32) || defined(__CYGWIN__)
#		define EXPORT
#	else
#		define EXPORT __attribute__ ((visibility ("default")))
#	endif
#endif


//#define IS_LITTLE_ENDIAN 1

/* Endian Check */
#if defined(IS_LITTLE_ENDIAN)
/* do Nothing */
#elif defined(__i386) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_X64)
#	define IS_LITTLE_ENDIAN 1
/* Intel Architecture */
#elif defined(_MSC_VER)
#	define IS_LITTLE_ENDIAN 1
/* All available "Windows" are Little-Endian except XBOX360. */
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && defined(__ORDER_LITTLE_ENDIAN__)
/* GCC style */
/* use __BYTE_ORDER__ */
#	if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#		define IS_LITTLE_ENDIAN 1
#	else
#		define IS_LITTLE_ENDIAN 0
#	endif
#elif defined(__BIG_ENDIAN__) || defined(__LITTLE_ENDIAN__)
/* use __BIG_ENDIAN__ and __LITTLE_ENDIAN__ */
#	if defined(__LITTLE_ENDIAN__)
#		if __LITTLE_ENDIAN__
#			define IS_LITTLE_ENDIAN 1
#		else
#			define IS_LITTLE_ENDIAN 0
#		endif
#	elif defined(__BIG_ENDIAN__)
#		if __BIG_ENDIAN__
#			define IS_LITTLE_ENDIAN 0
#		else
#			define IS_LITTLE_ENDIAN 1
#		endif
#	endif
#else
/* use <endian.h> */
#	ifdef BSD
#		include <sys/endian.h>
#	else
#		include <endian.h>
#	endif
#	if __BYTE_ORDER__ == __LITTLE_ENDIAN
#		define IS_LITTLE_ENDIAN 1
#	else
#		define IS_LITTLE_ENDIAN 0
#	endif
#endif

#endif

/* ===================== lea.h (reszlet) ===================== */
#ifdef __cplusplus
extern "C" {
#endif

typedef struct lea_key_st
{
	unsigned int rk[192];
	unsigned int round;
} LEA_KEY;

EXPORT void lea_set_key(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len);

/* ===================== lea_locl.h (reszlet) ===================== */
void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_decrypt(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key);

#ifdef __cplusplus
}
#endif

#endif

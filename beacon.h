/*
 * beacon.h — Havoc C2 Beacon API compatibility header
 *
 * Provides Cobalt Strike-compatible API declarations used by
 * Havoc's CoffeeLdr (BOF loader).
 *
 * CRITICAL: All Beacon API functions MUST use DECLSPEC_IMPORT
 * so the compiler generates __imp_BeaconXxx symbols in COFF.
 * CoffeeLdr resolves symbols by __imp_ prefix — plain declarations
 * produce bare symbols (e.g. BeaconOutput instead of __imp_BeaconOutput)
 * which CoffeeLdr cannot find → "Symbol not found" error.
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* --- Callback types --- */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* --- Data parser --- */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

/* --- Beacon API ---
 * DECLSPEC_IMPORT is required to generate __imp_ prefixed symbols
 * in the COFF object file. Without it, CoffeeLdr will fail with
 * "Symbol not found: BeaconXxx".
 */
DECLSPEC_IMPORT void    BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char   *BeaconDataExtract(datap *parser, int *size);

DECLSPEC_IMPORT void    BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, char *data, int len);

DECLSPEC_IMPORT BOOL    BeaconIsAdmin(void);
DECLSPEC_IMPORT void    BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void    BeaconRevertToken(void);

/* NOTE: BeaconFormat* APIs are broken in Havoc — do NOT use */

#endif /* BEACON_H */

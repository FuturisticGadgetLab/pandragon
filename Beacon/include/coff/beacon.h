/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Cobalt Strike 4.1.
 */

#include <minwindef.h>
#include <windows.h>

/* data API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

__declspec(dllimport)  void    BeaconDataParse(datap * parser, char * buffer, int size);
__declspec(dllimport)  int     BeaconDataInt(datap * parser);
__declspec(dllimport)  short   BeaconDataShort(datap * parser);
__declspec(dllimport)  int     BeaconDataLength(datap * parser);
__declspec(dllimport)  char *  BeaconDataExtract(datap * parser, int * size);

/* format API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

__declspec(dllimport)  void    BeaconFormatAlloc(formatp * format, int maxsz);
__declspec(dllimport)  void    BeaconFormatReset(formatp * format);
__declspec(dllimport)  void    BeaconFormatFree(formatp * format);
__declspec(dllimport)  void    BeaconFormatAppend(formatp * format, char * text, int len);
__declspec(dllimport)  void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
__declspec(dllimport)  char *  BeaconFormatToString(formatp * format, int * size);
__declspec(dllimport)  void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

__declspec(dllimport)  void   BeaconPrintf(int type, char * fmt, ...);
__declspec(dllimport)  void   BeaconOutput(int type, char * data, int len);

/* Token Functions */
__declspec(dllimport)  bool   BeaconUseToken(HANDLE token);
__declspec(dllimport)  void   BeaconRevertToken();
__declspec(dllimport)  BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
__declspec(dllimport)  void   BeaconGetSpawnTo(bool x86, char * buffer, int length);
__declspec(dllimport)  void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
__declspec(dllimport)  void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
__declspec(dllimport)  void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
__declspec(dllimport)  BOOL   toWideChar(char * src, wchar_t * dst, int max);

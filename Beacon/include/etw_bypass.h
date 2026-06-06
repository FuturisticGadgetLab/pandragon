#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "resolver.h"

#ifdef __cplusplus
extern "C" {
#endif

// ETW bypass state structure
typedef struct _ETW_BYPASS_STATE {
    bool enabled;                    // ETW bypass active
    int drIndex;                     // DR register used (1-3)
    void* ntTraceEventAddr;          // NtTraceEvent function address
    void* retGadget;                 // RET gadget address
    void* vehHandler;                // Reserved for future use
} ETW_BYPASS_STATE;

// Enable ETW bypass via HWBP
bool ETW_Enable(functionTable* funcTable);

// Disable ETW bypass (remove HWBP)
bool ETW_Disable(void);

// Check if ETW bypass is enabled
bool ETW_IsEnabled(void);

// Get ETW state (for VEH integration)
ETW_BYPASS_STATE* ETW_GetState(void);

// ETW VEH handler (called from main VEH)
LONG ETW_HandleException(EXCEPTION_POINTERS* ExceptionInfo);

#ifdef __cplusplus
}
#endif

#pragma once
#include <windows.h>

void* process_symbol(char* symbolstring);
bool initBOFEngineTable(functionTable* nt);
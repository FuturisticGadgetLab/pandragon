#ifndef WINHTTP_H
#define WINHTTP_H

#include "../../include/resolver.h"
#include "../../include/utils.h"
#include <utility>

std::pair<void*, size_t> CurlLikeRequest(functionTable* funcTable, LPCWSTR domain, LPCWSTR path, LPCWSTR userAgent, INTERNET_PORT port);

// Extended version supporting POST with body data
std::pair<void*, size_t> CurlLikeRequestWithBody(functionTable* funcTable, LPCWSTR domain, LPCWSTR path, LPCWSTR userAgent, INTERNET_PORT port, const void* bodyData, size_t bodyLen);

#endif
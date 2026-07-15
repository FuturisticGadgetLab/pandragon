ARCH ?= x86_64
ifeq ($(ARCH),x86_64)
    TARGET = x86_64-w64-windows-gnu
    OUTPUT_SUFFIX =
    CXXFLAGS_ARCH = -maes
    ENTRY = __start
else ifeq ($(ARCH),x86)
    TARGET = i686-w64-windows-gnu
    OUTPUT_SUFFIX = _x86
    CXXFLAGS_ARCH = -maes -msse2
    ENTRY = __start
else
    $(error Unsupported ARCH '$(ARCH)'. Use 'x86_64' or 'x86')
endif

OUTPUT_DIR = build/beacon
OUTPUT = $(OUTPUT_DIR)/pandragon$(OUTPUT_SUFFIX).exe

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

# BUILD_TIME_RANDOM_SEED is now evaluated per translation unit (see pattern
# rule below).  Each .cpp gets a unique seed, so strings compiled in different
# TUs use different LCG streams even for identical literals.  The magic LCG
# derivation constants stay compile-time only, never visible in the binary.

CXXFLAGS = -target $(TARGET) -nostdlib -nostartfiles -Oz -std=c++20 \
           $(CXXFLAGS_ARCH) -fno-builtin -fno-threadsafe-statics -fno-exceptions \
           -Wall -flto=full -MD -MP -ffunction-sections -fdata-sections \
           -fvisibility=hidden -Wl,--build-id=none \
           -fno-unwind-tables -fno-asynchronous-unwind-tables \
           -I$(OUTPUT_DIR)/.. -I. -Iinclude -IBeacon/include

_ALBEDO := $(or $(filter 1,$(ALBEDO)),$(filter 1,$(USE_ALBEDO)))
ifneq ($(_ALBEDO),1)
    CXX = clang++
else
    CXX = albedo-clang
    CXXFLAGS := $(filter-out -flto=full, $(CXXFLAGS))
    override ALBEDO := albedo
    export ALBEDO
    export ALBEDO_PRESET = offensive-prod
    export ALBEDO_PREOPT = Oz
    ALBEDO_REAL_CC ?= $(CXX:albedo-clang=clang++-18)
    export ALBEDO_REAL_CC
endif

LDFLAGS = -fuse-ld=lld \
          -Wl,--entry=$(ENTRY) -Wl,--gc-sections -Wl,-s \
          -Wl,--no-dynamicbase -Wl,--subsystem,console

SOURCES = $(shell find Beacon -name '*.cpp' ! -path '*/test/*' \
              ! -name 'config.cpp' ! -name 'doh.cpp' | sort)

OBJECTS = $(SOURCES:%.cpp=$(OUTPUT_DIR)/%.o)
DEPS = $(SOURCES:%.cpp=$(OUTPUT_DIR)/%.d)

ifeq ($(DEBUG),1)
    CXXFLAGS += -DDEBUG
    OUTPUT = $(OUTPUT_DIR)/pandragon_debug.exe
endif

.PHONY: all clean setup keys test ssl-cert \
        server gui run-server run-server-args run-gui

all: check-debug-consistency keys $(OUTPUT)
	$(ECHO) "[+] Beacon ($(ARCH)): $(OUTPUT)"

-include $(DEPS)

# ── Guard: config debug_mode must match compile-time DEBUG ──
# If there's a mismatch (or the config is missing/invalid), refuse to build.
.PHONY: check-debug-consistency
check-debug-consistency:
	@$(PYTHON) tools/check_debug_config.py $(CONFIG_FILE) $(DEBUG)

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

$(OUTPUT): $(OBJECTS) | $(GENERATED_CONFIG)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

$(OUTPUT_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) \
	    -DBUILD_TIME_RANDOM_SEED=$$(python3 -c "import random; print(hex(random.randrange(1<<64)))") \
	    -c $< -o $@

$(OBJECTS): | $(GENERATED_CONFIG)

setup:
	@git submodule update --init --recursive 2>/dev/null || true
	$(MAKE) -C server setup
	$(MAKE) -C gui venv
	$(ECHO) "[+] All set.  make server | make gui | make"

server:
	$(MAKE) -C server build

gui:
	$(MAKE) -C gui build

# ── Docker ─────────────────────────────────────────────────────────

docker-build:
	docker compose build

docker-run:
	docker compose up -d

docker-stop:
	docker compose down

docker-logs:
	docker compose logs -f

docker-restart: docker-stop docker-run

# ── Server (local) ─────────────────────────────────────────────────

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

.DELETE_ON_ERROR:

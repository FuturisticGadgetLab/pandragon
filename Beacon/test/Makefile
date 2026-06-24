# Cross-compile (Linux -> Windows via Wine):               make
# Native Windows (MinGW):                                  make NATIVE=1
# Custom toolchain:                                        make CXX=... RUNNER=... CXXFLAGS="..." LDFLAGS="..."

ifeq ($(NATIVE),1)
  CXX      = g++
  RUNNER   =
  CXXFLAGS = -std=c++20 -Wall -maes -I../include -I. \
             -DBUILD_TIME_RANDOM_SEED=0xdeadbeef
  LDFLAGS  = -static -static-libstdc++
else
  CXX      = clang++
  RUNNER   = wine
  CXXFLAGS = -target x86_64-w64-windows-gnu -std=c++20 -Oz -Wall -maes \
             -I../include -I. \
             -DBUILD_TIME_RANDOM_SEED=0xdeadbeef -Wno-writable-strings
  LDFLAGS  = -static -static-libstdc++ -Wl,--subsystem,console 
endif

STUBS = test_stubs.cpp

.PHONY: all clean

TESTS = test_sleep_utils test_net_crypto test_pkcs7 test_base64 test_bof_cache test_cookie

all: $(addsuffix .exe,$(TESTS))
	@set -e; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		$(RUNNER) ./$$t.exe; \
		echo; \
	done

test_sleep_utils.exe: test_sleep_utils.cpp ../core/sleep_utils.cpp $(STUBS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

test_net_crypto.exe: test_net_crypto.cpp ../libs/network/net_crypto.cpp ../libs/bastia/bastia.cpp $(STUBS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

test_pkcs7.exe: test_pkcs7.cpp $(STUBS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

test_base64.exe: test_base64.cpp $(STUBS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

test_bof_cache.exe: test_bof_cache.cpp ../core/coff/bof_cache.cpp $(STUBS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

test_cookie.exe: test_cookie.cpp $(STUBS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(addsuffix .exe,$(TESTS))

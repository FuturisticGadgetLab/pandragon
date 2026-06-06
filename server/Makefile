# Pandragon Server. Build, test, and development automation
#
# Usage:
#   make              # default: build-parser
#   make build-parser # compile Cython .pyx -> .so (setup.py build_ext --inplace)
#   make test         # build-parser + run pytest
#   make clean        # remove .so, .c, build artifacts

PYTHON   = python3
VENV     = venv
PIP      = $(VENV)/bin/pip
ACTIVATE = . $(VENV)/bin/activate

.PHONY: default build-parser test clean

default: build-parser

venv:
	@test -d $(VENV) || (echo "[*] Creating venv..." && $(PYTHON) -m venv $(VENV) && $(PIP) install -r requirements.txt)

build-parser: venv
	$(ACTIVATE) && python setup.py build_ext --inplace
	@echo "[+] Parser .so ready"

test: build-parser
	$(ACTIVATE) && python -m pytest tests/ -v

clean:
	rm -rf build/ $(VENV)
	rm -f protocol/parser.c protocol/parser*.so
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true

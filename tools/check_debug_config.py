import json
import sys

config_file = sys.argv[1]
debug_val = sys.argv[2] if len(sys.argv) > 2 else ''

try:
    with open(config_file) as f:
        cfg = json.load(f)
except FileNotFoundError:
    sys.exit(f'ERROR: {config_file} not found')
except json.JSONDecodeError as e:
    sys.exit(f'ERROR: invalid JSON in {config_file}: {e}')

dm = cfg.get('options', {}).get('debug_mode')
if dm is None:
    sys.exit(f'ERROR: debug_mode not found in options in {config_file}')

want = 1 if dm else 0
have = 1 if debug_val == '1' else 0

if want != have:
    sys.exit(
        f'ERROR: config debug_mode={str(dm).lower()} '
        f'but compile-time DEBUG={have} '
        f'(run make DEBUG={want})'
    )

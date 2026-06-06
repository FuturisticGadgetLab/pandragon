"""
Pandragon Teamserver Configuration

Loads configuration from JSON file.
Environment variables can override config file values after loading.
"""

import os
import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional, List, Dict, Any


# =============================================================================
# Config Loading
# =============================================================================

_config: Optional[Dict[str, Any]] = None
_log: Optional[logging.Logger] = None


def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    Load configuration from JSON file.
    Must point to an existing file
    """
    global _config

    if config_path is None:
        config_path = "config.json"

    if not os.path.exists(config_path):
        print(f"[!] Config file not found: {config_path}")
        print(f"    Create {config_path} or pass --config <path>")
        sys.exit(1)

    file_size = os.path.getsize(config_path)
    MAX_CONFIG_SIZE = 1024 * 1024
    if file_size > MAX_CONFIG_SIZE:
        print(f"[!] Config file too large: {file_size} bytes (max: {MAX_CONFIG_SIZE})")
        sys.exit(1)

    with open(config_path, 'r') as f:
        _config = json.load(f)

    return _config


def get_config() -> Dict[str, Any]:
    """Get the loaded configuration."""
    if _config is None:
        raise RuntimeError("load_config() must be called before get_config()")
    return _config


# =============================================================================
# Convenience Accessors  (inline .get() defaults protect against omitted keys)
# =============================================================================

def get_session_timeout() -> int:
    return get_config().get("server", {}).get("session_timeout_minutes", 30)


def get_download_dir() -> str:
    return get_config().get("beacon", {}).get("download_directory", "/tmp/pandragon_downloads")


# =============================================================================
# Listener Configuration
# =============================================================================

def get_listeners() -> List[Dict[str, Any]]:
    return get_config().get("listeners", [])


def resolve_effective_listeners() -> List[Dict[str, Any]]:
    """Resolve the effective list of listeners."""
    listeners = get_listeners()

    if not listeners:
        server = get_config().get("server", {})
        return [{
            "name": "legacy_https",
            "protocol": "https",
            "host": server.get("host", "0.0.0.0"),
            "port": server.get("port", 6767),
            "ssl_cert": server.get("ssl_cert", "ssl/cert.pem"),
            "ssl_key": server.get("ssl_key", "ssl/key.pem"),
            "primary": True,
            "beacon_enabled": True,
        }]

    effective = []
    primary_found = False

    for listener in listeners:
        entry = {
            "name": listener.get("name", "unnamed"),
            "protocol": listener.get("protocol", "https"),
            "host": listener.get("host", "0.0.0.0"),
            "port": listener.get("port", 443),
            "ssl_cert": listener.get("ssl_cert"),
            "ssl_key": listener.get("ssl_key"),
            "primary": listener.get("primary", False),
            "beacon_enabled": listener.get("beacon_enabled", True),
        }
        effective.append(entry)

        if entry["primary"]:
            primary_found = True

    if not primary_found and effective:
        for entry in effective:
            if entry["protocol"] == "https":
                entry["primary"] = True
                primary_found = True
                break

        if not primary_found:
            effective[0]["primary"] = True

    return effective


def get_beacons_file() -> Optional[str]:
    return get_config().get("beacons_file")


def get_primary_listener() -> Optional[Dict[str, Any]]:
    listeners = resolve_effective_listeners()
    for listener in listeners:
        if listener.get("primary"):
            return listener
    return None


# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging() -> logging.Logger:
    """Configure application logging with file and console handlers."""
    global _log

    log_config = get_config().get("logging", {})
    logger = logging.getLogger('pandragon')
    logger.handlers.clear()

    if not log_config.get("enabled", True):
        logger.addHandler(logging.NullHandler())
        _log = logger
        return logger

    log_level = getattr(logging, log_config.get("level", "INFO").upper())
    logger.setLevel(log_level)

    formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    log_target = log_config.get("target", "")
    if log_target:
        try:
            file_handler = RotatingFileHandler(
                log_target,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not create log file handler: {e}", file=sys.stderr)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    _log = logger
    return logger


def get_logger() -> logging.Logger:
    global _log
    if _log is None:
        if _config is None:
            # Import-time logger before load_config() is called
            _log = logging.getLogger('pandragon')
            _log.setLevel(logging.INFO)
            if not _log.handlers:
                _log.addHandler(logging.StreamHandler())
        else:
            setup_logging()
    return _log

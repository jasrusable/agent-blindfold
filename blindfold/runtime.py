"""Everything a hook call needs: config, known secrets and the masker.

A broken config must not switch masking off, and must not brick the session
either (every tool refused, including the edit that would fix it). So it falls
back to the defaults, which only ever mask more: no allow-list, no disabled
rules. The one thing lost is extra known-secret files the config listed, which
is why the fallback warns on every call until it's fixed.
"""

import os
from dataclasses import dataclass
from typing import Dict, Optional

from .config import Config, fingerprint_key, load_config
from .known import KnownLoad, KnownSecret, load_known_secrets
from .mask import Masker

KEY_NAME = "BLINDFOLD_FINGERPRINT_KEY"


@dataclass(frozen=True)
class Runtime:
    config: Config
    masker: Masker
    known: KnownLoad
    warning: Optional[str] = None


def load_runtime(environ: Optional[Dict[str, str]] = None) -> Runtime:
    warning = None
    try:
        config = load_config()
    except Exception as error:  # noqa: BLE001 - any config failure takes the safe fallback
        config = Config()
        warning = (
            f"blindfold's config is invalid ({type(error).__name__}: {error}), so the defaults are in use. "
            "Masking is on, but known-secret files the config adds are not loaded. "
            "Tell the user to fix it (`blindfold doctor`)."
        )
    return build_runtime(config, environ, warning)


def build_runtime(config: Config, environ: Optional[Dict[str, str]] = None, warning: Optional[str] = None) -> Runtime:
    known = load_known_secrets(
        config.known_secret_files,
        environ=os.environ if environ is None else environ,
        min_length=config.min_known_length,
    )
    key = fingerprint_key()
    masker = Masker(
        # The fingerprint key is a secret too: with it, ids confirm guesses.
        known=[*known.secrets, KnownSecret(key, KEY_NAME)],
        key=key.encode("ascii"),
        entropy=config.entropy,
        min_entropy=config.min_entropy,
        allow=config.allow,
        allow_ids=config.allow_ids,
        disabled_rules=config.disabled_rules,
    )
    return Runtime(config, masker, known, warning)

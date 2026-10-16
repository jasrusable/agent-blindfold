from blindfold.config import Config
from blindfold.events import Event
from blindfold.handlers import handle
from blindfold.known import KnownLoad
from blindfold.runtime import Runtime

CFG = Config(use_default_known_secret_files=False)


def runtime(masker, config=CFG, warning=None):
    return Runtime(config, masker, KnownLoad([], [], []), warning)


def reply(raw, masker, config=CFG, warning=None):
    return handle(Event(raw), runtime(masker, config, warning))

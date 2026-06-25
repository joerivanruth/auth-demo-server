from abc import ABC, abstractmethod
import importlib
import sys
from typing import Any, Optional, Tuple

from pymonetdb.target import Target

from credentials import CredStore


class ClientSide:
    @abstractmethod
    def respond(self, token: bytes) -> bytes:
        pass

    def wrap_up(self, additional_data: Optional[bytes]) -> Optional[str]:
        return None


class ServerSide:
    authcid: Optional[str]
    authzid: Optional[str]

    @abstractmethod
    def initial_challenge(self) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def next_challenge(self, token: bytes) -> Tuple[bool, Optional[bytes]]:
        raise NotImplementedError()


class Mechanism(ABC):
    wire_name: str
    client_first: bool

    @abstractmethod
    def start_client(self, *, target: Target) -> ClientSide:
        raise NotImplementedError()

    @abstractmethod
    def start_server(self, *, credstore: CredStore, opts: dict[str, Any]) -> ServerSide:
        raise NotImplementedError()


class Reject(Exception):
    client_message: str
    server_side_log_message: str
    authentication_failed = 'Authentication failed'

    def __init__(self, message: Optional[str] = None, public: bool = False):
        if message is None:
            message = self.authentication_failed
        super().__init__(message)
        self.client_message = message if public else self.authentication_failed


# ruff: disable[E402]
from credentials import CredStore
from mechanisms.plain import PlainMechanism
from mechanisms.naive_digest import NaiveDigestMechanism
from mechanisms.classic import ClassicMechanism

MECHANISMS: list[Mechanism] = [
    ClassicMechanism('ripemd160', 'sha512'),
    ClassicMechanism('sha256', 'sha512'),
    NaiveDigestMechanism(),
    PlainMechanism(),
]

__all__ = ['Mechanism', 'Reject', 'ClassicMechanism', 'PlainMechanism', 'NaiveDigestMechanism']


def prepend_mechanism_if_available(reqmods: list[str], modname: str, classname: str):
    assert isinstance(reqmods, list)
    for m in reqmods:
        try:
            importlib.import_module(m)
        except ModuleNotFoundError:
            return
    mod = importlib.import_module(modname)
    constructor = getattr(mod, classname)
    mech = constructor()
    setattr(sys.modules[__name__], constructor.__name__, constructor)
    MECHANISMS.insert(0, mech)
    __all__.append(constructor.__name__)


prepend_mechanism_if_available(['scramp'], 'mechanisms.naive_scram', 'NaiveScramMechanism')
prepend_mechanism_if_available(['gssapi'], 'mechanisms.naive_gssapi', 'NaiveGSSAPIMechanism')

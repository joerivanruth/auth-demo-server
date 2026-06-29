from abc import ABC, abstractmethod
from enum import Enum
import enum
import importlib
import sys
from typing import Any, Optional, Tuple

from pymonetdb.target import Target

from credentials import UserCreds


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


class Style(Enum):
    PASSWORD = enum.auto()
    KERBEROS = enum.auto()


class Mechanism(ABC):
    wire_name: str
    client_first: bool
    style: Style = Style.PASSWORD

    @abstractmethod
    def start_client(self, *, target: Target) -> ClientSide:
        raise NotImplementedError()

    @abstractmethod
    def start_server(self, *, usercreds: UserCreds, opts: dict[str, Any]) -> ServerSide:
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


def pick_mechanisms(mechnames: list[str], filter=None) -> dict[str, Mechanism]:
    mechnames = [m for m in mechnames or [] if m]
    by_name = dict()
    for m in MECHANISMS:
        assert m.wire_name not in by_name, m.wire_name
        if filter is None or filter(m):
            by_name[m.wire_name] = m
    if not mechnames:
        return by_name
    result = dict()
    for comma_separated in mechnames:
        for name in comma_separated.split(','):
            name = name.upper().strip()
            if name not in by_name:
                continue
            result[name] = by_name[name]
    return result


# ruff: disable[E401,E402]
from mechanisms.plain import PlainMechanism
from mechanisms.classic import ClassicMechanism

MECHANISMS: list[Mechanism] = [
    ClassicMechanism('sha512', 'sha512'),
    ClassicMechanism('sha256', 'sha512'),
    ClassicMechanism('ripemd160', 'sha512'),
    PlainMechanism(),
]

__all__ = ['Mechanism', 'Reject', 'ClassicMechanism', 'PlainMechanism']


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
prepend_mechanism_if_available(['gssapi'], 'mechanisms.gssapi', 'GSSAPIMechanism')

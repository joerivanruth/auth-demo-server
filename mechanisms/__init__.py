from abc import ABC, abstractmethod
import importlib
from typing import Optional

from pymonetdb.target import Target

from credentials import CredStore


class ClientSide:
    @abstractmethod
    def respond(self, token: bytes) -> bytes:
        pass


class ServerSide:
    @abstractmethod
    def initial_challenge(self) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def next_challenge(self, token: bytes) -> Optional[bytes]:
        raise NotImplementedError()


class Mechanism(ABC):
    wire_name: str
    client_first: bool

    @abstractmethod
    def start_client(self, target: Target) -> ClientSide:
        raise NotImplementedError()

    @abstractmethod
    def start_server(self, user: str, credstore: CredStore) -> ServerSide:
        raise NotImplementedError()


class Reject(Exception):
    pass


def invalid_credentials():
    return Reject('invalid credentials')


# ruff: disable[E402]
from credentials import CredStore
from mechanisms.plain import PlainMechanism
from mechanisms.digest import DigestMechanism

MECHANISMS = [PlainMechanism, DigestMechanism]

have_gssapi = False
try:
    importlib.import_module('gssapi')
    have_gssapi = True
except ModuleNotFoundError:
    pass
if have_gssapi:
    from mechanisms.naive_gssapi import NaiveGSSAPIMechanism

    MECHANISMS.append(NaiveGSSAPIMechanism)


__all__ = ['Mechanism', 'Reject'] + [m.__name__ for m in MECHANISMS]

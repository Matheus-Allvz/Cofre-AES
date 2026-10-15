"""S2: no máximo ARGON2_CONCORRENCIA hashes/verificações Argon2 ao mesmo tempo no processo."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException

from app import seguranca


class HasherLento:
    """Conta quantas verificações rodam juntas."""

    def __init__(self):
        self.agora = self.pico = 0
        self.trava = threading.Lock()

    def _rodar(self):
        with self.trava:
            self.agora += 1
            self.pico = max(self.pico, self.agora)
        time.sleep(0.05)
        with self.trava:
            self.agora -= 1

    def verify(self, *_):
        self._rodar()
        return True

    def hash(self, *_):
        self._rodar()
        return "$argon2id$falso"


def test_no_maximo_n_argon2_simultaneos(monkeypatch):
    lento = HasherLento()
    monkeypatch.setattr(seguranca, "HASHER", lento)
    segredo = bytes(range(32))
    with ThreadPoolExecutor(24) as ex:
        list(ex.map(lambda i: seguranca.verificar_auth("x", segredo, b"a" * 32), range(12)))
        list(ex.map(lambda i: seguranca.hash_auth(segredo, b"a" * 32), range(12)))
    assert lento.pico == seguranca.ARGON2_CONCORRENCIA == 2


def test_espera_longa_vira_503(monkeypatch):
    monkeypatch.setattr(seguranca, "_argon2", threading.BoundedSemaphore(1))
    monkeypatch.setattr(seguranca, "ARGON2_ESPERA_S", 0.01)
    seguranca._argon2.acquire()  # alguém ocupando a única vaga
    with pytest.raises(HTTPException) as erro:
        seguranca.verificar_auth("x", bytes(32), bytes(32))
    assert (erro.value.status_code, erro.value.detail) == (503, "ocupado")

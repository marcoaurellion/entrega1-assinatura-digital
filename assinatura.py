"""Entrega 1 - Assinatura digital com Ed25519.

Usa a biblioteca consolidada `cryptography`. Nenhum algoritmo é implementado
manualmente.
"""
import base64
import binascii
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALGORITMO = "Ed25519"


def gerar_par_chaves(pasta, senha):
    """Gera o par de chaves e salva em PEM.

    A chave privada é gravada CIFRADA com senha e com permissão 0600.
    A chave pública é gravada em claro (pode ser distribuída).
    """
    if not senha:
        raise ValueError("A senha da chave privada não pode ser vazia.")
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)

    privada = Ed25519PrivateKey.generate()
    publica = privada.public_key()

    pem_privada = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(senha.encode()),
    )
    pem_publica = publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    caminho_priv = pasta / "privada.pem"
    caminho_pub = pasta / "publica.pem"
    # abre com 0600 desde a criação (sem janela de exposição)
    fd = os.open(caminho_priv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem_privada)
    caminho_pub.write_bytes(pem_publica)
    return caminho_priv, caminho_pub


def carregar_privada(caminho, senha):
    return serialization.load_pem_private_key(
        Path(caminho).read_bytes(), password=senha.encode()
    )


def carregar_publica(caminho):
    return serialization.load_pem_public_key(Path(caminho).read_bytes())


def assinar(mensagem, chave_privada):
    """Assina a mensagem e devolve um 'envelope' (dict) pronto para enviar."""
    dados = mensagem.encode("utf-8")
    assinatura = chave_privada.sign(dados)
    return {
        "algoritmo": ALGORITMO,
        "mensagem": mensagem,
        "assinatura": base64.b64encode(assinatura).decode("ascii"),
    }


def verificar(envelope, chave_publica):
    """Devolve True se a assinatura for válida; False em qualquer outro caso."""
    try:
        if envelope.get("algoritmo") != ALGORITMO:
            return False
        dados = envelope["mensagem"].encode("utf-8")
        assinatura = base64.b64decode(envelope["assinatura"], validate=True)
        chave_publica.verify(assinatura, dados)
        return True
    except (InvalidSignature, KeyError, TypeError, AttributeError,
            ValueError, binascii.Error):
        return False


def salvar_envelope(envelope, caminho):
    Path(caminho).write_text(json.dumps(envelope, ensure_ascii=False, indent=2),
                             encoding="utf-8")


def ler_envelope(caminho):
    return json.loads(Path(caminho).read_text(encoding="utf-8"))

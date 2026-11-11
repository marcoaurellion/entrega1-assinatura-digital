"""Linha de comando da Entrega 1 (assinatura digital Ed25519).

Uso:
  python main.py gerar-chaves
  python main.py assinar "texto" -o mensagem.json
  python main.py verificar mensagem.json
  python main.py demo

A senha da chave privada vem da variável CHAVE_SENHA ou é pedida no terminal.
"""
import argparse
import getpass
import os
import sys

import assinatura as ass

PASTA_CHAVES = "chaves"


def obter_senha():
    return os.environ.get("CHAVE_SENHA") or getpass.getpass("Senha da chave privada: ")


def cmd_gerar(_):
    priv, pub = ass.gerar_par_chaves(PASTA_CHAVES, obter_senha())
    print(f"Chave privada (cifrada): {priv}")
    print(f"Chave pública:           {pub}")


def cmd_assinar(args):
    chave = ass.carregar_privada(f"{PASTA_CHAVES}/privada.pem", obter_senha())
    env = ass.assinar(args.mensagem, chave)
    ass.salvar_envelope(env, args.saida)
    print(f"Mensagem assinada e salva em {args.saida}")


def cmd_verificar(args):
    pub = ass.carregar_publica(f"{PASTA_CHAVES}/publica.pem")
    ok = ass.verificar(ass.ler_envelope(args.arquivo), pub)
    print("ASSINATURA VÁLIDA" if ok else "ASSINATURA INVÁLIDA")
    return 0 if ok else 1


def cmd_demo(_):
    import tempfile
    senha = "senha-de-demonstracao"  # só para a demo; nunca use em produção
    with tempfile.TemporaryDirectory() as pasta:
        _, pub_path = ass.gerar_par_chaves(pasta, senha)
        priv = ass.carregar_privada(f"{pasta}/privada.pem", senha)
        pub = ass.carregar_publica(pub_path)

        print("1) Mensagem original assinada")
        env = ass.assinar("Transferir R$ 100,00 para a conta A", priv)
        print(f"   mensagem:   {env['mensagem']}")
        print(f"   assinatura: {env['assinatura'][:32]}...")
        print(f"   verificação: {'VÁLIDA' if ass.verificar(env, pub) else 'INVÁLIDA'}")

        print("\n2) Mensagem adulterada (valor mudou)")
        adulterada = dict(env, mensagem="Transferir R$ 9000,00 para a conta B")
        print(f"   mensagem:   {adulterada['mensagem']}")
        print(f"   verificação: {'VÁLIDA' if ass.verificar(adulterada, pub) else 'INVÁLIDA'}")

        print("\n3) Assinatura adulterada (1 caractere trocado)")
        sig = env["assinatura"]
        trocado = ("A" if sig[0] != "A" else "B") + sig[1:]
        adulterada2 = dict(env, assinatura=trocado)
        print(f"   verificação: {'VÁLIDA' if ass.verificar(adulterada2, pub) else 'INVÁLIDA'}")

        print("\n4) Chave pública de OUTRA pessoa (falso remetente)")
        outra_pub = ass.Ed25519PrivateKey.generate().public_key()
        print(f"   verificação: {'VÁLIDA' if ass.verificar(env, outra_pub) else 'INVÁLIDA'}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gerar-chaves").set_defaults(f=cmd_gerar)
    a = sub.add_parser("assinar")
    a.add_argument("mensagem")
    a.add_argument("-o", "--saida", default="mensagem.json")
    a.set_defaults(f=cmd_assinar)
    v = sub.add_parser("verificar")
    v.add_argument("arquivo")
    v.set_defaults(f=cmd_verificar)
    sub.add_parser("demo").set_defaults(f=cmd_demo)
    args = p.parse_args()
    sys.exit(args.f(args) or 0)

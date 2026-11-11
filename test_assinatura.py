import os
import tempfile
import unittest

import assinatura as ass

SENHA = "senha-de-teste"


class TestAssinatura(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        priv_path, pub_path = ass.gerar_par_chaves(self.tmp.name, SENHA)
        self.priv_path = priv_path
        self.priv = ass.carregar_privada(priv_path, SENHA)
        self.pub = ass.carregar_publica(pub_path)
        self.env = ass.assinar("mensagem de teste", self.priv)

    # --- testes positivos ---
    def test_assinatura_valida(self):
        self.assertTrue(ass.verificar(self.env, self.pub))

    def test_acentos_e_unicode(self):
        env = ass.assinar("ação — çãõ ✓", self.priv)
        self.assertTrue(ass.verificar(env, self.pub))

    # --- testes negativos ---
    def test_mensagem_adulterada(self):
        env = dict(self.env, mensagem="mensagem de teste!")
        self.assertFalse(ass.verificar(env, self.pub))

    def test_assinatura_adulterada(self):
        sig = self.env["assinatura"]
        env = dict(self.env, assinatura=("A" if sig[0] != "A" else "B") + sig[1:])
        self.assertFalse(ass.verificar(env, self.pub))

    def test_chave_publica_errada(self):
        outra = ass.Ed25519PrivateKey.generate().public_key()
        self.assertFalse(ass.verificar(self.env, outra))

    def test_envelope_malformado(self):
        self.assertFalse(ass.verificar({}, self.pub))
        self.assertFalse(ass.verificar({"mensagem": "x"}, self.pub))
        self.assertFalse(ass.verificar(dict(self.env, assinatura="@@@"), self.pub))

    def test_algoritmo_diferente_rejeitado(self):
        self.assertFalse(ass.verificar(dict(self.env, algoritmo="none"), self.pub))

    # --- gestão de chaves ---
    def test_privada_gravada_cifrada(self):
        conteudo = self.priv_path.read_text()
        self.assertIn("ENCRYPTED", conteudo)

    def test_senha_errada_nao_abre_privada(self):
        with self.assertRaises(ValueError):
            ass.carregar_privada(self.priv_path, "senha-errada")

    def test_senha_vazia_recusada(self):
        with self.assertRaises(ValueError):
            ass.gerar_par_chaves(self.tmp.name, "")

    @unittest.skipIf(os.name == "nt", "permissão POSIX 0600 não se aplica ao Windows")
    def test_permissao_da_privada(self):
        self.assertEqual(self.priv_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
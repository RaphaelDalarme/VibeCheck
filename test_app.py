import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app


class TestVibeCheck(unittest.TestCase):
    def setUp(self):
        self.pasta = tempfile.TemporaryDirectory()
        self.banco = Path(self.pasta.name) / "teste.db"
        self.app = create_app(self.banco)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        self.pasta.cleanup()

    def criar(self, codigo="senha = 'valor_ficticio'"):
        return self.client.post("/api/analises", json={
            "nome": "Teste",
            "arquivo": "teste.py",
            "codigo": codigo,
        })

    def test_crud_e_persistencia(self):
        resposta = self.criar()
        self.assertEqual(resposta.status_code, 201)
        identificador = resposta.get_json()["id"]
        url = f"/api/analises/{identificador}"
        self.assertEqual(resposta.get_json()["resumo"]["alto"], 1)

        outro_cliente = create_app(self.banco).test_client()
        self.assertEqual(outro_cliente.get(url).status_code, 200)

        resposta = self.client.put(url, json={
            "nome": "Corrigido",
            "arquivo": "teste.py",
            "codigo": "import os\nsenha = os.getenv('APP_PASSWORD')",
        })
        self.assertEqual(resposta.status_code, 200)
        self.assertEqual(resposta.get_json()["resumo"]["total"], 0)

        self.assertEqual(self.client.delete(url).status_code, 204)
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.get("/api/analises").get_json(), [])

    def test_exclusao_remove_achados(self):
        identificador = self.criar().get_json()["id"]
        self.client.delete(f"/api/analises/{identificador}")
        with sqlite3.connect(self.banco) as conexao:
            total = conexao.execute("SELECT COUNT(*) FROM achados").fetchone()[0]
        self.assertEqual(total, 0)

    def test_codigo_invalido_nao_e_salvo(self):
        self.assertEqual(self.criar("def quebrado(").status_code, 422)
        self.assertEqual(self.client.get("/api/analises").get_json(), [])

    def test_comentario_nao_e_execucao(self):
        resposta = self.criar("# eval(entrada)\nprint('Olá')")
        self.assertEqual(resposta.get_json()["resumo"]["total"], 0)

    def test_atualizacao_invalida_preserva_resultado(self):
        identificador = self.criar().get_json()["id"]
        url = f"/api/analises/{identificador}"
        resposta = self.client.put(url, json={
            "nome": "Inválido",
            "arquivo": "teste.py",
            "codigo": "def quebrado(",
        })
        self.assertEqual(resposta.status_code, 422)
        self.assertEqual(
            self.client.get(url).get_json()["resumo"]["alto"], 1
        )


if __name__ == "__main__":
    unittest.main()
import hashlib
import sqlite3
from pathlib import Path

from flask import Flask, abort, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from analisador import AVISO, analisar


BASE = Path(__file__).resolve().parent
LIMITE_CODIGO = 100_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS analises (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    arquivo TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS achados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analise_id INTEGER NOT NULL,
    linha INTEGER NOT NULL,
    regra TEXT NOT NULL,
    risco TEXT NOT NULL CHECK (risco IN ('alto', 'medio')),
    titulo TEXT NOT NULL,
    descricao TEXT NOT NULL,
    recomendacao TEXT NOT NULL,
    FOREIGN KEY (analise_id) REFERENCES analises(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_achados_analise
ON achados(analise_id);
"""


def create_app(database=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=str(database or BASE / "vibecheck.db"),
        MAX_CONTENT_LENGTH=512 * 1024,
    )
    app.json.ensure_ascii = False

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def fechar_banco(erro=None):
        conexao = g.pop("db", None)
        if conexao is not None:
            conexao.close()

    with app.app_context():
        db().executescript(SCHEMA)
        db().commit()

    @app.errorhandler(HTTPException)
    def erro_http(erro):
        return jsonify(erro=erro.description), erro.code

    def obter_registro(identificador):
        registro = db().execute(
            "SELECT * FROM analises WHERE id = ?", (identificador,)
        ).fetchone()
        if registro is None:
            abort(404, description="Análise não encontrada.")
        return dict(registro)

    def relatorio(identificador):
        resultado = obter_registro(identificador)
        resultado["achados"] = [
            dict(item) for item in db().execute(
                """SELECT linha, regra, risco, titulo, descricao, recomendacao
                   FROM achados WHERE analise_id = ?
                   ORDER BY linha, regra""",
                (identificador,),
            ).fetchall()
        ]
        altos = sum(
            item["risco"] == "alto" for item in resultado["achados"]
        )
        medios = len(resultado["achados"]) - altos
        resultado["resumo"] = {
            "total": len(resultado["achados"]),
            "alto": altos,
            "medio": medios,
            "risco_geral": (
                "alto" if altos else
                "medio" if medios else
                "sem achados nas regras aplicadas"
            ),
        }
        resultado["aviso"] = AVISO
        return resultado

    def ler_entrada():
        if request.is_json:
            dados = request.get_json()
            if not isinstance(dados, dict):
                abort(400, description="Envie um objeto JSON.")
            nome = dados.get("nome")
            arquivo = dados.get("arquivo", "codigo.py")
            codigo = dados.get("codigo")
        elif request.mimetype == "multipart/form-data":
            nome = request.form.get("nome")
            enviado = request.files.get("arquivo")
            if enviado is None or not enviado.filename:
                abort(400, description="Selecione um arquivo .py.")
            arquivo = enviado.filename
            conteudo = enviado.read(LIMITE_CODIGO + 1)
            if len(conteudo) > LIMITE_CODIGO:
                abort(413, description="Código maior que 100 KB.")
            try:
                codigo = conteudo.decode("utf-8-sig")
            except UnicodeDecodeError:
                abort(400, description="O arquivo deve usar UTF-8.")
        else:
            abort(415, description="Use JSON ou multipart/form-data.")

        if not isinstance(nome, str) or not 1 <= len(nome.strip()) <= 100:
            abort(400, description="Nome obrigatório, com até 100 caracteres.")
        if not isinstance(arquivo, str) or not arquivo.lower().endswith(".py"):
            abort(400, description="Esta versão aceita apenas arquivos .py.")
        if not isinstance(codigo, str) or not codigo.strip():
            abort(400, description="Informe um código Python não vazio.")
        if len(codigo.encode("utf-8")) > LIMITE_CODIGO:
            abort(413, description="Código maior que 100 KB.")

        try:
            achados = analisar(codigo)
        except ValueError as erro:
            abort(422, description=str(erro))

        return {
            "nome": nome.strip(),
            "arquivo": secure_filename(arquivo)[:150] or "codigo.py",
            "sha256": hashlib.sha256(codigo.encode("utf-8")).hexdigest(),
            "achados": achados,
        }

    def salvar_achados(conexao, identificador, achados):
        conexao.executemany(
            """INSERT INTO achados
               (analise_id, linha, regra, risco, titulo, descricao, recomendacao)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    identificador, item["linha"], item["regra"],
                    item["risco"], item["titulo"], item["descricao"],
                    item["recomendacao"],
                )
                for item in achados
            ],
        )

    @app.get("/")
    def inicio():
        return render_template("index.html")

    @app.get("/api/analises")
    def listar():
        registros = db().execute(
            """SELECT a.*,
                      COUNT(v.id) AS total,
                      COALESCE(SUM(v.risco = 'alto'), 0) AS alto,
                      COALESCE(SUM(v.risco = 'medio'), 0) AS medio
               FROM analises a
               LEFT JOIN achados v ON v.analise_id = a.id
               GROUP BY a.id
               ORDER BY a.id DESC"""
        ).fetchall()
        return jsonify([dict(item) for item in registros])

    @app.get("/api/analises/<int:identificador>")
    def consultar(identificador):
        return jsonify(relatorio(identificador))

    @app.get("/api/analises/<int:identificador>/relatorio")
    def exportar(identificador):
        resposta = jsonify(relatorio(identificador))
        resposta.headers["Content-Disposition"] = (
            f'attachment; filename="analise-{identificador}.json"'
        )
        return resposta

    @app.post("/api/analises")
    def criar():
        entrada = ler_entrada()
        conexao = db()
        with conexao:
            cursor = conexao.execute(
                """INSERT INTO analises (nome, arquivo, sha256)
                   VALUES (?, ?, ?)""",
                (entrada["nome"], entrada["arquivo"], entrada["sha256"]),
            )
            identificador = cursor.lastrowid
            salvar_achados(conexao, identificador, entrada["achados"])

        return (
            jsonify(relatorio(identificador)),
            201,
            {"Location": f"/api/analises/{identificador}"},
        )

    @app.put("/api/analises/<int:identificador>")
    def atualizar(identificador):
        obter_registro(identificador)
        entrada = ler_entrada()
        conexao = db()
        with conexao:
            conexao.execute(
                """UPDATE analises
                   SET nome = ?, arquivo = ?, sha256 = ?,
                       atualizado_em = CURRENT_TIMESTAMP
                   WHERE id = ?""",
                (
                    entrada["nome"], entrada["arquivo"],
                    entrada["sha256"], identificador,
                ),
            )
            conexao.execute(
                "DELETE FROM achados WHERE analise_id = ?", (identificador,)
            )
            salvar_achados(conexao, identificador, entrada["achados"])
        return jsonify(relatorio(identificador))

    @app.delete("/api/analises/<int:identificador>")
    def excluir(identificador):
        obter_registro(identificador)
        conexao = db()
        with conexao:
            conexao.execute(
                "DELETE FROM analises WHERE id = ?", (identificador,)
            )
        return "", 204

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
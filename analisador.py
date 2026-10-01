import ast
import re


AVISO = (
    "Análise estática limitada às regras deste protótipo. "
    "Ausência de achados não comprova segurança."
)


def analisar(codigo):
    try:
        arvore = ast.parse(codigo)
    except (SyntaxError, ValueError, RecursionError) as erro:
        linha = getattr(erro, "lineno", None)
        raise ValueError(
            f"Código Python inválido ou complexo demais. Linha: {linha}."
        ) from erro

    achados = []
    registrados = set()
    aliases = {}
    variaveis_dinamicas = set()

    def nome(no):
        if isinstance(no, ast.Name):
            return aliases.get(no.id, no.id)
        if isinstance(no, ast.Attribute):
            return f"{nome(no.value)}.{no.attr}"
        return ""

    def registrar(no, regra, risco, titulo, descricao, recomendacao):
        chave = (getattr(no, "lineno", 1), regra)
        if chave in registrados:
            return
        registrados.add(chave)
        achados.append({
            "linha": chave[0],
            "regra": regra,
            "risco": risco,
            "titulo": titulo,
            "descricao": descricao,
            "recomendacao": recomendacao,
        })

    # Resolve formas comuns de importação, inclusive aliases.
    for no in ast.walk(arvore):
        if isinstance(no, ast.Import):
            for item in no.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(no, ast.ImportFrom):
            for item in no.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = (
                        f"{no.module}.{item.name}"
                    )

    def dinamico(no):
        if isinstance(no, ast.Name):
            return no.id in variaveis_dinamicas
        if isinstance(no, ast.JoinedStr):
            return True
        if isinstance(no, ast.BinOp):
            return isinstance(no.op, (ast.Add, ast.Mod))
        return (
            isinstance(no, ast.Call)
            and isinstance(no.func, ast.Attribute)
            and no.func.attr == "format"
        )

    atribuicoes = [
        no for no in ast.walk(arvore)
        if isinstance(no, (ast.Assign, ast.AnnAssign))
    ]

    # Propagação simples; não é uma análise completa de fluxo de dados.
    for _ in range(3):
        for no in atribuicoes:
            if no.value is not None and dinamico(no.value):
                alvos = no.targets if isinstance(no, ast.Assign) else [no.target]
                for alvo in alvos:
                    if isinstance(alvo, ast.Name):
                        variaveis_dinamicas.add(alvo.id)

    for no in atribuicoes:
        alvos = no.targets if isinstance(no, ast.Assign) else [no.target]
        valor = no.value
        for alvo in alvos:
            identificador = nome(alvo)
            if isinstance(alvo, ast.Subscript):
                chave = alvo.slice
                if isinstance(chave, ast.Constant):
                    identificador = str(chave.value)

            suspeito = re.search(
                r"(^|_)(password|passwd|senha|secret|token|api_key)($|_)",
                identificador.lower(),
            )
            if (
                suspeito
                and isinstance(valor, ast.Constant)
                and isinstance(valor.value, str)
                and valor.value.strip()
            ):
                registrar(
                    no, "VC001", "alto", "Possível credencial fixa",
                    "Uma variável com nome sensível recebe texto diretamente.",
                    "Use variáveis de ambiente ou um gerenciador de segredos. "
                    "Se a credencial for real e tiver sido exposta, substitua-a.",
                )

    for no in ast.walk(arvore):
        if not isinstance(no, ast.Call):
            continue

        chamada = nome(no.func)

        if chamada in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            registrar(
                no, "VC002", "alto", "Execução dinâmica de código",
                "eval ou exec pode executar instruções controladas por terceiros.",
                "Substitua por operações explícitas e valide a entrada. "
                "Para dados JSON, utilize json.loads.",
            )

        shell_ativo = any(
            item.arg == "shell"
            and isinstance(item.value, ast.Constant)
            and item.value.value is True
            for item in no.keywords
        )
        if chamada in {"os.system", "os.popen"} or (
            chamada.startswith("subprocess.") and shell_ativo
        ):
            registrar(
                no, "VC003", "alto", "Uso de shell",
                "Comandos de shell podem permitir injeção quando recebem "
                "dados externos sem controle.",
                "Evite o shell. Prefira subprocess.run com lista de argumentos, "
                "shell=False e validação dos valores.",
            )

        if (
            isinstance(no.func, ast.Attribute)
            and no.func.attr in {"execute", "executemany", "executescript"}
            and no.args
            and dinamico(no.args[0])
        ):
            registrar(
                no, "VC004", "alto", "Possível SQL construído dinamicamente",
                "O argumento da execução é montado com interpolação ou "
                "concatenação. Confirme se recebe entrada externa.",
                "Use consultas parametrizadas e passe os valores separadamente.",
            )

        if (
            isinstance(no.func, ast.Attribute)
            and no.func.attr == "run"
            and any(
                item.arg == "debug"
                and isinstance(item.value, ast.Constant)
                and item.value.value is True
                for item in no.keywords
            )
        ):
            registrar(
                no, "VC005", "medio", "Modo debug habilitado",
                "Uma chamada run contém debug=True. Verifique se é um "
                "servidor web que será publicado.",
                "Desative o debug no ambiente de produção.",
            )

        if chamada in {"pickle.load", "pickle.loads"}:
            registrar(
                no, "VC006", "alto", "Desserialização com pickle",
                "Dados pickle não confiáveis podem provocar execução de código.",
                "Não carregue pickle de terceiros. Prefira JSON para "
                "intercâmbio de dados simples.",
            )

    return sorted(achados, key=lambda item: (item["linha"], item["regra"]))
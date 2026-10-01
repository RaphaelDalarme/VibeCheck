import os

senha = "senha_ficticia_para_demonstracao"

def buscar_usuario(cursor, usuario):
    cursor.execute(
        f"SELECT * FROM usuarios WHERE nome = '{usuario}'"
    )

def executar_comando(comando):
    os.system(comando)

def calcular(expressao):
    return eval(expressao)
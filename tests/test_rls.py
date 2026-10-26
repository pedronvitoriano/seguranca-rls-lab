"""Prova, com teste, a diferença entre a tabela sem RLS e a tabela com RLS.

Cada teste entra no banco como um papel (anon ou authenticated) e tenta o que um
atacante tentaria. A conexão base é de administrador só para montar os dados.
"""
import os
import uuid

import psycopg
import pytest

DSN = os.environ.get("DATABASE_URL", "postgresql://postgres:lab@127.0.0.1:55432/postgres")
SQL_DIR = os.path.join(os.path.dirname(__file__), "..", "sql")

ALICE = str(uuid.uuid4())
BOB = str(uuid.uuid4())


def como(conn, papel, usuario=None):
    """Troca o papel da sessão, como a API do Supabase faz a cada requisição."""
    conn.execute(f"SET ROLE {papel}")
    if usuario:
        conn.execute("SELECT set_config('request.jwt.claim.sub', %s, false)", (usuario,))
    else:
        conn.execute("SELECT set_config('request.jwt.claim.sub', '', false)")


def volta_a_admin(conn):
    conn.execute("RESET ROLE")


@pytest.fixture(autouse=True)
def papel_limpo(request):
    """Cada teste começa como administrador, mesmo que o anterior tenha falhado no meio."""
    if "banco" in request.fixturenames:
        request.getfixturevalue("banco").execute("RESET ROLE")
    yield


@pytest.fixture(scope="module")
def banco():
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public")
        admin.execute("DROP SCHEMA IF EXISTS auth CASCADE")
        for papel in ("anon", "authenticated"):
            admin.execute(
                f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{papel}') "
                f"THEN EXECUTE 'DROP OWNED BY {papel}'; EXECUTE 'DROP ROLE {papel}'; END IF; END $$"
            )
        for arquivo in ("01_papeis.sql", "02_vulneravel.sql", "03_corrigida.sql"):
            admin.execute(open(os.path.join(SQL_DIR, arquivo), encoding="utf8").read())
        admin.execute(
            "INSERT INTO notas_vulneravel (dono, conteudo) VALUES (%s,'segredo da Alice'),(%s,'segredo do Bob')",
            (ALICE, BOB),
        )
        admin.execute(
            "INSERT INTO notas_corrigida (dono, conteudo) VALUES (%s,'segredo da Alice'),(%s,'segredo do Bob')",
            (ALICE, BOB),
        )
        yield admin


# --- tabela vulnerável: o que o atacante consegue sem nem fazer login ---------


def test_vulneravel_anonimo_le_tudo(banco):
    como(banco, "anon")
    linhas = banco.execute("SELECT conteudo FROM notas_vulneravel").fetchall()
    volta_a_admin(banco)
    assert len(linhas) == 2  # a falha: quem não fez login lê as notas de todo mundo


def test_vulneravel_anonimo_apaga_tudo(banco):
    como(banco, "anon")
    banco.execute("DELETE FROM notas_vulneravel WHERE conteudo = 'lixo'")
    banco.execute("INSERT INTO notas_vulneravel (dono, conteudo) VALUES (gen_random_uuid(), 'lixo')")
    apagadas = banco.execute("DELETE FROM notas_vulneravel WHERE conteudo = 'lixo' RETURNING id").fetchall()
    volta_a_admin(banco)
    assert len(apagadas) == 1  # a falha: anônimo também grava e apaga


# --- tabela corrigida ---------------------------------------------------------


def test_corrigida_anonimo_nao_acessa(banco):
    como(banco, "anon")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        banco.execute("SELECT * FROM notas_corrigida")
    volta_a_admin(banco)


def test_corrigida_cada_usuario_ve_so_as_proprias(banco):
    como(banco, "authenticated", ALICE)
    linhas = banco.execute("SELECT conteudo FROM notas_corrigida").fetchall()
    volta_a_admin(banco)
    assert linhas == [("segredo da Alice",)]


def test_corrigida_nao_apaga_linha_de_outro(banco):
    como(banco, "authenticated", ALICE)
    apagadas = banco.execute("DELETE FROM notas_corrigida WHERE conteudo = 'segredo do Bob' RETURNING id").fetchall()
    volta_a_admin(banco)
    assert apagadas == []  # a linha do Bob continua lá


def test_corrigida_nao_cria_linha_em_nome_de_outro(banco):
    como(banco, "authenticated", ALICE)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        banco.execute("INSERT INTO notas_corrigida (dono, conteudo) VALUES (%s, 'falsa')", (BOB,))
    volta_a_admin(banco)


def test_auditoria_acha_a_tabela_sem_rls(banco):
    sql = open(os.path.join(SQL_DIR, "04_auditoria.sql"), encoding="utf8").read()
    resultado = {t: (rls, anon) for t, rls, anon in banco.execute(sql).fetchall()}
    assert resultado["notas_vulneravel"] == (False, True)
    assert resultado["notas_corrigida"] == (True, False)


def test_ligar_o_rls_sozinho_ja_bloqueia_o_anonimo(banco):
    """Um único comando fecha o vazamento: RLS ligado sem política nenhuma nega tudo."""
    banco.execute("DROP TABLE IF EXISTS notas_um_comando")
    banco.execute("CREATE TABLE public.notas_um_comando (id serial PRIMARY KEY, conteudo text)")
    banco.execute("GRANT SELECT ON public.notas_um_comando TO anon")
    banco.execute("INSERT INTO notas_um_comando (conteudo) VALUES ('a'), ('b')")
    como(banco, "anon")
    antes = banco.execute("SELECT count(*) FROM notas_um_comando").fetchone()[0]
    volta_a_admin(banco)
    banco.execute("ALTER TABLE public.notas_um_comando ENABLE ROW LEVEL SECURITY")
    como(banco, "anon")
    depois = banco.execute("SELECT count(*) FROM notas_um_comando").fetchone()[0]
    volta_a_admin(banco)
    assert (antes, depois) == (2, 0)

# seguranca-rls-lab

**PT:** laboratório pequeno que mostra, com teste, o erro mais comum em app feito com ferramenta de IA: o banco ficar aberto porque ninguém ligou o RLS (regra de acesso por linha). Há uma tabela com a falha, a mesma tabela corrigida, uma consulta de auditoria e testes que provam a diferença.

**EN:** a small lab that shows, with tests, the most common flaw in apps built with AI tools: a database left open because Row Level Security was never turned on. It has a vulnerable table, the fixed one, an audit query, and tests that prove the difference.

## O que acontece

| | Sem RLS (`notas_vulneravel`) | Com RLS (`notas_corrigida`) |
|---|---|---|
| Quem não fez login lê as notas de todo mundo | sim | não (sem acesso) |
| Quem não fez login grava e apaga | sim | não |
| Usuário logado lê a nota de outro | sim | não, só as próprias |
| Usuário logado apaga ou cria linha em nome de outro | sim | não |

Isso é o que um atacante faz só com a URL e a chave pública do projeto, sem invadir nada. Falhas desse tipo têm registro oficial: o [CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757) descreve políticas de RLS insuficientes em sites criados pela Lovable, que permitiam a quem não estava logado ler e gravar nas tabelas (a Lovable contesta, dizendo que a proteção dos dados é responsabilidade de quem publica o app).

Ligar o RLS sozinho, sem política nenhuma, já fecha o vazamento para quem não fez login: o teste `test_ligar_o_rls_sozinho_ja_bloqueia_o_anonimo` prova isso. As políticas servem para liberar de volta só o que cada usuário pode ver.

## Como rodar

```bash
docker compose up -d
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -v
```

São 8 testes. Se o RLS da tabela corrigida for desligado, 4 deles falham. Eles montam o banco do zero, entram como cada papel (`anon`, `authenticated`) e tentam o que um atacante tentaria. O CI do GitHub roda o mesmo com um Postgres de serviço.

## Como saber se o seu projeto tem o problema

`sql/04_auditoria.sql` lista as tabelas do schema `public` sem RLS ligado e se o papel `anon` consegue ler cada uma. Qualquer linha com `rls_ligado = false` e `anon_le = true` é uma porta aberta. No seu app, o teste mais rápido é abrir a URL da API sem estar logado e tentar ler a tabela.

## O que está imitado

O Supabase usa PostgREST e papéis do Postgres; aqui o laboratório usa só Postgres puro, com os papéis `anon` e `authenticated` e uma função `auth.uid()` que lê o usuário de uma variável de sessão. É uma simulação didática do mecanismo, não uma cópia do Supabase: não testa a API HTTP nem o gerenciamento de chaves.

## Autor

Pedro Vitoriano · [pedronvitoriano.com](https://pedronvitoriano.com)

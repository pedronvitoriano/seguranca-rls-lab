-- VERSÃO COM FALHA: o erro mais comum em app feito com ferramenta de IA.
-- A tabela existe, o app funciona, mas ninguém ligou o RLS (regra de acesso por linha).
CREATE TABLE public.notas_vulneravel (
  id         bigserial PRIMARY KEY,
  dono       uuid NOT NULL,
  conteudo   text NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.notas_vulneravel TO anon, authenticated;
GRANT USAGE ON SEQUENCE public.notas_vulneravel_id_seq TO anon, authenticated;

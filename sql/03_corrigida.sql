-- VERSÃO CORRIGIDA: RLS ligado, uma regra por operação, só o dono mexe na própria linha.
CREATE TABLE public.notas_corrigida (
  id         bigserial PRIMARY KEY,
  dono       uuid NOT NULL DEFAULT auth.uid(),
  conteudo   text NOT NULL
);
ALTER TABLE public.notas_corrigida ENABLE ROW LEVEL SECURITY;

-- Quem não fez login não tem nenhum acesso: nem grant, nem política.
GRANT SELECT, INSERT, UPDATE, DELETE ON public.notas_corrigida TO authenticated;
GRANT USAGE ON SEQUENCE public.notas_corrigida_id_seq TO authenticated;

CREATE POLICY le_so_as_proprias ON public.notas_corrigida
  FOR SELECT TO authenticated USING (dono = auth.uid());
CREATE POLICY cria_so_como_dono ON public.notas_corrigida
  FOR INSERT TO authenticated WITH CHECK (dono = auth.uid());
CREATE POLICY edita_so_as_proprias ON public.notas_corrigida
  FOR UPDATE TO authenticated USING (dono = auth.uid()) WITH CHECK (dono = auth.uid());
CREATE POLICY apaga_so_as_proprias ON public.notas_corrigida
  FOR DELETE TO authenticated USING (dono = auth.uid());

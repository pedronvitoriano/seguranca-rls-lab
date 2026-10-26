-- Imita o que o Supabase faz: um papel para quem não fez login (anon) e outro
-- para quem fez (authenticated). A API entra no banco como um desses papéis.
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;

CREATE SCHEMA auth;
-- No Supabase, auth.uid() devolve o id de quem está logado (vem do token).
CREATE FUNCTION auth.uid() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;

GRANT USAGE ON SCHEMA public, auth TO anon, authenticated;

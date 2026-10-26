-- Auditoria: lista tabelas do schema public sem RLS ligado. Em um projeto real,
-- qualquer linha aqui, com grant para anon ou authenticated, é uma porta aberta.
SELECT c.relname AS tabela,
       c.relrowsecurity AS rls_ligado,
       has_table_privilege('anon', c.oid, 'SELECT') AS anon_le
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY c.relname;

-- Demo data: one project with two environments, and nothing else.
--
-- Deliberately no tokens and no API keys. Both are secrets, and a seed that
-- invents secrets teaches the wrong habit — worse, a seeded token that looks
-- real is a live token in every deployment that forgot to switch this off.
-- An empty environment with a working panel is enough to see how the service
-- fits together; the first real token is one form submission away.

INSERT INTO projects (id, slug, name, created_at)
VALUES (1, 'demo', 'Demo Service', unixepoch());

INSERT INTO environments (project_id, slug, created_at)
VALUES (1, 'prod', unixepoch()),
       (1, 'staging', unixepoch());

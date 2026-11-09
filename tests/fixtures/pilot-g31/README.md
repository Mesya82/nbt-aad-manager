# Pilot head unit fixtures (BMW G31 530i, 2018, NBT EVO `NBTevo_Y23236I`)

Sanitized `report/` folders from read-only probe runs (Rust probe v0.0.1,
Windows 10, direct ENET). Raw `private/` data never leaves the operator's
laptop. Omitted stdout (third-party content or bulky; digest + size kept):
`pf.conf`, `use <tool>` help text, full `pidin` process lists.

| Run | Date (UTC) | Android Auto | Outcome |
| --- | --- | --- | --- |
| run1 | 2026-11-09 12:45 | stopped (fresh boot) | stopped before login (client GEX minimum 3072 bits) |
| run2 | 2026-11-09 12:57 | stopped | 162 commands; read-backs skipped (sentinel used a shell built-in through `on`) |
| run3 | 2026-11-09 13:00 | connected | as run2; **AA disconnected mid-run** (see docs/UPSTREAM_RESEARCH.md, incident) |

No command in any run was a write; the guard admits only read-only shapes.

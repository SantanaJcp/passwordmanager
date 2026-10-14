**ISSUES** — commit `e18cf389c91623072d7e8584860e9ca85a6f5356`, desde `2801c4893b1a1e1870479eb692b120929518c8a4`.

Worktree `/home/santana/.t3/worktrees/passwordmanager/t3-a69e62ca`; rama `t3/protected-memory-exposures`.

- **Source:** roundtrip SID con liberación comprobada, negativas nativas de apertura inicial y correcciones del [informe](/home/santana/.t3/worktrees/passwordmanager/t3-a69e62ca/docs/verification/chef-installed-config-20261014.md). APIs y política permanecen iguales.
- **Medido:** tests compartidos **6/6**, fmt/clippy rc0 bajo flock y target privado.
- **NOT_RUN:** compilación, ejecución y RED/GREEN Windows. La hipótesis P1 sobre ProgramData permanece abierta.
- **Inferido:** corregida la afirmación de bloqueo de rename conforme a [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew). Fallbacks heredados sin modificar.

SHA enviado al coordinador. Siguiente paso: fixture protegido y repros R1 cuando exista autorización nativa.



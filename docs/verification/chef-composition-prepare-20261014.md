# Next composition preparation — 2026-10-14

**CLEAN_METADATA_ONLY.** Measured Git/object/ref preparation only. No Cargo,
build, project check, lab, full52, kitchen integrate, review or delegation ran.
No future product PASS, accepted composition, final composite SHA or47/52 count.
Principles: `isolate`, `evidence`, `truthful-state`, `small-owned`, `handoff`.

Workspace remains `/home/santana/.t3/worktrees/passwordmanager/t3-0eed2d3d`,
branch `t3/chef-integration-tests`, starting method HEAD
`0a11733ffc784e80cb75c8df01d2cdcf34862d7e`. T3 binding was not moved.
Original run1/8cd logs, roots, targets, receipts and method files are unchanged.
No foreign ledger, production, fixture, oracle, config, native, manifest or lock
was edited. Normalized checkout changes are only already-authored delta replay.

## Prepared exact refs and future strategy

Base: **`8cd45529b062506a2cbe0c567538d3999ac8a2b6`**, retaining all nine original sibling heads transitively
(measured nine `merge-base --is-ancestor` rc0; exact list in export receipt).
Canonical disposable source for future `kitchen --repo`:

```text
/home/santana/.t3/worktrees/passwordmanager/t3-0eed2d3d/.scratch/chef-composition-prepare-20261014-repeat/repo
```

Known exact siblings, in proposed future merge order:

1. Selected caller: `3b4dd416a4dcd6f7cc301fc4c9f2c1d30ce540d9` (`refs/inputs/selected-caller`).
2. Normalized latest guide: `55abf2592cc67a7da9a0fcaa89055540f41fe61c` (`refs/heads/chef/normalized-guide-20261014`).
3. Normalized TLS test gate: `15013de74d7bf55464c2d6aef7e99ee2f9ee25fc` (`refs/heads/chef/normalized-tls-gate-20261014`).
4. Original unchanged method: `0a11733ffc784e80cb75c8df01d2cdcf34862d7e` (`refs/inputs/original-method`).
5. **Reviewed product-fix candidate: NOT_RETURNED.** No SHA/ref/commit placeholder
   exists. Append its actual reviewed SHA only after the parent supplies it.

This is an incomplete future vector, not a runnable integration command. The
parent must import the actual candidate by local filesystem fetch into this
owned repo, inspect its exact reviewed range/ancestry and allowed footprint,
and resolve it before any final kitchen run. If it introduces unexpected
history or conflicts, report those exact paths; no semantic conflict edits,
ours/theirs resolution, automatic fix normalization or policy invention.
The two-defect source review belongs to the parent; prior D1/D2 review budget
is exhausted and was not reopened here. No polling or waiting for that worker.

All refs are directly resolvable in the canonical repo, including the base and
method. A local bundle exports only those known refs and their ancestry:
[prepared-known-refs.bundle](../../.scratch/chef-composition-prepare-20261014-repeat/prepared-known-refs.bundle).
The bundle is not a final composition and contains no product-fix placeholder.
[Export/tree hashes](../../.scratch/chef-composition-prepare-20261014-repeat/export-and-trees.json).

## Normalization provenance

Measured original/cherry-picked base patch identity:

- Original guide `9de9aa99347cc2b3300190601ba00c568f22aa86` equals copied
  `6e5fbee014a279810286d3636cee5162f395e6da` by stable patch-id and raw diff SHA256.
- Original sync `5e26f3b4d4813c4e606339353e67e82ede4dcdf5` equals copied
  `7499754386931663a844c8b0522cb6ccbb26a4b2` by the same two measures.

Neither copied base was cherry-picked again. Guide source repository was
`/home/santana/.t3/worktrees/passwordmanager/t3-9eb5de46`; TLS source repository
was `/home/santana/.t3/worktrees/passwordmanager/t3-e1e1ea68`. Local filesystem
fetches used exact pinned commits, never live branch heads, remote URLs or
uncommitted files. No later coordinator/native branch was opportunistically read
into a normalized branch.

| Source delta | Source parent | Normalized commit | Normalized parent | Stable patch-id (equal) |
| --- | --- | --- | --- | --- |
| `e1307808be9b88a77cc3a9725356b7281f4bb49f` | `6e5fbee014a279810286d3636cee5162f395e6da` | `062e3e540af77a4451a60a599c03c08b68442e71` | `8cd45529b062506a2cbe0c567538d3999ac8a2b6` | `036cd26d393fb2662fd8e4e1ac02ba0bcc805af4` |
| `2d86a31537d9418b7f7f7a66e567ca84fe82f505` | `e1307808be9b88a77cc3a9725356b7281f4bb49f` | `55abf2592cc67a7da9a0fcaa89055540f41fe61c` | `062e3e540af77a4451a60a599c03c08b68442e71` | `11bd53391b34d34a852396785bb998fa2f5ea0a1` |
| `fffceb33622af151a55216677b20946b05f4e844` | `7499754386931663a844c8b0522cb6ccbb26a4b2` | `15013de74d7bf55464c2d6aef7e99ee2f9ee25fc` | `8cd45529b062506a2cbe0c567538d3999ac8a2b6` | `9b5bd550bfed81f2c3a8787bd474afb7d59c4c81` |

For all three deltas, stable patch-id, SHA256 of the complete raw binary-capable
Git diff, and each changed file's Git blob/SHA256 are identical to source.
Two fresh disposable repositories reproduced the exact same three normalized
commit SHAs and parents. The normalizer fixes only committer identity/date
(`2000-01-01T00:00:00+00:00`), preserves source authors, and uses `cherry-pick -x`.
No source, Python fixture, semantic patch or conflict resolution was handmade.
[Per-file hashes, raw-diff hashes and mappings](../../.scratch/chef-composition-prepare-20261014-repeat/provenance.json),
[base equivalence](../../.scratch/chef-composition-prepare-20261014-repeat/cherrypicked-base-equivalence.json).

Measured normalized net footprints against8cd:

- Guide: README.md, docs/user/evaluacion-linux.md,
  docs/verification/chef-guide-alignment-20261014.md only.
- TLS: crates/pm-sync/src/frame_cost_tests.rs and
  docs/verification/chef-sync-probe-gate-20261014.md only.

Every other tracked path is identical to8cd: production, fixtures, manifests,
lockfiles, scripts/workflows, AGENTS/spec and coordinator ledgers included.
The Rust file is a test-only module: main.rs:45–46 uses cfg(all(test,unix));
main.rs and actual production framing remain byte-identical to8cd.

Measured raw `git merge-tree --write-tree` preflight (no checkout edits):
2d86 source returns rc1/add-add in README.md and docs/user/evaluacion-linux.md;
fff source returns rc1/add-add in crates/pm-sync/src/frame_cost_tests.rs.
All three normalized cherry-picks returned rc0 without conflicts.
[Raw conflict output](../../.scratch/chef-composition-prepare-20261014-repeat/raw-input-merge-preflight.json).
This proves normalization applies; it does not prove the incomplete future
vector integrates or passes runtime verification.

## Selected caller history and excluded inputs

Measured caller production/scripts/manifests/lock/workflow diff against8cd is
empty. Its authored delta against parent b12784295b31415de577889b63883f9169278dfd
contains eight Python fixtures plus its new caller report, as pinned.

Important explicit inheritance: selected3b also contains eight historical
coordinator paths from b127's first parent e8c750fef38d4e88d57ec6e68621c787ae514d14:
three parallel-run ledgers and five evidence-r1 reports under .scratch.
They are already part of the explicitly selected caller, not introduced by
normalization. Keeping exact3b necessarily retains that ancestry; this report
does not claim an empty .scratch delta for a future merged caller. No later
ledger changes were fetched or selected, and none were edited or silently
stripped. Exact inherited paths are in provenance.json.

Measured excluded commits are not ancestors of base, caller, either normalized
head or method (all fifteen ancestry probes rc1):

- `2801c4893b1a1e1870479eb692b120929518c8a4`
- `e18cf389c91623072d7e8584860e9ca85a6f5356`
- `e44854e451b4dea705fdf57972ea3bb3ba78ae1d` (G7 Unix reader evidence only)

Their exact objects were read by local fetch solely for ancestry proof; no ref
in the proposed vector points at them. Object availability is not inclusion.
Native config/profile proof and G7 acceptance remain pending.

## Source compatibility and precise future method adjustments

**Inferred from pinned source, not executed here:**
chef_installed_fixture.py:27–55 initializes exactly once as real UID0 inside a
subordinate namespace, allocates its own short /var/tmp/pc-* root, copies this
checkout's fresh custody binary/public libs, and records hashes. Its
prepare():58–76 accepts only installed commands as UID1, rewrites bounded paths
under that root, then chroots BEFORE dropping identity. Clients and human PTYs
remain outside. linux_lab.py:29–33 wires that helper into as_uid/start_as at
:47–48/:65–66; its main initializes before fixture allocation (:182–185).

The current sweep.py invokes original shell wrappers directly; it does NOT
wrap those seven legacy cases in owned_root.py. Preserve that structure. The
new callers initialize their own root, so those direct wrappers must not gain
an outer chroot wrapper. If an installed command already prepared by the new
API passes through owned_root.py:40–63, its global Popen hook would chroot once
and then call the original preexec that chroots again; paths/principals would
no longer represent the intended fixture. No such lab was attempted here.

Exact small OWNED-method proposals for the next authorized run (not applied):

1. Add an explicit future vector manifest/dispatcher. Load source repo, base and
   complete actual SHA list from that run's request in both entrypoint and
   stage.py instead of importing the old hardcoded BASE/REFS. stage must assert
   ordered ancestry and use the actual list length, executing the full check
   only on its final merge. Retain0a as method provenance; do not rewrite its
   historical constants/evidence. Bind the new method content/command and
   complete vector in a NEW execution digest/receipt. No --recorded.
2. Keep sweep's historical-cases.json byte-identical (52 cases/order/arguments/
   expectations) and run every direct wrapper with fresh target/debug aligned
   to CARGO_TARGET_DIR. No dropping cases or translating product RED to exit0.
3. Explicitly distinguish self-initializing fixtures from legacy wrapper modes.
   Never run self-initializing fixtures through owned_root.py. For a focused
   CLI mode that intentionally migrates to the new API, replace ONLY its owned
   wrapper setup/Popen hook with linux_lab.initialize_installed_fixture(fresh
   custody) while UID0, before allocating fixture data; leave the CLI fixture's
   current assertions and explicit setup→migrate→restart sequence unchanged.
   Entering installed UID1 calls must remain the API's prepare() responsibility.
   Non-migrated legacy modes remain explicit; no automatic catch/fallback path.
   Fail closed on a mixed initialization/hook mode instead of nesting roots.
4. sweep.py:23 hardcodes WAYLAND_DISPLAY=wayland-1. The future no-owner-GUI
   constraint requires an explicitly OWNED GUI/runtime endpoint for the GUI
   cases; remove that host-session assumption in the owned method, require the
   private endpoint/environment as a precondition, and retain clipboard/browser
   assertions. If an owned GUI prerequisite is absent, report BLOCKED for those
   cases; do not silently inherit the real desktop or skip cases. No compositor,
   GUI, clipboard or desktop config was opened/changed here.

These are method proposals, not fixture/oracle changes and not authorization
for another execution now. Before the parent starts the final run it must
establish: exact reviewed two-defect candidate/range; absence of excluded or
unexpected history; compatible single-root runner routing; private GUI and
fresh target/bin origins; fixed immutable root toolchain with own clone link;
blocking flock without nested acquisition; new empty clean target and complete
52 plus affected flows. Existing deadlines8/15/20/30 and limits4/16/128 stay.

## Coverage and handoff boundary

Supplied/pinned author evidence, NOT rerun: caller3b converts five of seven RED
callers; intrinsic passkey stolen by generic worker and cancel blocked during
provider POST-response I/O remain product RED. Parent has one independent
product writer for those two defects; its candidate has not returned. TLSfff
reports a real inefficiency-counterexample RED101→GREEN0 and39 executed tests,
zero ignored, unchanged production. Source equality preserves those authored
inputs, but it does not transfer their runtime results to a future composite.

Original8cd's kitchen/check/clean and42/52 remain evidence of that exact old run
only. No old clean, check,52 receipt or cached PASS may validate a changed head.
No old files/logs/targets/roots were removed or rewritten. Original0a's eleven
method/report files are byte-identical on this workspace; only this new report
and metadata preparation utility are added.
[Original evidence retention receipt](../../.scratch/chef-composition-prepare-20261014-repeat/original-evidence-retained.json).

Reproduce only this metadata preparation, in a NEW owned destination:

```sh
python3 scripts/chef-integration-20261014/prepare_refs.py /absolute/new/owned/destination
```

[Preparation utility](../../scripts/chef-integration-20261014/prepare_refs.py) executes
only Git init/local fetch/ref resolution, cherry-picks and source hash/patch
comparison. Its Git commands and return codes are retained in
[git-operations.json](../../.scratch/chef-composition-prepare-20261014-repeat/git-operations.json).
No global kitchen/model/config changes, downloads, installation, paid/native
runner, push/PR/master/release/publication, real credential, review/delegation,
worker polling or product acceptance occurred. Preparation ends here; the parent
starts final integration only after exact fix/review inputs are ready.

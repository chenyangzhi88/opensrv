# Uni5DB OpenSrv maintenance

## Provenance

- Fork: `git@github.com:chenyangzhi88/opensrv.git`
- Official upstream: `https://github.com/datafuselabs/opensrv.git`
- Maintenance baseline: `4f45ae6720b09c302458bbe6280ff0398f5b6b19`
- MySQL package version: `0.8.0`; no release tag is invented for this baseline.
- Maintenance branch: `uni5db-0.8`; `main` has no product patches.
- Input: the complete old `third_party/opensrv-mysql` working-tree snapshot,
  including uncommitted changes, at parent HEAD
  `b88e963757b2eb583266eb17a310f397623c0d00`.

The old copy has no Cargo VCS metadata. Of 29 files in the original parent
import `5b1584a7`, 22 match this upstream baseline byte-for-byte and 7 already
contain local differences. Another equally matching candidate,
`501395a384c63f77b80f90f39cdc00f6f320a884`, has an identical MySQL directory tree.
The selected maintenance baseline is therefore reproducible, not a claim that
the exact original checkout commit can be uniquely inferred.

All 39 current package files, including sources, tests, examples, manifest,
README and TLS fixtures, are retained byte-for-byte. There are 24 modified
upstream files and 10 added files. Their sorted path/checksum inventory digest is
`361820aac1bcce3e6b6822ff343e2b84e41b7f7d2cbe7965dd67aa3667e8d8c8`.

## Existing local contracts

The complete MySQL snapshot preserves the existing backend callback API and
command-state contracts, raw SQL/parameter names and values, fallible binding
parsing and allocation ownership, query attributes, authentication/TLS and
session information, compressed packet streams, packet limits and boundaries,
prepared/cursor/long-data handling, local infile, result/status/error metadata,
value codecs, and their tests/examples. This migration introduces no new wire
behavior and does not claim every contract currently passes.

Shared packet, authentication and command-state code depends on the same
backend interface. It is retained as one complete functional commit rather
than artificially splitting unusable intermediate states. Moved original
upstream tests remain upstream code: use Git movement detection to inspect
authorship. Independent contributions require focused extraction and review.

Only `mysql/` sources are modified. ClickHouse and other upstream component
sources are unchanged and are not product dependencies.

## Build integration

The root workspace's upstream Git-only subprocess patch is removed to preserve
the registry dependency used by the old standalone MySQL package. This is a
separate build-integration change, not a protocol change. The original 309
standalone package identities are all retained; 22 additional resolved package
identities come from the complete workspace's other members. The product's
733-package graph, versions, features and root Cargo.lock remain unchanged.

Product test runners select only `-p opensrv-mysql` using this workspace's
manifest from the parent working directory. The original toolchain file is
untouched. Actual migration checks used Rust 1.95.0.

## Actual checks and existing failures

- Product dependency `cargo check --locked --offline -p opensrv-mysql --lib` passed.
- Library tests: 282 passed, 8 failed. The old-copy diagnostic rerun reproduced
  exactly the same 8 failing tests.
- Client integration tests: 27 passed, 1 failed (`secure::test_secure`, `256 != 0`).
  The old-copy targeted diagnostic reproduced the same failure.
- Source-evidence utility: 25 tests passed; Classic producer selection: 2 passed.
- Formatting and strict Clippy checks failed on retained existing code.
- The changed-path architecture text check failed on a pre-existing literal
  `.execute_prepared_sql(` expectation; the current Classic implementation
  uses a publishing entry point. Its assertion was not rewritten to obtain PASS.

No failed assertions were deleted, no workload was changed, and no opportunistic
behavior repairs were included. This is a source migration, not full application
certification, performance acceptance or a release.

## Maintenance and upstream contributions

```sh
git log --reverse --oneline 4f45ae6720b09c302458bbe6280ff0398f5b6b19..HEAD
git diff --color-moved 4f45ae6720b09c302458bbe6280ff0398f5b6b19...HEAD -- mysql Cargo.toml
git blame -C -C -- mysql/src/lib.rs
```

The parent gitlink pins an exact validated maintenance commit. The branch hint
does not automatically upgrade it. Initial submodule checkout normally has
detached HEAD; local branch aliases and additional upstream remotes are not
copied by clone. Check/add the official upstream remote and use an explicit
integration branch for a selected upstream commit. Verify protocol/backend
contracts and dependencies before moving the parent pin. Do not rewrite shared
maintenance history.

For a PR, branch from current `upstream/main`, extract the relevant contract
and tests, and adapt to upstream APIs. Do not submit the whole product branch.
New local commits require an explicitly authorized push before another machine
can fetch them. No push or PR is part of this source migration.

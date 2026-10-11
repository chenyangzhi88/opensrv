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

At the migration commit, all 39 input package files, including sources, tests,
examples, manifest, README and TLS fixtures, were retained byte-for-byte. There are 24 modified
upstream files and 10 added files. Their sorted path/checksum inventory digest is
`361820aac1bcce3e6b6822ff343e2b84e41b7f7d2cbe7965dd67aa3667e8d8c8`.

## Existing local contracts

The complete MySQL snapshot preserves the existing backend callback API and
command-state contracts, raw SQL/parameter names and values, fallible binding
parsing and allocation ownership, query attributes, authentication/TLS and
session information, compressed packet streams, packet limits and boundaries,
prepared/cursor/long-data handling, local infile, result/status/error metadata,
value codecs, and their tests/examples. This migration introduces no new wire
behavior. The follow-up repair below is distinct from that byte-preserving migration.

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

## Follow-up repairs and recorded checks (2026-10-11)

The migration's historical results were 282/290 library tests, 27/28 integration
tests, and failed format/strict-Clippy/old-architecture checks. The old copy
reproduced the same test failures. Preserve that raw baseline at
`/nvme_data_1/uni5db-opensrv-migration.eNvtms`; it is not the current result.

The authorized follow-up fixes:

- Parse handshake connection attributes only when both peers advertise
  `CLIENT_CONNECT_ATTRS`. libmysqlclient can retain that client bit while
  omitting the field for a server without it. Preserve the original client
  flags and all strict length/size checks for genuinely negotiated attributes.
  Test both negotiation outcomes, both client-bit states and both TLS phases.
- Align compression reply fixtures with the request's actual sequence, count
  decoded commands separately from admission events, and forward the installed
  named-query consumer in the frontier fixture. Assert the consumer's setter
  ERR has exactly one existing query terminal, not an additional packet terminal.
- Await the TLS server task and assert TLS was actually negotiated, retaining
  the real command-line client's successful-exit assertion.
- Remove the unused legacy single-packet decoder/buffer wrapper. Keep the
  single live decoder and its packet tests. Clean strict Clippy findings without
  blanket allowances, extra state, or changing the native statistics widths.
- Update the parent architecture assertion to check the actual shared product
  publishing, batch and cursor entries used by Classic/X.

Recorded checks of the earlier frozen source:

- All-features library tests: **291 passed, 0 failed, 0 ignored**.
- All-features client integration: **28 passed, 0 failed, 0 ignored**.
- Without default/TLS features: **290 library and 27 integration tests passed**.
- Selected-package formatting and strict all-targets/all-features Clippy passed.
- Strict all-targets Clippy without default/TLS features also passed.
- Actual product dependency `cargo check --locked --offline -p opensrv-mysql --lib` passed.
- Relevant parent architecture test: 1 passed; evidence utility: 25 passed;
  Classic producer selection: 2 passed.

Commands, exit codes, raw logs, final diffs and source checksums are in
`/nvme_data_1/uni5db-opensrv-fixes.UCodRr`. Rust/Clippy 1.95.0 and the installed
official MySQL CLI 8.0.46 were used. No dependencies or lockfiles were changed.
These are selected MySQL development checks, not full product/application
certification, performance acceptance or a release. ClickHouse was not tested.

Subsequent checksum verification found that `mysql/src/lib.rs` no longer matches
that run's `source-freeze.sha256`; the other 38 recorded files still match. The
counts above are historical evidence, not verification of this later source.
This local follow-up commit does not rerun the test matrix or publish a release.

Follow-up repairs are recorded on `uni5db-0.8`; updating the parent gitlink is a
separate parent-repository operation. This local commit does not push or open a
PR. The migration inventory above describes the migration commit, not the
intentionally changed repaired sources.

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

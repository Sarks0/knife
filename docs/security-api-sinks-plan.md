# Security-API sinks: review and research

Status: research / design proposal (branch `feat/sinks-improvement`). No
behaviour has changed yet. This document records what the current sink system
does, where the Windows "security API" surface falls through it, and a phased,
evidence-first way to close that gap without duplicating `capabilities`.

## 1. How sinks work today

The sink surface is three cooperating pieces plus one sibling it deliberately
stays separate from.

- `src/analysis/sinks.rs` — the user-mode `CATALOG`. Each entry is a
  `SinkDef { api, class, note, severity }`. Entries are grouped by **the
  mistake they enable**, not by intent: `memory`, `stack`, `format`, `exec`,
  `alloc`, `path`, `random`, `privilege`. `find()` matches the binary's
  imports *and* defined names against the catalogue, sees through toolchain
  decoration (`_strcpy`, `__isoc99_sscanf`), refuses to match the fortified
  `_chk` aliases, and attaches call sites by walking `xrefs_to` (skipping data
  xrefs and PLT self-references). Output is call sites, ranked by severity then
  site count.
- `src/analysis/ntapi.rs` — the `KERNEL_CATALOG`. Same `SinkDef` shape, merged
  into `find()` via `CATALOG.iter().chain(ntapi::KERNEL_CATALOG.iter())`. It
  covers kernel/driver primitives (`physical-mem`, `kernel-rw`, `io-port`,
  `loader`, `callback`, `device`, `process`, `pool`, `registry`, `security`,
  `netio`, …). This is the proof that **adding a whole new class of sink is a
  catalogue change, not a plumbing change**.
- `src/analysis/audit.rs` — the bug finder. For the *auditable subset* of the
  catalogue it runs a bounded backward data-flow walk over x86 registers and
  promotes a call site to a `Finding` only when the dangerous argument's
  provenance matches a pattern (format string loaded from memory, allocation
  size from a multiply, copy length from a subtraction, unbounded copy into a
  stack buffer). The auditable subset is the `checks()` table: `Format`,
  `AllocSize`, `CopySize`, `Unbounded`.
- `src/analysis/capabilities.rs` — the **sibling, not a sink**. It answers the
  triage question "what could this program do to a machine" and is weighted by
  intent (`injection`, `persistence`, `theft`, `crypto`, `network`,
  `anti-debug`, …). `sinks.rs`'s own module doc is explicit that it is *not*
  the capability catalogue.

Consumers: the `sinks` and `trace_taint` tools (`src/tools.rs`), the CLI
`knife sinks [--class] [--all]` (`src/main.rs::cmd_sinks`), and the driver pass
(`src/analysis/driver.rs`, `src/api/driver_surface.rs`).

### Why the class dimension is cheap to extend

`class` and `note` are open `&'static str`; `severity` is `u8` in `1..=3`. The
CLI renders classes generically — `cluster()` counts per class, colour is by
severity, the `--class` filter is a case-insensitive string match — and the
JSON/tool output passes `class` straight through. The only code anywhere that
hard-codes a specific class string is the driver pass's `"callback"`
special-casing. **A new class (`acl`, `token`, `authz`, `crypto-weak`) needs no
rendering, no enum, no tool-schema change.** That is the lever this proposal
pulls.

## 2. The gap

> "sinks only covers classic memory/exec sinks — NOT security APIs."

Accurate, with one seam already open: the `privilege` class exists but holds
five Unix-leaning entries (`setuid`/`setgid`/`seteuid`) plus two Windows ones
(`ImpersonateNamedPipeClient`, `RevertToSelf`). The Windows security surface —
access control, tokens, impersonation, authorization checks, weak crypto
selection, COM/RPC authentication level — is almost entirely absent from the
*sink* view. Some of it (`OpenProcessToken`, `CryptEncrypt`, `CreateService`,
`CryptUnprotectData`) lives in `capabilities`, but that catalogue answers a
different question and carries no call-site/provenance machinery.

Crucially, these APIs fit the sink philosophy *exactly*: each is "a function
that is perfectly normal to call and only interesting because of how easy it is
to call wrongly." The wrongness is just a different shape than a memory bug:

- `SetSecurityDescriptorDacl(sd, /*bDaclPresent*/ TRUE, /*pDacl*/ NULL, FALSE)`
  installs a **NULL DACL** — every principal gets full control of the object.
  Normal API; one wrong argument is a local EoP.
- `ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;;GA;;;WD)", …)`
  grants Everyone GENERIC_ALL via an **over-broad SDDL string constant**.
- `ImpersonateNamedPipeClient` / `RpcImpersonateClient` / `CoImpersonateClient`
  whose **return value is not checked** run the privileged body as the service
  identity on failure (named-pipe / RPC impersonation EoP).
- `AccessCheck` / `AuthzAccessCheck` whose **result is ignored**, or that is
  simply **absent** before the sensitive operation (missing per-procedure
  authorization).
- `AdjustTokenPrivileges` enabling `SeDebugPrivilege` / `SeLoadDriverPrivilege`;
  its return lies (`ERROR_NOT_ALL_ASSIGNED` still returns `TRUE`).
- `CoInitializeSecurity(…, RPC_C_AUTHN_LEVEL_NONE, …, EOAC_NONE, …)` disables
  COM authentication — a constant-argument bug.
- Weak algorithm selection: `BCryptOpenAlgorithmProvider(…, L"MD5"|L"RC4"|
  L"DES", …)`, `CryptCreateHash(…, CALG_MD5, …)`.

## 3. Two detector shapes

The security surface splits cleanly, and the split decides implementation cost.

### Shape A — constant-argument bugs (high value, fits existing machinery)

The bug is a *specific constant* (or NULL) in a *specific argument slot*. This
is the same backward-provenance walk `audit.rs` already runs for `Format`/
`AllocSize`, pointed at a different slot with a different verdict. It produces
real **findings**, not just surface, and it is mostly immune to the
forward-flow limitation below.

Candidates: NULL DACL (`SetSecurityDescriptorDacl` arg3==NULL && arg2==TRUE),
over-broad SDDL (`ConvertStringSecurityDescriptorToSecurityDescriptor*` arg1
string ACE granting `WD`/`AN`/`BU` with `GA`/`FA`/`GW`), disabled COM auth
(`CoInitializeSecurity` authn-level arg == 0 or capabilities == EOAC_NONE),
weak hash/cipher id (`CryptCreateHash` Algid; `BCryptOpenAlgorithmProvider`
AlgId wide-string constant).

Implementation: add `Check::ConstArg { idx, predicate }` (and an
`Origin::Zero` for NULL/0 immediates) to `audit.rs`; the walk already recovers
`Fixed`/`Constant` origins and `lea [rip+k]` string pointers, so a "this
constant is the dangerous one" verdict reuses the existing trail/reachability
plumbing. Each new predicate is small and independently testable against a
hand-built fixture, exactly like `a_path_runs_from_the_entry_point_to_the_sink`.

### Shape B — missing / unchecked-call bugs (surface now, detection later)

The bug is an *absence*: a return value never consumed, or a required second
call (`RevertToSelf`, `AccessCheck`) missing on some path. The current walk is
backward-only and single-call, so it cannot yet prove these. Two honest stages:

1. **Now:** add the APIs to the sink `CATALOG` under new classes so `knife
   sinks`/`drv`/`trace_taint` surface the call sites with a precise `note`
   ("check the return; an unchecked failure runs the body as the service").
   This is pure catalogue data and ships immediately.
2. **Later:** a forward/structural pass — "is this call's result used before the
   next sensitive op?", "is there a `RevertToSelf` on every path out of the
   function that impersonated?" — reported as inference, never as a confirmed
   bug, per the AGENTS.md observation/inference/unknown contract. This is a
   separate, larger change and should not block stage 1.

## 4. Proposed catalogue (tiered, Windows-first, cross-format where it maps)

New classes: `acl` (security-descriptor / object ACLs), `token` (token
creation and application), `impersonation` (impersonate/revert pairs — fold the
two existing `privilege` Windows entries in here), `authz` (access checks),
`crypto-weak` (algorithm *selection*, distinct from `capabilities`' `crypto`
which is about intent). Severity keeps the catalogue convention
(3 = dangerous by default, 2 = needs care, 1 = context).

Tier 1 — constant-argument, Shape A, ship with an audit check:

| API | class | sev | the wrong call |
| --- | --- | --- | --- |
| `SetSecurityDescriptorDacl` | acl | 3 | present+NULL = NULL DACL |
| `ConvertStringSecurityDescriptorToSecurityDescriptorA/W` | acl | 2 | over-broad SDDL constant |
| `CoInitializeSecurity` | authz | 2 | authn level NONE / EOAC_NONE |
| `BCryptOpenAlgorithmProvider` | crypto-weak | 2 | weak AlgId string |
| `CryptCreateHash` | crypto-weak | 2 | weak CALG_* id |

Tier 2 — unchecked-return / primitive, Shape B, catalogue only for now:

| API | class | sev | note |
| --- | --- | --- | --- |
| `ImpersonateNamedPipeClient` (move from privilege) | impersonation | 2 | check the return before trusting the context |
| `RpcImpersonateClient`, `CoImpersonateClient` | impersonation | 2 | unchecked failure runs the body as the server |
| `ImpersonateLoggedOnUser`, `SetThreadToken` | impersonation | 2 | check the return; stale impersonation on failure |
| `RevertToSelf` (move from privilege), `CoRevertToSelf`, `RpcRevertToSelf` | impersonation | 2 | a failure leaves impersonation active |
| `AccessCheck`, `AccessCheckByType`, `AuthzAccessCheck` | authz | 2 | the result must gate the operation, not just be computed |
| `AdjustTokenPrivileges` | token | 2 | enabling a privilege; return lies on partial success |
| `DuplicateTokenEx`, `CreateProcessAsUserW`, `CreateProcessWithTokenW`, `CreateProcessWithLogonW`, `LogonUser` | token | 2 | who controls the target token / identity |
| `SetNamedSecurityInfo`, `SetSecurityInfo`, `SetKernelObjectSecurity`, `RegSetKeySecurity` | acl | 2 | writes an ACL; check it is not weakening the object |
| `SetSecurityDescriptorOwner` | acl | 1 | owner change; context |

Out of scope for sinks (belongs in `capabilities`, already partly there):
`CreateService*`, `CryptUnprotectData`, `CryptEncrypt`, generic
`OpenProcessToken`. These are intent signals, not "called-wrongly" sites.

Boundary rule to keep the two catalogues honest: **if the finding is "this
program can do X", it is a capability; if it is "this call site is the one you'd
check for mistake Y", it is a sink.** `AdjustTokenPrivileges` is a sink only
because the *audit* story (enabling a dangerous privilege, return-value trap) is
a mistake you check at the site; the bare ability to open a token is a
capability.

## 5. Risks and constraints

- **ANSI/W duplication.** Follow the existing pattern: list `A`/`W` as separate
  entries folded to one logical API where `find()` already groups by name. The
  `bare_name` thunk handling covers `KERNEL32!`-style prefixes.
- **False positives on Shape A.** A NULL-DACL verdict must require *both* the
  present flag true *and* the pointer NULL from provenance; if either argument's
  origin is `Dynamic`/`Argument`, downgrade to "worth a look", never "bad".
  Report the may/must distinction the walk already produces.
- **Forward-flow honesty.** Shape B stays surface-only until a real forward pass
  exists. Do not emit "missing RevertToSelf" as a confirmed finding from a
  backward walk — that violates "missing evidence is not evidence of absence."
- **Typed addresses / bounding.** New detectors inherit the existing display-base
  shifting, the `ANALYSIS_BUDGET`, and truncation reporting. No new unbounded
  walk.
- **Untrusted data.** SDDL strings, algorithm ids, and any target-derived
  constant the audit reads are evidence to classify, never instructions.

## 6. Phasing

1. **Catalogue + classes (Tier 1 & 2 data), `find()` unchanged.** Pure data;
   `knife sinks --class acl|token|impersonation|authz|crypto-weak` works
   immediately. Tests: catalogue has no duplicates, severities in range, a
   fixture importing `SetSecurityDescriptorDacl` surfaces under `acl`.
2. **Audit Shape A.** `Check::ConstArg` + `Origin::Zero`, the five Tier-1
   predicates, fixtures per predicate, wire into `trace_taint`. Findings carry a
   trail and reachability like every existing finding.
3. **Docs + changelog.** README sink section, this doc moved from proposal to
   reference, CHANGELOG entry. Only once behaviour is user-visible.
4. **(Separate, later) Shape B forward pass.** Its own branch; out of scope here.

## 7. Open questions for review

- Do we want `impersonation` as its own class, or is it cleaner to keep the
  existing `privilege` class and just widen it? (Proposal: new class — the CLI
  cluster line reads better and `--class impersonation` is a natural filter.)
- SDDL "over-broad" needs a small, defensible deny-list of principals/rights to
  flag (`WD`, `AN`, `BU` × `GA`, `FA`, `GW`). Agree the initial set before
  coding so the predicate is reviewable, not a heuristic that drifts.
- Weak-crypto id lists (CALG_* and CNG strings) should cite a fixed reference in
  the code comment so the choice is auditable.

# DAS 1.5 reference contract implementation

The HTTP additions use `das-http-declaration/v1` and `das-http-inventory/v1`.
OpenAPI-first declarations pin scope, original source bytes/base URIs and one
generation direction; inventory is a derived, non-authoritative projection.
`cadence contracts http-inventory --probe` accepts only a declaration and its
exact original URI/base64 byte set. No fetch, approval, signing or resource
permission occurs. See the [controlled HTTP sample](../../cadence-examples/examples/headless-minimal/http/README.md)
for supported native versions, security/reference semantics, bounds, errors and
the actual DASOps resource path. Inventory coverage stays unknown, complete
schema validation stays false; independent route/history/enforcement evidence
and approved facts remain mandatory. Both schema validators reject added author
or qualification fields; shape success does not establish source authority.

This directory adds identities alongside existing protocol objects. Legacy
StreamFrame, canonicaljson and protected v1 digest bytes are unchanged. A new
identity does not enable a protected operation or approve a deployment.

The authored schemas are in `schemas/das_v1_5/`. `tools/exact_contracts.py` is the
Python producer validator; Cadence Core owns the resolver, text materialization
and authorization checks. Generated copies must come from the same authors.

1. Install the pinned protocol verifier requirements into an isolated environment.
2. Run `bash scripts/verify` from this component. It checks the old compatibility
   matrix and all new Python tests. Run the Core verifier separately to exercise
   the Go consumers against the shared independent fixtures.
3. Decode security JSON through `tools/exact_json.py`. Repeated decoded keys,
   malformed Unicode, trailing values and bounded parsing failures are errors.
   Preserve exact number lexemes until their application domain is validated.
4. Validate the requested explicit identity. Fields are case sensitive; unknown
   critical payload fields are rejected. External schema retrieval is disabled.
5. For signed JSON semantic digests use `das-json-jcs/v1` only where the contract
   specifies it. This does not alter historical digest methods. Numeric counters
   must be exact integral values in the safe range before JCS conversion.
6. When consuming DSSE, first verify the native PAE bytes and supported payload
   type against independently installed Ed25519 trust policy. Parse only the
   verified payload bytes. Outer DSSE extensions follow the native protocol;
   inner action payloads follow their closed schema. `keyid` is a hint.
7. Count independent principal approvals as well as unique public keys. Repeating
   a signature, using another key for the same principal, or substituting an
   evidence signer cannot satisfy a multiple approver policy.
8. Revalidate current authority and every ancestor before resource execution.
   A valid action signature is not a Decision, receipt or Completion. A static
   authorization check does not reserve shared budgets or perform target CAS.

New identities currently implemented:

| Identity | Consumer and current meaning |
|---|---|
| das-bundle-preview-input/v1 | Exact input to the one Go module resolver |
| das-bundle-preview/v1 | Deterministic preview; authority and qualification are false |
| das-bundle-preview-input/v2 | Historical partial-catalog input; rejected with the current complete catalog |
| das-bundle-preview/v2 | Historical partial-catalog result; not the current complete result |
| das-bundle-preview-input/v3 | Current module plus complete pinned leaf catalog input |
| das-bundle-preview/v3 | Complete leaf mapping; authority and qualification remain false |
| das-approved-facts-check/v2 | Signed-facts check result containing an unapproved v3 preview |
| das-approved-facts/v1 | Native signed, scope/target/policy/catalog-bound fact payload; not self-authenticating approval |
| das-approved-facts-preview-input/v1 | Public signature/current-binding probe under supplied context; produces a check/v2 result containing an unapproved v3 preview |
| das-text-delta/v1 | Existing string append/replace in a planned lane |
| das-text-delta-end/v1 | All planned lane watermarks and final semantic digest |
| das-action-authorization/v1 | Exact action grant; native signature and current-state checks are separate |
| das-candidate-binding/v1 | Complete committed regular-file tree and pinned external material bytes; not worktree or build qualification |
| das-version-tree-plan/v1 | Exact generation, complete preimage/postimage and per-file ownership/deletion plan |
| das-version-switch-receipt/v1 | Unsigned staging native reference fact; authority and qualification are false |
| das-integration-plan/v1 | Exact source C, actual I, B/generation, verification plan/evidence and integrate Decision references |
| das-integration-receipt/v1 | Actual target CAS result with the same C/I/verification bindings; staging authority/qualification remain false |
| das-completion/v1 | Immutable task/revision/cycle completion, actual integration receipt, current completion Decision and parent state; staging only |
| das-verification-plan/v1 | Approved exact C/B/I/task/context, slots, assertions, action denominator and fixed no-reuse aggregation |
| das-verification-evidence/v1 | Native DSSE purpose-bound results with original run/attempt/report/artifact identities; scoped original readback required |
| das-action-decision/v1 | Native DSSE action/audience/actor/target/receipt-bound conclusion; not business authorization or execution |

## Complete requirement preview

The current requirement catalog has schemaVersion `3.0.0`, 1,745 legacy leaves
and 978 edition leaves (2,723 total), mapping 518 legacy carriers. Current full
input/output identities are `das-bundle-preview-input/v3` and
`das-bundle-preview/v3`. Historical v1/v2 contracts retain their declared reading
scope; the current catalog cannot be submitted under v2. A fixed binary rejects
missing, modified or unsupported catalogs. Catalog completeness is not approved
applicability, permission, execution success or deployment qualification.

The single Standard authors are `standard_modules.json`,
`standard_requirements.json` and their schemas. Their reviewed embedded copies
are `cadence-core/internal/resolver/testdata/module_catalog.json` and
`cadence-core/internal/resolver/requirement_catalog.json`; schemas are alongside
them. Compare exact bytes against the chosen Standard revision when changing
copies, then build and check the consumer. There is no public
`tools/generate_contract_copies.py` command in this checkout.
The signed-facts request stays `das-approved-facts-preview-input/v1`, its DSSE
payload stays `das-approved-facts/v1` with payloadType
`application/vnd.das.approved-facts.v1+json`, and its outer result is
`das-approved-facts-check/v2`. Only the embedded preview is v3.

Each trace row records true/false/unknown/conflict applicability, not a passing
check. Source contexts preserve normative strength, alternatives and approved
preapproval policies. Complete mapping can be true while authorityVerified and
qualificationEligible remain false; approved applicability and actual protected
execution are separate boundaries.

Catalog input has a fixed 262,144-node budget because the current authored
requirement catalog exceeds 100,000 parsed nodes. Only explicit v2/v3 catalog preview input
and the signed-facts preview input select it; the embedded requirement catalog
uses the same budget. Generic JSON, v1 preview input, action grants and signed
fact payloads retain 100,000 nodes. The 4 MiB byte limit, depth 64, exact numeric
domain and duplicate/Unicode rejection are unchanged. Both budgets produce the
same RFC 8785 bytes and digest for a value they accept. A larger budget neither
accepts arbitrary mandatory catalogs nor grants authority. The generic
`contracts canonicalize --identity das-json-jcs/v1` command keeps its original
parser budget; use the explicit resolver input for catalog exchanges.

The S13 storage leaves bind complete paragraph groups and native strength
phrases. The reference connection-constraint proof remains SHOULD, while the
selected explicit MUST/MUST NOT clauses keep their original force. Their source
block is independently pinned, including process/system crash distinctions,
ordinary-read limits, rollback/retry, post-backup facts, cross-storage atomicity
limits and unknown recovery. No metadata converts these checks into passed
durability or a guarantee against arbitrary disasters. Failure/identity-conflict
handling applies to the configured authoritative write path before any failure
occurs; caller claims that no error occurred or writes are not permitted cannot
waive that denominator. Specific system-crash artifact obligations retain their
declared fault-model condition; Linux directory synchronization additionally
retains its filesystem condition. Narrower durability scope does not waive other
applicable writing, recovery and truthful qualification obligations.

The S13 control leaves retain the independent bounded-stop path, immutable audit
checkpoint, truthful nonexecution recovery, read reference bindings, capability
address handling and limited continuous disclosure. Their full source contexts
and exceptions are independently pinned. A configured write/read path must
include its denial and recovery duties before any fault or permission decision;
`permission.read_allowed=false` or `failure.revoked=false` cannot waive them.
Capability addresses are authorization material, not ordinary public artifact
references. The capability audience source is taken after its own force carrier,
not the earlier reference-audience occurrence with another scope.

Continuous disclosure predicates require both protected reads and a continuous
path. They preserve public-data policy, do not force all public downloads through
a private gateway, do not require per-byte authorization and do not claim that
revocation retrieves data already legitimately released. Byte/record/time limits,
continuation checkpoints, revocation effect/confirmation and residual in-flight
volume/time bounds are distinct obligations. Ordinary protected reads still
need identity/resource/purpose/audience bindings when no continuous stream or
capability address exists. This is applicability only: actual authenticated read,
bounded release and global revocation confirmation remain product integration work.

Fact keys for the predicates describe actual behavior:

| Key | Meaning |
|---|---|
| activity.ai_task_or_pr | The scoped work is an AI task or PR |
| change.contract_needed | The scoped work needs contract changes |
| change.contract_breaking | The scoped AI task/PR has a breaking contract impact |
| activity.protected_action | The scoped execution attempts/performs a protected action, including refused attempts |
| activity.delegation | The scoped authorization delegates permission |
| activity.evidence_consumption | The scoped verification consumes an evidence report |
| activity.agent_execution | An Agent participates in the scoped execution |
| activity.worker_execution | A Worker participates, including read/edit work rather than only candidate execution |
| activity.untrusted_execution | The scoped work executes untrusted code |
| activity.verification | The scoped work performs verification |
| activity.integration | The scoped work performs integration |
| material.external_required | External artifacts are necessary to the scoped candidate identity |
| risk.agent_authored_tests | The scoped verification includes Agent-authored tests |
| change.integration_competition | Integration encounters competing target changes |
| change.integration_rebase | Integration rebases the candidate |
| change.integration_merge_result | The merge result changes during integration |
| activity.completion | The scoped work requests/projects completion |
| activity.log_emission | The scoped work emits ordinary logs |
| activity.artifact_output | The scoped work outputs artifacts |
| activity.authoritative_write | The scoped configured path writes authoritative state, including error/conflict handling |
| activity.state_backup | The scoped path backs up authoritative transaction state |
| activity.artifact_registration | The scoped path registers artifacts as consumable qualification material |
| storage.system_crash_covered | The approved artifact-storage fault model includes system/host crash; not a durability test result |
| storage.linux_filesystem | The scoped artifact path uses the Linux filesystem protocol |
| activity.artifact_recovery | The scoped path reconciles artifact/reference recovery |
| activity.qualification_issuance | The scoped path issues qualification dependent on durable evidence |
| activity.audit_recording | The scoped path emits protected authoritative audit events/checkpoints |
| activity.protected_read | The scoped path reads restricted protected material; not a grant or success flag |
| activity.capability_url_handling | The scoped path handles addresses bearing access tokens/signatures/session capability |
| activity.continuous_disclosure | The scoped path supports downloads, paging, subscriptions or delayed feedback; restricted disclosure additionally requires protected_read |

Facts are proposals with sourceRefs, not approved scope or evidence of success.
Missing facts remain unknown; disagreements retain all sources as conflict.
Z02 approval/unknown-risk handling and Z12 provenance/safe-stop duties are
unconditional. With no facts, these 13 leaves are true and the other 122 unknown.
Z06 verification and integration are evaluated separately; each external binding
also requires material.external_required. Z07's Agent-test restriction requires
verification and risk.agent_authored_tests. Z09's three recheck triggers require
integration and their respective change facts. Nonbreaking changes do not acquire
the legacy compatibility-plan duty. Permission flags or claimed absence of a
failure cannot suppress Worker protections, forbidden completion shortcuts or
safe-stop duties. Facts describe activity, not the permission to perform it.

For a source-development probe, form an input object with contractIdentity
`das-bundle-preview-input/v3`, a nonempty scope, a `sha256:` policyDigest,
`catalog` loaded from Standard's standard_modules.json, `requirementsCatalog`
loaded from standard_requirements.json and a `facts` array. Each fact has key,
boolean or `unknown` value and sourceRef. Run `cadence resolve --preview` with
this exact JSON on stdin; protected resolution remains disabled. For dasops,
use `standards resolve-preview` with that input and the absolute binary path,
runtime release version and binary digest pins shown by its help. It checks
the runtime identity, both catalogs' digests, complete unique leaf coverage,
ownership, parent clauses and the response digest without reimplementing rules.
The root integration test exercises this path with an actual Go binary.

## Signed-fact binding probe

Use `das-approved-facts/v1` only as the inner payload of DSSE with payload type
`application/vnd.das.approved-facts.v1+json`. The selected key must be eligible for
`facts_approver` under the expected issuer. This is distinct from action grants
and evidence signers. All scope, audience, proposing principal, candidate and
deployment-baseline digests, policy ID/digest/generation/authority epoch, fact
ID/generation, Standard version and both catalog digests are inside the native
signature. Facts retain their boolean/unknown value and sourceRef. The approved
policy and target shapes are embedded definitions, with no second schema author.
`candidateDigest` is the JCS SHA-256 of the exact `das-candidate-binding/v1`
object, rather than a Git OID or archive hash. `deploymentBaselineDigest` is the
JCS SHA-256 of the separately approved deployment baseline record. Comparing
these references does not itself verify those objects or the deployed resources.

The probe input contains that envelope, the two Standard catalogs and an explicit
`controlContext`. The context supplies expected identities/bindings, both
revocation states, a trusted-observation uncertainty interval, observation time,
staleness bound, keys/principal/issuer/roles and threshold. A public caller can
choose these values: **the probe does not authenticate the installed control
plane, current state or real identity separation**. Its output deliberately
returns `das-approved-facts-check/v2` with `authority=false` and
`qualification=false`. Its embedded `das-bundle-preview/v3` reports
`leafMigrationComplete=true` for the current 2723-leaf complete catalog, while
`authorityVerified=false` and `qualificationEligible=false`. The probe input is
`das-approved-facts-preview-input/v1`; the signed inner payload and its DSSE
payload type remain v1. It is not a formal Bundle or permission to adopt, integrate or complete.

Run `cadence resolve --check-approved-facts` with this explicit JSON on stdin.
The existing pinned Python adapter exposes `resolve_facts_preview`; the existing
`dasops standards resolve-preview` command selects it by the new input identity.
The runtime version/binary pin, bounded I/O, full trace and all response digests
are checked as for ordinary preview. Python decodes the same payload only for
response binding; native signature verification and rule evaluation remain Go.
No new launcher, service, state store or Python rule evaluator is introduced.

The earliest/latest observation must fit the signed [notBefore, expiresAt)
window, including uncertainty at the exclusive expiry boundary. Observation may
not be later than earliest or older than the supplied bound (1–30 seconds).
Missing/stale/revoked current state rejects. Policy/fact generations use exact
safe integers, never float rounding. Both catalogs must match the pinned binary's
supported digests; signing a rewritten catalog does not make it supported.
Only facts from the very verified payload enter the existing evaluator. Unsigned
alternate facts, duplicate key/source records and unsupported scalar values fail.
Missing facts remain unknown and disagreements remain conflict.

The proposing caller's keys cannot contribute to the approval threshold. Duplicate
keys/signatures and two keys mapped to one principal do not supply independent
approvals. An extra proposing-caller signature alongside enough independent
signatures is harmless; it does not count. Native envelope extensions retain DSSE
semantics, while the inner payload and diagnostic input are closed contracts.

Library rejections use the `resolver: approved_facts_` prefix with codes:
`schema_unavailable`, `invalid_input`, `revoked`, `invalid_time`,
`stale_or_uncertain_context`, `invalid_trust`, `invalid_envelope`,
`signature_rejected`, `invalid_payload`, `binding_mismatch`,
`generation_mismatch`, `outside_validity`, `unsupported_catalog`.
The public CLI exits nonzero without an applicability result; diagnostics do not
print signed payloads or trust data. This is never an empty successful Bundle.

The public deterministic Python/OpenSSL vector is test-only. Go checks its native
signature; actual pinned Go→Python and public CLI exchange checks expected false
obligations independently. Schema, binding, revocation, time, role/issuer,
independence and byte-tampering negatives exercise the failure paths. Production
activation still requires protected current state and independent roots supplied
by the installed control plane, complete leaf migration and formal Bundle/adopt/
Context Pack consumers. Do not substitute these fixture values at that boundary.

Text streams use JSONL lines under the separate `das-text-jsonl/v1` transport.
Each lane starts at zero and advances continuously. Same sequence/content is a
replay; different content conflicts. Reconnect does not reset total budgets.
Pointers decode once into tokens and use actual object/array semantics: object
`01` is legal; array `01` and `/outputX` outside `/output` are rejected. Only a
validated end record completes a stream. EOF alone does not complete it. The
current in-memory materializer is not restart-persistent; service integration
must retain operation identity and budget history before authorizing recovery.

The DSSE profile uses
`application/vnd.das.action-authorization.v1+json` and the `action_authorizer`
role. The first grant contract permits exact-scope actor delegation, shorter
validity and reduced cost. It does not support resource, action or parameter
expansion. Parent records come from the protected store. Trusted time uses an
uncertainty interval; both boundaries must be inside every validity window.

Sources: [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785),
[RFC 6901](https://www.rfc-editor.org/rfc/rfc6901),
[DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).

The resource intent author is `schemas/das_v1_5/resource_action_intent.schema.json`
(`das-resource-action-intent/v1`). The exact validator registers it, and the
monorepo generator produces the dasops resource copy. Its request digest covers
stable task/resource/action/parameter/tool/policy/budget/cost data. Current
credentials, authorization epoch and lease generation belong to the action
check, so their renewal does not create a different business action. The dasops
outbox bounds this intent to 64 KiB and retains verified native receipt bytes.

Candidate reception recomputes Git blobs/trees/commit identity from bounded bytes;
it invokes no Git or candidate program. The profile supports strict complete
USTAR and one gzip member with separate raw/decoded digests. Links, gitlinks and
unexpanded LFS reject until a separate approved mapping is implemented. Source
attributes are retained without applying export-ignore/subst. The importer,
approved closure and final OS storage boundaries remain separate required work.

Version-tree plans and receipts describe a same-database staging CAS, not a signed
Decision, Integration Receipt or Completion. An action's sole parameter is the
retained plan digest; actual authority/fencing is rechecked at the resource point.
Rollback requires the original postimage and generation and advances generation
while retaining security history. The dasops candidate package includes the
full storage/recovery instructions. These Python consumers are registered in the
exact protocol validator; Go consumption/reader compatibility must close before
using them for any formally negotiated cross-language protected exchange.

## Executable current-catalog example

From the Cadence repository root, after building `cadence-core/cadence` with the
documented Go toolchain, this example checks current identities and refuses v2:

```bash
python3 - ./cadence-core/cadence <<'PYCODE'
import json, subprocess, sys
from pathlib import Path
root = Path("cadence-core/internal/resolver")
request = {
    "contractIdentity": "das-bundle-preview-input/v3",
    "scope": "synthetic-doc-smoke",
    "policyDigest": "sha256:" + "0" * 64,
    "catalog": json.loads((root / "testdata/module_catalog.json").read_text()),
    "requirementsCatalog": json.loads((root / "requirement_catalog.json").read_text()),
    "facts": [],
}
run = subprocess.run([sys.argv[1], "resolve", "--preview"], input=json.dumps(request), text=True, capture_output=True, check=True)
result = json.loads(run.stdout)
ids = [row["requirementId"] for row in result["requirementTrace"]]
if len(ids) != 2723 or len(set(ids)) != 2723 or result["contractIdentity"] != "das-bundle-preview/v3":
    raise SystemExit("Unexpected catalog/preview identity")
if result["leafMigrationComplete"] is not True or result["authorityVerified"] is not False or result["qualificationEligible"] is not False:
    raise SystemExit("Incorrect authority boundary")
request["contractIdentity"] = "das-bundle-preview-input/v2"
old = subprocess.run([sys.argv[1], "resolve", "--preview"], input=json.dumps(request), text=True, capture_output=True)
if old.returncode == 0:
    raise SystemExit("Current catalog accepted under historical v2")
print("2723 unique leaves; v3 non-authoritative preview; v2 refused")
PYCODE
```

# Linux reference controller — development status

`controller.py` is a bounded, native Docker reference mechanism. It does not
activate govern, authorize resources, run all beta acceptance or issue a signed
qualification. The tested Python image is a development fixture. A final approved
build image, installed controller/source identity, complete independent driver /
signer topology and final package qualification remain required.

## Selected Linux installation and offline image restoration

The development reconstruction uses Ubuntu 22.04 / Linux
`5.15.0-125-generic`, cgroup v2, Docker `29.1.3`, containerd `2.2.1`
and runc `1.3.4`. These are observed inputs, not a promise that every host
with those version strings is qualified. The installer supplies and locks the
base OS, actual executables, configuration, storage and required capabilities.
This reference does not build an OS distribution or install/upgrade host packages.

1. Keep the tool payloads, Python/backend/Go materials, Docker-load archive and
   selected-child OCI verification archive as distinct hashed materials. Obtain
   them in the preparation domain and verify complete bytes before installation.
   The OCI parser below never loads an image. A selected-child verifier archive
   alone may omit the originally approved index blob and cannot restore that ID.
2. For the selected index-ID configuration, use the containerd image store. A
   traditional Docker `vfs` image store can load the same archive as its image
   **config** ID and lose the original index-ID address. Do not replace the
   approved ID to make that installation pass; refuse the unsupported combination.
3. Test restoration in a separately administered daemon. Explicitly set its own
   Docker data/exec/PID/socket paths **and** its own containerd address/root/state.
   A new Docker data root alone does not isolate the default shared containerd.
   Keep runtime paths short enough for internal AF_UNIX sockets (108-byte limit,
   including runtime-added suffixes). Disable unused containerd CRI/NRI plugins.
   For this no-network combination, disable bridge, IPv4/IPv6 iptables, forwarding
   and masquerading. Never rewrite the shared daemon's configuration or prune it.
4. Use an empty private Docker client configuration and an explicit local socket:

   ```bash
   docker --config "$PRIVATE_CLIENT" --host "unix://$PRIVATE_SOCKET" image ls --quiet
   docker --config "$PRIVATE_CLIENT" --host "unix://$PRIVATE_SOCKET" image load --input "$VERIFIED_BOOTSTRAP_ARCHIVE"
   docker --config "$PRIVATE_CLIENT" --host "unix://$PRIVATE_SOCKET" image inspect --platform linux/amd64 "$APPROVED_IMAGE_ID"
   docker --config "$PRIVATE_CLIENT" --host "unix://$PRIVATE_SOCKET" info --format '{{json .}}'
   ```

   Record an empty store before load, the restored original index, selected child,
   native daemon ID and the actual store/platform. Populate the existing five-field
   `EngineConfig` from independently installed inputs; an old daemon ID does not
   approve a new daemon. Pass the separate `ImageMaterial` and retain the actual
   Controller run, unchanged snapshot and whole-domain termination observations.
5. Materialized candidate entries must be readable by UID 65532 through the
   read-only mount: the fixture uses directory mode 0755 and file mode 0644 under
   a private host parent. Do not make authority files readable this way. Retain
   wrong-material refusal before creation as a control alongside legal execution.
6. In a disposable private runtime, test daemon death after trusted admission.
   Missing native termination observation must remain an error. Independently
   observe the guardian emptying the original cgroup, restart that same private
   daemon, reread the exact original container state and only then reconcile it.
   A daemon crash is not host power-loss, storage-device or SQLite durability proof.
   Stop only created processes and remove disposable state after preserving raw
   observations; keep the approved archives available for reconstruction.

Host browser libraries, fonts, certificates and SQLite/runtime prerequisites need
their own actual-use lock and supplier/installation evidence. An `ldd` or installed
package list is an inventory, not proof that those archives are available offline.
Source fallback, missing required materials or unknown controls refuse the affected
combination. Independent-host acceptance, role/custody approval and final same-byte
qualification remain separate from this same-host fresh-daemon diagnostic.

The fixed UI driver now retains `runtime-attempt-loaded-materials.json`: native
browser process IDs and start times, files actually mapped by Node/Chrome, and
their byte digests. Exited/inaccessible processes and deleted mappings remain
explicit observations of missing readback. Deleted browser shared-memory files
are runtime outputs, not a reason to download additional OS packages. An actual
mapped-file inventory still does not cover unexecuted supported branches or
approve suppliers. Reuse exact packages already prepared for linked libraries;
bind additional actual shared libraries to regular members of their original
packages. Keep host installation and third-party redistribution approval separate.

## HTTP inventory coverage consumer

`cadence contracts http-inventory --probe` continues to derive an Inventory with
`declaredCoverage=unknown`. Use `cadence contracts check-http-coverage --probe`
for the separate supplied-context comparison. Its exact input fields are
`inventory`, `baseline`, `observed`, and boolean `observationComplete`.
Baseline rows contain `operationId/method/path`; observed rows contain only
`method/path`. Both lists are bounded by the existing 1,024-operation limit.
A complete matching observation returns `coverage=matched`; incomplete discovery
returns `unknown`. Deleted declarations, reused identities, extra/duplicate routes
or malformed fields refuse. The result binds the JCS input digest and always
returns `authority=false/qualification=false`. The installer must independently
approve/protect the baseline and actual collector; caller-supplied strings do not
establish that approval. This check performs no HTTP requests or resource writes.

## Private signing material for installed reference diagnostics

The root acceptance harness's fixed integration driver can consume installer-owned
private test material instead of the public fixture seeds. This remains a TEST
diagnostic and grants no production or release qualification.

1. In the trusted installation domain, generate one exclusive 96-byte file using
   OS randomness: three distinct 32-byte Ed25519 seeds. Keep it outside the checkout
   and all candidate/Worker mounts, owned by the executor with mode 0600 and
   protected ancestors. Never commit, package or log its contents. Repeated-byte
   public fixture keys are refused. Installation owns the file's raw SHA-256.
2. In the existing `developmentInstallation`, supply both `signingMaterialPath`
   and `signingMaterialSha256`. The first key serves existing facts/grant fixture
   purposes, the second evidence/decision, and the third the fixed key-rotation
   control. Existing role policy still applies; separate required responsibilities
   using the actual OS/installation boundaries. These offsets are a fixed test
   recipe, not a new signing protocol or an externally callable signing service.
3. The controller-side driver rechecks ownership, ancestry, unique regular-file
   identity, length and digest before using a key. Only public keys and signatures
   reach evidence. Keys are passed to the existing OpenSSL signer through anonymous
   descriptors; candidate outputs never choose key paths or invoke that signer.
4. The optional existing `referenceWorkerUid` transport checks real/effective/saved
   UID and attempts to read the actual authority DB, private original and key file.
   All reads must fail while the authorized Unix request succeeds. Candidate
   execution additionally uses the existing container UID boundary. A named role
   or shared public seed alone is insufficient evidence of separation.
5. No material fields preserves historical TEST behavior. A single field, bad
   bytes, readable keys or drift refuses. Private material supports the fixed
   integration and analysis recipes; other recipes refuse these fields instead of
   reverting to public keys. Independent-host acceptance, approved trust/custody
   and the complete installed qualification path still require their own evidence.

## Installed inputs and privilege domains

1. Install this exact tracked controller and its fixed dependencies outside the
   candidate's directories and UID. Do not load it from candidate cwd, PATH,
   PYTHONPATH or a candidate-provided adapter path. The module uses only stdlib.
2. Administrators supply `EngineConfig(cli, cli_sha256, socket_path, image_id,
   daemon_id)`. CLI is a normalized absolute regular file with trusted ownership,
   no group/world write and a matching SHA-256. The controller copies those exact
   bytes to a sealed memfd; execution never reopens a candidate-selected name.
3. Use one fixed local Unix daemon socket and its exact native daemon ID. Remote
   contexts, inherited Docker configuration and credentials are excluded. The
   client uses a fresh private configuration directory and an explicit socket.
   Protect access to that socket as control-plane privilege.
4. Supply the approved local `sha256:<image-ID>`; this may name an OCI index or a
   child manifest. Inspect and create both explicitly select `linux/amd64`; pull
   is disabled. A Docker index ID and its selected child digest are different
   identities. Child content need not have an independent local image name, so
   create uses the approved original ID and checks the actual container's
   `ImageManifestDescriptor.digest` against the selected child. Reject unknown
   descriptors/platforms and implicit volumes. Approve contents and startup
   behavior independently; a matching digest alone is not approval.
5. Keep materialized inputs under the driver UID, private ancestors and
   non-writable files/directories for other UIDs. The snapshot binds all names,
   file bytes and modes. Reject aliases, symlink/hardlink/special members, >10,000
   entries, >32 MiB per file and >64 MiB total. These are limits of this reference
   mechanism, not a declaration that every DAS build fits the development image.
6. The host driver, in-container fixed guardian and candidate have distinct
   responsibilities. Guardian is PID 1 / UID 0 with only SETUID, SETGID and KILL.
   It never imports candidate modules. After admission it forks, clears groups,
   sets **all real/effective/saved UID and GID** to 65532, checks zero effective /
   permitted / inheritable / ambient capabilities and execs the fixed Python
   workload. No-new-privileges is inherited. Candidate cannot regain guardian UID.
7. The immutable guardian has its own 25-second CLOCK_BOOTTIME deadline. It remains
   alive after host controller death, observes the primary worker and exits on
   timeout or worker completion. PID-namespace init exit terminates descendants,
   including children that created another process group/session. The driver
   additionally kills the exact native container and observes termination.
8. Keep signer keys, authority DB, registry, engine socket and independently owned
   evidence storage outside candidate mounts. This controller mounts only one
   read-only input tree, without recursive submounts and with rprivate propagation.
   Root is read-only; /tmp is a bounded noexec/nosuid/nodev tmpfs. There is no host
   writable output mount. Candidate stdout/stderr are bounded raw data.

## Selected OCI material profile

Install `ImageMaterial(archive_path, archive_sha256, child_digest)` independently
and pass it as `Controller(config, image_material=material)`. These values are
control-side approval inputs; candidates cannot select them. The archive is a
normalized absolute, owner-controlled, regular, single-link OCI-layout tar, with
no group/world write. Keep its ancestors under the installed control identity.
The parser never extracts layers to the host or loads an image into the daemon.

`image_material_binding(material)` checks the complete archive hash, selected
linux/amd64 manifest and config raw bytes, compressed layer digests, ordered
uncompressed diff IDs, and their match to actual native image inspection. The
exported layout index's raw digest may differ from the approved original Docker
index ID; retain both. Unknown unselected extensions do not force fetching them.
Unsupported selected types/platforms, ambiguous selection, substituted/truncated
blobs, duplicate JSON keys, implicit volumes and wrong layer order are refused
before container creation. Bounds: 192 MiB archive/member total, 4,096 members,
1 MiB index/manifest/config, 64 layers and 256 MiB expanded layer total. This
finite profile supports raw tar/gzip OCI layers, not arbitrary image formats.

The native engine applies whiteouts, opaque-directory changes and mount overlays;
the controller binds those inputs rather than implementing another layer engine.
Retain both actual container manifest selection and runtime observations. Running
without `image_material` preserves the earlier limited runtime diagnostic; it
does **not** prove full OCI-material closure. Final approved build materials,
installer wiring and supported deployment qualification remain separate exits.

## Preparation, execution and termination sequence

1. `snapshot(materialized_root)` produces a byte binding for a controlled input
   tree containing the fixed entry `run.py`. Independent approval must supply the
   expected snapshot in production; a developer computing both values locally
   does not create that approval.
2. `Controller(config).run(root, expected_snapshot=..., timeout=...)` verifies the
   snapshot, actual daemon / image identity and cgroup-v2 platform. It creates one
   uniquely named, labelled container; it never searches, kills or removes others.
3. Observe native created controls: private network/IPC/cgroup namespaces, readonly
   root/input, explicit user/capability boundary, no privilege escalation, PID / CPU
   / memory limits and exactly the intended mount. Unknown/mismatched controls fail.
4. Start only the fixed `python3 -I -S` preparation/guardian. Disabling system-site
   startup avoids candidate site customization. No candidate code, metadata hook,
   dependency resolver or pytest collection executes before this domain exists.
5. Before admission, the fixed stage reports native namespace descriptors,
   privilege posture and UID. Driver compares all six namespaces to its own and
   independently reads the live native PID's cgroup, membership, memory.max,
   pids.max, cpu.max and memory.swap.max from the host kernel.
6. Recheck the snapshot. Write the admission marker using a fixed root helper in
   the same pinned image; no candidate argv or module is passed to that helper.
   The guardian drops worker credentials and emits a fixed pre-exec credential
   record before loading `run.py`. Candidate output after that boundary remains
   candidate-origin data even if it prints PASS or copies the record's strings.
7. Put all workload preparation, backend metadata, dependency handling and test
   discovery inside `run.py`. It may use authorized scratch within /tmp. The
   development Python fixture image does not supply final Python/Go/Node build
   dependencies; the approved build-image recipe and offline closure are pending.
8. The host controller bounds native calls/output. Timeout, output overflow or
   broken observation does not establish operation failure or a resource result.
   Resource effects must still use the separate durable action/reconciliation path.
9. Always stop the exact created container. Inspect native stopped state and PID 0;
   verify its actual cgroup disappeared or has no processes. `domainTerminated`
   is true only after those observations. If missing/unknown, refuse environment
   reuse and reconcile the original ID. Removal touches only this created ID.
10. Compare the input snapshot again and retain complete native observations plus
    candidate raw bytes in the separately protected evidence store. Display-safe
    copies cannot substitute for originals. Every returned record explicitly says
    `qualificationEligible=false` and `authorityVerified=false`.

## Independent output assertion and signed source exchange

The same controller now offers `verify_output(...)` for the original P09/P10
reference chain. It runs the fixed workload through `run`; it never parses a
candidate-produced report or signs candidate JSON. The installed driver supplies
the approved expected stdout bytes, exact input snapshot, gate ID and bounded
report metadata. Candidate requests must not choose those operands.

1. Verify/materialize the **actual I**, then obtain its execution-view mapping
   and approved snapshot. C's previous test does not qualify changed I.
2. Bind the installed controller bytes, actual EngineConfig, expected assertion
   and timeout to the verification slot's config digest. Keep the existing
   plan/binding/config/shard/run/attempt identities; no new exchange schema exists.
3. Call `verify_output` before opening a writer transaction. It returns the
   Standard's existing Verify Report and the complete original native observation.
   `pass` needs zero integer exit, exact candidate stdout, unchanged snapshot,
   observed whole-domain termination and no collection/runtime error. Nonzero
   exit/output mismatch is `fail`; missing/type-confused observations or runtime
   failure are `error`. A printed PASS, matching answer or process exit alone
   cannot establish success.
4. Retain the raw report, complete native observation and separate candidate
   output in the independently controlled original store. Report metadata is
   driver-origin; stdout/stderr stay candidate-origin. A missing candidate tail
   remains missing; retain available raw output without manufacturing a tail.
   This helper returns data; it does not create durable custody, authorization,
   signing roots or a collector service. The installed service must supply them.
5. Retain **all** attempts independently of the evidence submitter. Index an
   original by `(digest, runId, attempt)`, since real runs can emit identical bytes.
   Supply that full history's digest to the current native checker. Under the
   existing all-attempts-pass/no-reuse profile, a later pass cannot hide a failure;
   signing only the successful suffix cannot change the collected history.
6. The separately authorized signer may create the existing evidence envelope
   from these collected references; its Decision and action grant are distinct.
   The existing native qualification consumer rechecks originals at the actual
   SQL plan/CAS/Completion boundary. Do not run Docker or sign inside that writer
   transaction. Missing/cleaned required originals reject qualification.

`test_signed_integration_completion_exchange.py` runs this source exchange over
actual Unix peer authentication. It checks one and two real passing runs, forged
PASS, nonzero exit, timeout, failed retry, omitted history and lost native original.
Original A01.1 and A16.1/A16.2 source nodes consume selected mechanisms; a missing
native configuration/skip is rejected by their node driver. Those are partial
source checks, not complete original cases or installed beta qualification.
Production service identities/custody/current-control/signer approval, full
Standard adoption and all final package/deployment/trial exits remain open.

## Verification

### Fixed offline Python wheel preparation

`build_python_wheel.py` is an optional fixed workload for this existing domain,
not a host builder or release entry. Install it as the snapshotted `run.py`, with
the complete approved source in `source/`, and the exact local pure-Python
setuptools, wheel and packaging wheels in `wheelhouse/`. `build-inputs.json`
contains only `buildWheels` (filename to raw SHA-256) and `sourceDateEpoch`
(a fixed integer from 1980 through 2038). The installer approves the complete
snapshot, wheels, epoch and native image; candidate-computed hashes do not
provide that approval. Preserve source modes and independently verify provenance.

The backend imports, metadata hooks and build execute after credential drop,
inside the no-network domain. Scratch remains within the existing 64 MiB tmpfs;
this finite recipe accepts a wheel of at most 512 KiB and emits its raw bytes as
base64 within the existing 1 MiB output budget. It does not change controller
limits to support arbitrary Python/Go/Node projects. Backend diagnostics go to
raw stderr. There is no resolver, package download, signer or host output mount.

Use `Controller.run(..., expected_snapshot=..., timeout=...)` and always call
`close()` (or stdlib `contextlib.closing`). Collect both complete observations.
Require observed whole-domain termination and unchanged input, check the actual
wheel filename/member/metadata/content independently, compare two isolated runs,
then install those same bytes with hash-locked runtime dependencies in a separate
environment. A JSON checksum or successful backend exit alone is insufficient.
Distribution bytes may differ from an older development wheel solely through the
chosen epoch; retain both identities, rather than relabeling old install evidence.
Production image/material approval and the final three-component release remain
separate requirements. The development verification uses no release credentials.

Source boundary tests run with the ordinary standalone sandbox verifier. Native
runtime tests require an explicit owner-controlled mode-0600 config file with the
five exact EngineConfig keys; no default engine/image is inferred from worker data.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s cadence-sandbox/tests -p test_das_v15_reference.py
CADENCE_DAS_V15_REFERENCE_CONFIG=/protected/reference-test-config.json \
  PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s cadence-sandbox/tests -p test_das_v15_reference.py
```

Without that config, native tests explicitly skip and cannot contribute runtime
qualification. With the actual local config, tests execute legal scratch work,
input-write and root-credential denial, a live host loopback reachability control
and blocked candidate connection/socket, descendants on timeout, forged PASS JSON,
and real host controller death with an independently observed stopped/empty domain.
They use temporary source fixtures and do not establish final installed package,
all Z controls, remote resource authority or independent signing.

Original A06.1/A06.2 source drivers also test host surfaces with harmless markers.
Before launch the independent host can read the protected marker and connect to
the real mode-0600 Unix control socket. In the candidate, both probes must raise
OSError while legal scratch still works; afterwards the marker is unchanged and
the control socket has received no candidate connection. A second probe opens an
explicitly inheritable host marker fd and sets a TEST control environment value.
The actual candidate fd inventory must contain no matching device/inode, the
control variable must be absent and its real/effective/saved UID must be 65532.
The original host fd remains readable. No real key, token or production service
is used. These execute isolation mechanisms, not a complete access inventory,
approved account topology, metadata/proxy configuration or deployment acceptance.

Run the two original drivers from the DAS Tools root with the same configured
native runtime and its installed dependencies:

```bash
CADENCE_DAS_V15_REFERENCE_CONFIG=/protected/reference-test-config.json \
  PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -q \
  tests/das_v1_5/test_a06_isolation_access.py
```

Unlike standalone discovery, these original drivers fail if native probes skip:
missing config or permission to launch is not an executed access-denial result.
Keep raw native output/XML and actual engine/daemon/image/controller input pins
outside Git; do not promote source TEST results to installed qualification.

Docker options and mount behavior are grounded in the official
[bind mount reference](https://docs.docker.com/engine/storage/bind-mounts/),
[container create reference](https://docs.docker.com/reference/cli/docker/container/create/)
and [resource limits](https://docs.docker.com/engine/containers/resource_constraints/).
The controller verifies the actual selected engine/kernel behavior rather than
assuming an option's presence proves enforcement.

# Relay-fault authority transaction

The relay-restart qualification authority is part of the deployment rollback
tuple. A failed candidate must not leave a new gate key, relay public-key
authorization, SSH policy, or sudo policy behind.

## Transaction boundary

The orchestrator transfers three root-owned public inputs only: the relay host's
SSH Ed25519 public key to the gate host, and the gate's SSH Ed25519 public key
plus its OpenSSL Ed25519 permit-signing public key to the relay. Relay-side
transfer files live only in a fresh transaction-ID-bound, root-only `/run`
directory and are not authority by themselves. The OpenSSL private key is
created and retained as a root-only file on the gate; it is never copied to the
relay or orchestrator host.

On the gate host, `install-edge-lab.sh` validates the host-key input and the
existing relay-fault tree before taking its snapshot. It then assembles and
verifies the candidate release. Only after the snapshot is complete does the
manifest-bound provisioner create or update `/etc/campus-link/relay-fault`.
That mutation creates or validates both the dedicated SSH keypair and a
canonical OpenSSL Ed25519 permit-signing keypair. Every private and public key in
that tree is root-owned with one link; both permit-key files are mode `0600`.
That entire tree was already recorded as present or absent, so the installer's
ERR trap and `rollback-edge.sh` restore it exactly.

On the relay, `install-relay.sh` validates the account, prior authority tuple,
and public-key input before taking its snapshot. The snapshot covers the forced
authorized-key file, the SSH Match drop-in, the sudoers rule, the root-owned
permit public key, and all four manifest-bound helper executables. The installer
then applies the authority, validates both SSH and sudo syntax, reloads SSH, and
verifies the exact installed state. `rollback-relay.sh` restores the files,
revalidates both configurations (including the effective per-user SSH policy),
and reloads SSH before it records a successful rollback.

The SSH Match policy disables global key-command and user-CA/principal sources
for this account, pins the one dedicated authorized-key file and forced command,
and resets with `Match all` so the include cannot leak its scope into later SSH
configuration. (`PermitUserEnvironment` is not a legal Match keyword and is
therefore never emitted there.) The forced-command entry point uses
`/bin/bash -p`, rejects inherited `BASH_ENV` and `ENV`, and can reach root only
through two exact, zero-argument, `NOSETENV` sudo command paths, pinned to the
`root:root` run-as identity: the restart actuator and the permit authorizer.
Both root helpers consume their bounded
request frames on standard input. Validation inspects the effective per-user
`sshd -T -C` policy, not
only the text of the drop-in: `permituserenvironment` must resolve to `no`, and
`SetEnv` must be absent. Effective `AcceptEnv` may be absent or contain only the
exact conventional `LANG` and `LC_*` tokens; every broader wildcard or pattern
is rejected because sshd constructs the forced-command environment before the
helper can clear it. `UseDNS` must resolve globally to `no`, so the `Host`
criterion is the numeric authorized source and reverse-name ambiguity is
rejected rather than guessed. Validation expands every configured numeric SSH
listener over every currently configured same-family local address and port,
then evaluates the complete policy for each actual
`user,host,addr,laddr,lport` context. A hostname listener, missing local
address, empty or unbounded context inventory, or context-dependent unsafe
result fails closed. Provisioning performs this matrix for the source address
authorized by the dedicated key (and a replacement transaction's candidate
source); rollback recovers that source from the exact restored key entry before
evaluating the same matrix.

The same command-specific sudo policy disables both a caller-TTY requirement
and sudo pseudo-terminal allocation
and every aggregate and stream-specific input/output logging flag for those two
binary-framed helpers. It resets the
preserved- and checked-environment lists to one inert sentinel name, disables
both trusted and restricted environment files, supplies a fixed system path,
and explicitly deletes shell, locale, loader, OpenSSL, pager, and
temporary-directory control variables. The proof consumes sudo's full verbose
effective listing across all configured policy sources. It accepts exactly two
local entries, each with one zero-argument helper, `root:root`, and only the
`NOPASSWD:NOSETENV` tags. It also accepts exactly the two closed
command-specific Defaults bindings above; any additional command grant,
argument form, run-as identity, policy source, runas/command Defaults binding,
PTY or I/O logging flag, or environment widening fails closed. This is an
enumeration of the merged result, not a sample query for a few known commands.
The former wildcard-argument actuator rule is not an accepted migration
baseline; it must be removed through an explicit separately reviewed recovery
before this candidate can provision authority.

## Relay mutation serialization

Every relay install and rollback uses one lock order:

1. `/run/campus-link-install-relay.lock` (deployment/rollback ownership),
2. `/run/campus-link-relay-fault/actuator.lock` (permit and restart state),
3. `/run/campus-link-provision-relay-fault.lock` (authority files).

The authority provisioner takes the third lock in its subprocess while the
installer retains the first two. An installer's ERR rollback receives and
validates the already-locked deployment and actuator file descriptors instead
of opening them again; an independently invoked rollback opens all three in the
same order. No error path unlocks between failed mutation and restoration.

While holding the actuator lock, install and rollback atomically move any
root-owned pending `expected-run.env` into a bounded root-only revoked directory.
This revocation is deliberately outside the rollback snapshot: restoring an old
public key or helper can never resurrect an outstanding permit. The consumed
`used/` replay ledger is neither snapshotted, removed, nor rewritten.

Each mutating provisioner call also requires a root-only, transaction-ID-bound
permit inside the completed snapshot. The installer removes that permit after
the mutation, and rollback removes it on every error path. A completed snapshot
alone therefore cannot be reused later to change authority.

## Inert account bootstrap

Linux account databases are deliberately not copied and replaced during
rollback. The `campus-link-fault` account is instead a one-time prerequisite,
like the relay service account. Its bootstrap is bounded and fail-closed:

- a pre-existing user/group pair is never modified and must match the exact
  home, `/bin/sh` shell, primary-group-only, non-root, unusable-password, and
  complete shadow-aging contract;
- a partial or conflicting user/group state is rejected;
- a newly created account uses no home, an unusable `*NP*` password value, and
  has no authorized-key, SSH Match, or sudo authority;
- a failed new-account creation attempts to delete only the exact user/group it
  just created;
- public-key authorization, forced command, and sudo authority are installed
  only later, inside the relay installer transaction.

New accounts normalize the shadow tuple to an unusable `*NP*` password, a
nonzero non-future last-change day, minimum age `0`, maximum age `99999`, warning
age `7`, and empty inactivity, account-expiry, and reserved fields. Existing
accounts are validated against that complete tuple and are never rewritten.
Every account predicate and database read propagates failure explicitly even
when the validator is called from a conditional expression; a later successful
predicate can never mask an earlier mismatch.

Rollback derives the restored SSH source restriction only from a root-owned,
mode-0600, single-link regular `authorized_keys` file whose one canonical entry
matches the pinned Ed25519 identity, forced command, and CIDR contract. Every
file, syntax, identity, and address predicate propagates failure explicitly,
and the caller rejects a failed derivation before SSH is reloaded.

## Gate-local transport artifact

`relay-restart-transport.sh` is a manifest-bound gate-only executable. The edge
installer snapshots and installs it beside the restart driver, rollback restores
it exactly, deployment verifies its installed digest against the candidate
manifest, and the candidate fingerprint includes it. It is never placed in the
relay staging directory or installed on the relay.

If a first deployment fails after account bootstrap, the harmless exact account
may remain, but it has no authentication path or privilege rule. A retry merely
validates it. Existing deployments retain their prior account and authority
exactly on rollback.

## Failure invariants

- Invalid input or an unsafe prior authority tuple fails before a snapshot or
  persistent mutation.
- Any failure after an authority mutation triggers the same transaction's
  rollback.
- The outer orchestrator records an edge install attempt before opening its SSH
  command. If the connection is interrupted after mutation and the installer's
  local ERR trap cannot finish, the orchestrator detects the still-complete
  snapshot and retries that exact transaction's rollback.
- A relay rollback is incomplete until restored SSH and sudo configuration
  validates and the active SSH daemon reloads it.
- Temporary transfer cleanup cannot turn a successfully installed edge into an
  untracked orchestrator failure; cleanup is bounded again in the finalizer.
- No private key leaves the gate host.

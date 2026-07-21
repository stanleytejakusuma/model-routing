# model-routing

A capital-action gate for LLM agents. An agent that can run shell commands should never be able to fire an irreversible action on its own: restart a live trading signer, place an exchange order, read a signing key, move funds. This system classifies every proposed tool call, blocks anything capital-shaped, and only lets the action through when a signed, single-use intent exists that is bound to that exact action and has been approved by an independent LLM reviewer and confirmed by a human.

The code here is the real enforcement stack I run in front of a coding agent that works inside repos which control live trading capital. Hostnames, paths, and service names in the configs and corpora are fictional stand-ins; the logic, tests, and red-team corpus are the real thing.

The core bet: authoring code is reversible, so the agent edits capital-repo source freely. Executing a live-capital trigger is not reversible, so that single class of action routes through cryptographic authorization with a human at the end of the chain.

## Threat model

Defended against:

- A confident-wrong agent that decides mid-task to "just restart the signer" or "just place a small test order".
- Prompt injection that steers the agent into reading key material or firing a service mutation.
- Trigger smuggling: hiding a capital command behind newlines, `bash -c`, `env` wrappers, semicolon chains, ssh to a production host, heredocs, herestrings, or command substitution.
- Replay: reusing a previously approved intent for a second execution.
- Swap-after-approval: getting one command approved, then executing a different one, or executing the approved command after the reviewed repo state has changed.

Out of scope: an adversary with root or sudo on the gatekeeper host, and an agent that already owns the gatekeeper user. The design assumes the gatekeeper host and user are outside the agent's control; that separation is the point.

## Architecture

```
tool call (Bash / Edit / Write)
  |
  v
classifier (deterministic, triggers-only)          src/model_routing/classifier.py
  | non-capital or read-only -> allowed, no ceremony
  | capital trigger -> blocked until authorized
  v
approval request, exact action + context           src/model_routing/lifecycle.py
  |
  v
independent LLM review (fail-closed)               scripts/request_capital_approval.py
  |  reviewer fetches repo state itself; any error,
  |  timeout, empty output, or ambiguous verdict = REJECT
  v
worktree state binding                             src/model_routing/statehash.py
  |  git tree SHA over tracked + untracked files,
  |  computed with a scratch index
  v
human confirmation (typed, per request id)         scripts/gatekeeper_sign.py
  |
  v
Ed25519 signature by the gatekeeper                src/model_routing/intents.py
  |  separate host, separate user, private key 0600,
  |  owner-checked, never inside the agent workspace
  v
execution gate                                     scripts/pretooluse_hook.py
     signature valid, all 7 binding fields match the
     live action, not expired, tree SHA unchanged,
     nonce unseen -> consume nonce, allow ONCE
```

The classifier is triggers-only. It does not gate by directory or by vibes. An action is capital only if it matches an enumerated trigger: secret, key, or vault access (read or write), a registered capital-service mutation, a mutating HTTP call to a registered live exchange host, or a transfer-shaped operation naming a registered capital address. Everything else, including edits to capital-repo source files and dev commands run inside capital repos, passes without ceremony. Bash commands are scanned in full so a trigger cannot be smuggled by position or shell wrapping.

The intent record binds 16 fields, including the exact action string, cwd, repo id, host, target, risk class, reviewer identity, policy version, the reviewed tree SHA, a nonce, and an expiry. Verification checks the signature over canonical JSON, then requires exact equality on every binding field against the action actually being executed. Change one character of the command and verification fails with `binding-mismatch:exact_action`.

Replay protection is a directory-backed nonce store where `O_EXCL` file creation is the commit. It is race-safe: the test fires 8 concurrent verifications of the same signed intent and exactly 1 wins, 7 get `nonce-replay`.

State binding kills approval-then-drift. The approval records a git tree SHA computed through a temporary index, so tracked edits, untracked additions, and deletions all change the hash. At execution time the hook recomputes it; drift invalidates the pending intent on disk and blocks. Reverting the drift byte-for-byte restores the hash and the intent works again. All 14 hook isolation checks, including commit drift, unstaged drift, untracked add, untracked delete, and drift-then-revert, run in `scripts/test_hook_isolation.py`.

Failure posture is layered and deliberate. The LLM review, the signing path, and the intent verification fail closed on every error class. The local PreToolUse hook fails open on internal errors (bad stdin, missing config) so a hook bug cannot wedge every tool call in every session, but once an action classifies as a capital mutation in enforce mode, any error in intent checking or state verification fails closed. The kill switch is split: `DISABLE_MODEL_ROUTING=1` can turn off non-capital routing, and no environment variable can disable the capital gate. Bypass requires an expiring break-glass record with a written reason, a named human, and an audit log path.

## The red-team harness and what it caught

`scripts/redteam_harness.py` replays a corpus of known-bad and known-good actions through the full pipeline (classify, approve, sign, verify, consume) with throwaway keys, executing nothing. Current corpus: 59 cases, 43 known-bad, 16 known-good.

```
cases=59 known_bad=43 detected_bad=43 known_good=16 allowed_good=16
recall=1.000 precision=1.000 false_negative=0 false_positive=0
```

The harness exits nonzero on any false negative, so it works as a CI gate. Three findings from running it against earlier versions of the classifier shaped the current design:

1. The keywordless exchange order. A `curl -X POST` to a live exchange order endpoint with no trading vocabulary in the command slipped the first trigger set, which looked for words like "order" in the wrong places. The fix detects mutating-HTTP shape (method flags, data flags, order-path fragments) and requires the URL to hit a registered exchange host. Plain GETs to the same host, and downloads from data mirrors, stay free.

2. The heredoc false positive, then 25 attempted bypasses. Writing a spec file through `cat > spec.md <<'EOF'` that merely mentioned `systemctl restart signer.service` in prose was blocked, which pushed the agent toward worse workarounds. The fix recognizes exactly one authoring shape: a whole-command literal `cat` heredoc with a quoted delimiter and a verified regular-file sink, and strips only the body from the scan. Everything that deviates falls back to the full scan. The corpus then grew 25 adversarial variants that must still block: interpreter-after-write, `chmod +x` then execute, dot-source, `tee | bash`, ssh with `bash -s`, unquoted delimiters that trigger command substitution at write time, `<<-` dedent tricks that hide a trigger after a fake terminator, `/dev/stdin` and `/proc` sinks, symlink sinks, variable sinks, `crontab -`, and herestrings. `scripts/test_heredoc_canary.py` additionally executes the two allowed authoring cases in a sandbox with shimmed `systemctl` and `docker` binaries and fails if either shim ever fires.

3. Secret-surface false positives. Reading `id_ed25519.pub` or running `vault-up.sh` was gated as secret access. Public keys are published material, and a `vault-` prefixed shell script is tooling, not a vault bundle. Both carve-outs are narrow: explicit registered paths are never relaxed, and the invariant test proves that bundling a real secret next to a benign script (`tar czf b vault-up.sh vault-trading.age`) still blocks.

## Shadow-runner deployment pattern

Nothing here arms itself. The path to enforcement:

1. `scripts/shadow_runner.py` replays a corpus of realistic actions against the registry and prints would-allow and would-block with the reason chain, executing nothing.
2. The hook installs in shadow mode first (`MODEL_ROUTING_MODE=shadow`, the default). It classifies live traffic and logs capital mutations it would have blocked, and never blocks. You read the log until the false-positive rate is boring.
3. `scripts/test_hook_isolation.py` drives the hook as a subprocess with controlled stdin and env and asserts exit codes and side effects for all 14 scenarios before the hook goes anywhere near a live session.
4. `scripts/dry_run_install.py` prints the install plan (key custody checks, nonce stores, non-agent-owned hook paths) and performs none of it.
5. Enforce mode turns on only after the pre-arm checklist in `config/policy.json` passes: registry human-reviewed, key provisioned outside the agent workspace, break-glass audited, split kill-switch verified, red-team harness green.
6. `scripts/gatekeeper_selftest.py` runs on the gatekeeper host with the deployed keys and proves classify, sign, verify, and replay-refusal end to end before the system is trusted.

The runtime flow once armed: the hook blocks a capital mutation, the operator runs `scripts/request_capital_approval.py` with the exact action, the independent review runs, the operator types CONFIRM, the gatekeeper signs over ssh, a pending intent lands on disk, the retried action consumes it exactly once.

## Repo layout

```
src/model_routing/
  classifier.py     triggers-only capital classifier, heredoc authoring exclusion
  registry.py       human-owned capital registry: repos, services, hosts, surfaces
  intents.py        Ed25519 signed intent records, nonce store, verify_peek / verify_intent
  lifecycle.py      classify -> approval request -> signing request -> gate checks
  approval.py       two-sided approval loop, reviewer and human confirmer seams
  statehash.py      worktree tree-SHA state binding via scratch git index
  breakglass.py     expiring, audited bypass records
  kill_switch.py    split kill switch, capital gate not env-disableable
  mutation.py       allow/deny decision primitive
  advice.py         flags capital-shaped advice text as UNVERIFIED
  redteam.py        recall / precision calculation
  telemetry.py      heartbeat where no data is failure
scripts/
  pretooluse_hook.py           agent-harness PreToolUse hook (shadow / enforce)
  request_capital_approval.py  approval channel: review, confirm, remote sign
  gatekeeper_sign.py           gatekeeper-side signer CLI (separate user, holds key)
  gatekeeper_selftest.py       end-to-end sign / verify / replay-refusal selftest
  shadow_runner.py             log-only corpus replay
  redteam_harness.py           recall / precision harness, nonzero exit on any miss
  test_hook_isolation.py       14-scenario subprocess test of the hook
  test_heredoc_canary.py       executes allowed authoring cases behind inert shims
  dry_run_install.py           print-only install plan
config/
  capital-registry.example.json  fictional example registry (edit to your world)
  policy.json                    policy constants and pre-arm checklist
corpus/
  redteam_cases.json     59 known-bad / known-good cases
  shadow_actions.json    realistic action replay set
  heredoc_fp_cases.json  the heredoc authoring corpus, 25 block / 2 allow
tests/                   79 tests plus subtests across every primitive
```

## Running it

Requires Python 3.10+ and the `cryptography` package. From the repo root:

```bash
PYTHONPATH=src python3 -m pytest tests/ -q
PYTHONPATH=src python3 scripts/shadow_runner.py
PYTHONPATH=src python3 scripts/redteam_harness.py
python3 scripts/test_hook_isolation.py
python3 scripts/test_heredoc_canary.py
python3 tests/test_classifier_secret_surface.py
```

The runners generate throwaway Ed25519 keys in a temp directory, execute no corpus commands, contact no hosts, and clean up after themselves. The reference LLM reviewer shells out to a Claude CLI with an Opus model pinned; swap `opus_capital_reviewer` for any reviewer that meets the same contract: one exact verdict line, reject on anything else.

## License

MIT. See LICENSE.

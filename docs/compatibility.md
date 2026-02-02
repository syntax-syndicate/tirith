# Compatibility and Stability

## Stable Subcommands

The following subcommands are considered stable. Their flags, exit codes, and output format will not change in a backwards-incompatible way within a major version:

- `check` — analyze a command before execution
- `paste` — analyze pasted content
- `score` — risk score a URL
- `diff` — compare URL against known-good
- `why` — explain last triggered rule
- `receipt` — manage execution receipts
- `init` — initialize shell hooks

## Experimental Subcommands

These subcommands may change without notice:

- `run` — safe script download/execute
- `doctor` — diagnostic output
- `completions` — shell completion generation (hidden)
- `manpage` — man page generation (hidden)

## Exit Codes

Exit codes are stable:

| Code | Meaning |
|------|---------|
| 0    | Allow (no issues found) |
| 1    | Block (high/critical severity findings) |
| 2    | Warn (medium/low severity findings) |

## JSON Output

- `schema_version` is not yet emitted; it will be added before 1.0
- JSON fields are additive only: new fields may appear in any release
- Existing fields will not be removed or change type within a major version
- The `findings` array structure is stable

## Rule IDs

- Rule IDs (e.g., `curl_pipe_shell`, `punycode_domain`) are stable identifiers
- Rule wording (title, description) may change
- New rules may be added in any release
- Rules will not be removed within a major version (they may be deprecated)

## Policy Format

- `policy.yaml` (or `policy.yml`) format is additive: new keys may appear
- Existing keys will not change semantics within a major version

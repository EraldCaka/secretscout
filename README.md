# secretscout

`secretscout` is a fast command-line secret scanner written in Zig. It scans a file or directory tree for likely leaked credentials before commit, prints readable findings for developers, and can emit JSON for CI pipelines and automation.

## Features

- Recursive scanning for files and directories
- Human-readable findings by default
- JSON output for CI and machine consumers
- Manual pattern-based detection with no external runtime dependencies
- Common junk-directory skipping for faster local runs
- Binary and oversized file skipping to avoid noisy results

## Warning

Pattern-based scanners produce false positives and false negatives. `secretscout` is useful as a guardrail, but it is not a substitute for credential hygiene, secret rotation, or incident response. If you discover a real secret, rotate it.

## Build

Install Zig, then build the project:

```bash
zig build
```

The included CI workflow currently targets Zig `0.14.1`.

Run the test suite:

```bash
zig build test
```

The compiled binary is installed to `zig-out/bin/secretscout`.

## Usage

```bash
secretscout <path>
secretscout <path> --json
secretscout <path> --fail-on-findings
secretscout --help
```

Examples:

```bash
zig build run -- .
zig build run -- . --fail-on-findings
zig-out/bin/secretscout ./src --json
```

## Detection Rules

`secretscout` currently looks for:

- AWS access keys beginning with `AKIA` or `ASIA`
- GitHub classic tokens beginning with `ghp_`
- GitHub fine-grained, app, and related tokens beginning with `github_pat_`, `gho_`, `ghu_`, `ghs_`, or `ghr_`
- Slack tokens beginning with `xoxb-`, `xoxp-`, or `xoxa-`
- Generic assignments involving keys like `api_key`, `apikey`, `secret`, `token`, or `password`
- Private key markers such as `-----BEGIN PRIVATE KEY-----`

The scanner skips:

- `.git`
- `zig-cache`
- `zig-out`
- `node_modules`
- `target`
- `.venv`
- Files larger than 2 MB
- Binary-looking files

## Example Output

Human-readable output:

```text
src/config.env:3:12 [generic-secret] sk_l...9xA
deploy/.env:7:18 [github-classic-token] ghp_...456
```

JSON output:

```json
[
  {
    "file": "src/config.env",
    "line": 3,
    "column": 12,
    "rule": "generic-secret",
    "preview": "sk_l...9xA"
  }
]
```

## CI Usage

Use `--fail-on-findings` in CI to turn findings into a failing job:

```bash
zig build
zig-out/bin/secretscout . --json --fail-on-findings
```

The included GitHub Actions workflow installs Zig, runs `zig build test`, and then runs `zig build`.

## Exit Codes

- `0`: no findings, or findings were found without `--fail-on-findings`
- `1`: findings were found and `--fail-on-findings` was used
- `2`: invalid arguments or runtime errors

## Roadmap

- Entropy scoring to reduce false positives
- Allowlist configuration for ignored files and approved findings
- Git diff-only mode for pre-commit and pull request workflows
- SARIF output for richer code scanning integration

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

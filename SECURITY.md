# Security Policy

This tool is intended to test systems you own or are explicitly authorized to assess.

- Do not use this tool against systems without authorization.
- Intrusive tests require explicit CLI opt-in: `--active --i-understand`.
- Report security issues privately via GitHub Security Advisories.
- Avoid submitting sensitive information in public issues.

## Scope & Modes

- __Safe (default)__: Non-intrusive checks that avoid mutating remote state where possible.
- __Active (opt-in)__: May send malformed/invalid inputs, bursts, or intentionally forged artifacts to test validation and rate-limits.
- You must pass both `--active` and `--i-understand` to enable intrusive checks.

## Data Handling

- Ephemeral keys are generated unless `--pubkey/--seckey` are provided. Use `--no-store` to avoid writing them.
- Reports (`--out`, `--html`, `--pdf`) can contain URLs, relay statuses, and event identifiers. Handle outputs as sensitive.
- The preview-probe logs inbound requests (headers and query). Avoid embedding secrets in preview URLs.

## Responsible Use

- Respect rate limits and legal constraints. Limit targets via `--targets` and reduce `--rate`/`--max-events` for sensitive environments.
- Obtain written authorization where required. Keep audit logs of consent.
- Do not attempt to bypass authentication, access data you are not entitled to, or disrupt services.

## Coordinated Disclosure

- Please report vulnerabilities privately via GitHub Security Advisories.
- Provide reproduction steps, impacted versions, and mitigations if known.
- Avoid sharing sensitive logs or credentials. Redact secrets before submission.

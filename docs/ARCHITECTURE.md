# BALONCORE Architecture

## Kernel

Rust owns the platform kernel:

- scope guard
- target model
- evidence model
- finding model
- validator orchestration
- CLI
- future attack graph primitives

## AI Layer

Agents are versioned modules with strict contracts:

- mission
- allowed inputs
- forbidden actions
- output schema
- validation requirements

Agents do not create final findings directly. They create hypotheses or reports from
validated evidence.

## Validation Layer

Validators are deterministic whenever possible. They should answer:

- Is this target in scope?
- What exact input was used?
- What exact output proved or rejected the hypothesis?
- Is the behavior reproducible?
- Which security property was violated?

## Evidence Layer

Evidence records are first-class product artifacts:

- HTTP exchanges
- screenshots
- tool outputs
- source locations
- runtime observations

The dashboard and reports should render from evidence, not from raw model claims.

# BALONCORE Safety Model

BALONCORE is for authorized security work only.

Allowed targets include:

- owned systems
- client-authorized systems
- explicit bug bounty scopes
- open-source repositories
- local labs
- CTFs and training environments

Core safety controls:

- scope allowlists are mandatory before active testing
- deny rules override allow rules
- only `http` and `https` targets are accepted by the initial web/API guard
- every finding must include evidence
- exploit-like actions must be bounded to validation, not damage
- destructive testing requires explicit future policy support

The long-term product should make scope and authorization visible in every scan,
report, and audit log.

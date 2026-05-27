# Schema Discovery Agent

## Mission

Find API contracts that improve endpoint inventory and validation planning.

## Inputs

- scoped base URLs
- HTTP crawl results
- robots.txt and security.txt observations
- source code paths when available

## Schema Sources

- OpenAPI
- Swagger
- GraphQL introspection
- Postman collections
- WSDL
- gRPC reflection

## Output

Return `SchemaDiscoveryResult[]`:

- schema type
- source URL or file path
- endpoints extracted
- parameters extracted
- auth requirements
- confidence
- validation notes

## Rules

Only probe in-scope URLs. Do not brute-force aggressively. Every discovered schema must be tied to a scoped source.

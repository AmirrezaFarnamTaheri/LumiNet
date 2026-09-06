# Use served routes as route truth

Status: Accepted

## Context and Problem Statement

Gin registration, workflow classification, capability metadata, unregistered handler methods, and a hand-maintained route document disagreed about which routes existed. Some compatibility state was documented or classified even though no live route served it.

## Considered Options

- Maintain a separate route-spec registry and keep it synchronized with Gin.
- Treat actual served Gin routes as existence authority and derive runtime metadata/document checks from that inventory.

## Decision Outcome

`GET /api/routes` is the runtime authority for served route existence. Workflow, capability, availability, and deprecation metadata attach to or derive from that served inventory. Documentation is mechanically checked against registration, and unregistered/synthetic route corpus is retired after liveness proof.

## Consequences

There is one answer to “is this route served?” Compatibility or historical routes may still be documented, but only when explicitly labeled non-served/preserved. Route metadata must not invent operational capability independently of runtime truth.

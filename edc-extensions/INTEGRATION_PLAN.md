# Cocos EDC Integration Plan

## Scope

This directory contains the Cocos-owned Eclipse EDC extensions needed to connect Cocos to external control-plane and trust services while keeping the integration code in the `cocos` repository.

In scope:

- Cocos runtime integration with Eclipse EDC
- Cocos-specific EDC extensions
- public integration contracts and setup guides
- mocked and hybrid test setups

Out of scope:

- external VM provisioning systems
- external provider deployments
- external Identity Hub and ledger implementations

## Current State

The extension structure is in place and has been moved out of the Connector fork into this repository.

Available now:

- standalone Cocos EDC extension modules
- computation API and orchestration skeleton
- Cocos VM data sink
- attestation-backed credential hook
- real KBS-backed testing on the Cocos side

Missing for end-to-end operation:

- real Connector-to-Cocos CLI bridge
- real DSP consumer flow for remote assets
- real Identity Hub client integration
- dedicated tests for the moved extension project

## Modules

- `extensions/cocos/cocos-spi`
- `extensions/cocos/cocos-cli`
- `extensions/cocos/cocos-computation-api`
- `extensions/cocos/cocos-orchestrator`
- `extensions/cocos/cocos-attestation-credential-service`
- `extensions/cocos/cocos-data-sink`

## External Dependencies

Preferred validation order:

1. real KBS
2. real Identity Hub when available
3. mocks for remaining unavailable external systems

Practical rule:

- KBS can already be tested for real.
- Identity Hub should target Eclipse EDC IdentityHub when available and fall back to mocks otherwise.
- Provisioning and partner provider endpoints should be treated as external integrations.

## What We Need To Do

### 1. Publish stable integration contracts

- document the computation request contract
- document the callback contract
- document expected behavior for mocked external services

Outcome:

- external integrators can work against Cocos without reading the source tree

### 2. Add a testable standalone extension project

- add unit tests for orchestration, API, data sink, and attestation flow
- add shared test fixtures and mock HTTP services
- keep support for real KBS in environment-gated tests

Outcome:

- the integration can evolve safely outside the Connector fork

### 3. Implement the real CLI bridge

- map extension operations to `cocos-cli`
- implement agent start, uploads, attestation retrieval, and result retrieval
- add timeout and error handling

Outcome:

- an upstream EDC runtime can drive real Cocos VMs

### 4. Implement remote asset consumption

- replace the stub remote asset fetcher
- support catalog, negotiation, transfer, and payload retrieval
- keep provider-side dependencies mockable

Outcome:

- datasets and algorithms can be pulled through EDC and delivered into Cocos VMs

### 5. Implement the Identity Hub adapter

- finalize the internal adapter contract
- implement nonce and presentation requests against IdentityHub
- keep the flow testable with mocks

Outcome:

- attestation-backed credentials can be used in the DSP flow

### 6. Harden runtime behavior

- complete job lifecycle states
- improve structured logging and diagnostics
- publish a mock-first setup guide and a hybrid setup guide

Outcome:

- the integration is usable by external adopters and easier to troubleshoot

## Recommended Execution Order

1. contracts and public docs
2. tests and fixtures
3. CLI bridge
4. DSP consumer flow
5. Identity Hub adapter
6. hybrid and partner-facing setup guides

## Short-Term Next Steps

1. verify upstream EDC artifact coordinates and Java 17+ build baseline
2. add the first standalone tests for orchestrator and computation API
3. define the `cocos-cli` command mapping used by the extension modules
4. publish the first public request and callback contracts
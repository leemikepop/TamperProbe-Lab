# TamperProbe TEE / Android Keystore detectors

This is the active primary source directory. Publication still requires the active CMake list,
native registration, and generated catalog; the README alone is not publication evidence.

Catalog 1.0 publishes three hardware-attestation detectors:

| ID | Payload schema | Current behavior |
| --- | --- | --- |
| `TEE_ATTESTATION` | v1 | Fresh challenge, ordered chain, JCA signature/root validation, offline revocation, attestation/KeyMint fields, RKP presence and RootOfTrust/boot consistency |
| `TEE_OVERSIZED_CHALLENGE` | v1 | Separates accepted, rejected, provider/unsupported and collection-failure states for a 256-byte challenge |
| `TEE_KEYSTORE_CONSISTENCY` | v1 | Public-API signature, lifecycle and certificate-entry invariants; AES/StrongBox remain diagnostics |

The SDK and standalone RASP share a public-API-only Keystore collector. Native C++
still owns outcome and evidence strength. `TEE_ATTESTATION` no longer promotes
multiple weak posture findings to strong evidence. Unknown roots, RKP/provider
availability and parser limits become Inconclusive unit issues or Observation unless an independent
Signal exists.

Strong findings are restricted to challenge mismatch, a completed chain-signature
failure, official `REVOKED`/`SUSPENDED` status, and oversized-challenge acceptance.
Verified-boot contradictions/all-zero comparable fields are moderate. Unlocked,
non-Verified boot and software-backed posture are weak.

The offline assets are `attestation_roots.json` and `attestation_status.json`. There
is no implicit SDK networking; the existing
`installAttestationStatus(ByteArray)` API remains the explicit status-update path.
The status validator follows the official draft-07 shape: lowercase hexadecimal
certificate serial keys, `REVOKED`/`SUSPENDED`, bounded optional fields, and no
unknown properties. Expired status entries are ignored. Certificate validity
uses the documented legacy factory-root exception while retaining strict RKP
chain expiry checks.
Temporary aliases are random, and cleanup failure is a unit issue rather than a tamper Signal.

Fresh challenges, certificate DER, chain serials and leaf-key hashes are used
only inside the collection/native boundary and are not exported in the public
payload.

Local validation is target-process evidence and is not equivalent to a trusted
server verifier or a Google Play Integrity verdict.

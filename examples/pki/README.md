# Lab PKI fixtures

These certificates exist only to demonstrate and test `certsentinel`. They are a
disposable laboratory PKI, not a production trust hierarchy: all names use the
reserved `.example` domain and all addresses come from the RFC 5737 documentation
ranges (`192.0.2.0/24`).

Only certificates are committed. The RSA and EC private keys were generated in a
temporary directory with OpenSSL 3.5.6 and deleted immediately after the
certificates were produced; no private key, keystore or password exists in this
repository. Do not use these certificates for anything outside a laboratory.

## Files

| File | Subject CN | Serial | Validity (generated 2026-11-16) | Signature | Key |
| ---- | ---------- | ------ | ------------------------------ | --------- | --- |
| `root-ca.pem` | NetWatch Lab Root CA | `1000` | 2026-11-16 to 2036-11-13 | sha256WithRSAEncryption | RSA 2048 |
| `intermediate-ca.pem` | NetWatch Lab Intermediate CA | `2000` | 2026-11-16 to 2031-11-15 | sha256WithRSAEncryption | RSA 2048 |
| `leaf-server.pem` | srv-a.example | `3001` | 2026-11-16 to 2027-11-16 | sha256WithRSAEncryption | RSA 2048 |
| `leaf.der` | srv-a.example (DER copy) | `3001` | 2026-11-16 to 2027-11-16 | sha256WithRSAEncryption | RSA 2048 |
| `leaf-expiring-soon.pem` | srv-b.example | `3002` | 2026-11-16 to 2026-12-06 | sha256WithRSAEncryption | RSA 2048 |
| `leaf-sha1.pem` | legacy-sha1.example | `3003` | 2026-11-16 to 2027-11-16 | sha1WithRSAEncryption | RSA 2048 |
| `leaf-small-key.pem` | legacy-rsa.example | `3004` | 2026-11-16 to 2027-11-16 | sha256WithRSAEncryption | RSA 1024 |
| `leaf-self-signed.pem` | selfie.example | `4000` | 2026-11-16 to 2027-11-16 | sha256WithRSAEncryption | RSA 2048 |

Chain: `root-ca.pem` signs `intermediate-ca.pem`, which signs `leaf-server.pem`,
`leaf-expiring-soon.pem`, `leaf-sha1.pem` and `leaf-small-key.pem`.
`leaf-self-signed.pem` is a self-signed non-CA leaf.

The chain verification used when the fixtures were created:

```text
> openssl verify -CAfile root-ca.pem intermediate-ca.pem
intermediate-ca.pem: OK
> openssl verify -CAfile root-ca.pem -untrusted intermediate-ca.pem leaf-server.pem
leaf-server.pem: OK
```

## Intentional audit findings

The fixtures are deliberately imperfect so the rule engine can be demonstrated:

* `leaf-expiring-soon.pem` expires roughly 20 days after generation
  (`CERT-EXPIRING`).
* `leaf-sha1.pem` is signed with SHA-1 (`CERT-WEAK-HASH`).
* `leaf-small-key.pem` uses a 1024-bit RSA key (`CERT-SMALL-RSA-KEY`).
* `leaf-self-signed.pem` is self-signed and is not a CA (`CERT-SELF-SIGNED`).
* `leaf.der` is the same certificate as `leaf-server.pem`, so scanning the
  directory reports a duplicate fingerprint (`CERT-DUPLICATE`).
* The root and intermediate CAs have validity windows above 398 days and are
  flagged with `CERT-LONG-VALIDITY` notices (normal for a lab CA, informative
  for an auditor).

## Regenerating

The fixtures were produced with OpenSSL 3.5.6 using `req -x509` for the root and
self-signed leaf, `x509 -req -CA ... -CAkey ...` for the intermediate and signed
leaves, and `-addext`/`-extfile` for basic constraints, key usage, extended key
usage, subject alternative names, key identifiers and AIA URLs. Certificates were
written to this directory; only the certificate files were kept.

# EAT Attestation Result (EAR)
[![Go Reference](https://pkg.go.dev/badge/github.com/veraison/ar4si.svg)](https://pkg.go.dev/github.com/veraison/ear)
[![ci](https://github.com/veraison/ear/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/veraison/ear/actions/workflows/ci.yml)
[![cover ≥90.0%](https://github.com/veraison/ear/actions/workflows/ci-go-cover.yml/badge.svg?branch=main)](https://github.com/veraison/ear/actions/workflows/ci-go-cover.yml)

The `ear` package provides a golang API for working with EAR (EAT Attesation Result), an EAT/JWT serialisation of the [Attestation Result for Secure Interactions (AR4SI)](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/) information model.

This implementation aligns with
[rev04](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/) of EAR and
[rev10](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/10/) of AR4SI
specification drafts. Additionally, it implements the following as-of-yet unpublished
features:

- Recursive EARs: https://github.com/ietf-rats-wg/draft-ietf-rats-ear/pull/87
- Incomplete ARISI tier: https://github.com/ietf-rats-wg/draft-ietf-rats-ar4si/pull/49

A command line interface utility ([`arc`](arc/README.md)) is also provided to create, verify and display EAR attestation result payloads. To install it:

```sh
go install github.com/veraison/ear/arc@latest
```

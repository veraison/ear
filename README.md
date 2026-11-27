# EAT Attestation Result (EAR)
[![Go Reference](https://pkg.go.dev/badge/github.com/veraison/ar4si.svg)](https://pkg.go.dev/github.com/veraison/ear)
[![ci](https://github.com/veraison/ear/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/veraison/ear/actions/workflows/ci.yml)
[![cover ≥90.0%](https://github.com/veraison/ear/actions/workflows/ci-go-cover.yml/badge.svg?branch=main)](https://github.com/veraison/ear/actions/workflows/ci-go-cover.yml)

The `ear` package provides a golang API for working with EAR (EAT Attesation Result), an EAT/JWT serialisation of the [Attestation Result for Secure Interactions (AR4SI)](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/) information model.

This implementation aligns with
[rev06](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/06/) of EAR and
[rev11](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/11/) of AR4SI
specification drafts.

A command line interface utility ([`arc`](arc/README.md)) is also provided to create, verify and display EAR attestation result payloads. To install it:

```sh
go install github.com/veraison/ear/arc@latest
```

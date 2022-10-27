# Attestation Results for Secure Interactions
[![Go Reference](https://pkg.go.dev/badge/github.com/veraison/ar4si.svg)](https://pkg.go.dev/github.com/veraison/ar4si)
[![ci](https://github.com/veraison/ar4si/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/veraison/ar4si/actions/workflows/ci.yml)
[![cover ≥90.0%](https://github.com/veraison/ar4si/actions/workflows/ci-go-cover.yml/badge.svg?branch=main)](https://github.com/veraison/ar4si/actions/workflows/ci-go-cover.yml)

The `ar4si` package provides a golang API for working with EAR (EAT Attesation Result), an EAT/JWT serialisation of the [Attestation Result for Secure Interactions (AR4SI)](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/) information model.

A command line interface utility ([`arc`](arc/README.md)) is also provided to create, verify and display EAR attestation result payloads. To install it:

```sh
go install github.com/veraison/ar4si/arc@latest
```

# Attestation Result Command

`arc` (attestation result command) allows:

* synthesising attestation results in EAR (EAT Attestation Result) format,
* cryptographically verifying and displaying the contents of an EAR

## Create

The `create` sub-command is used to synthesise an EAR given the full claims-set.

```sh
arc create \
    [--claims <file>] \
    [--skey <signing key>] \
    [--alg <alg>] \
    <jwt-file>
```

### Parameters

| parameter | meaning |
| --- | --- |
| `--claims` | EAR claims-set in JSON (default to `${PWD}/ear-claims.json`) |
| `--skey`  | signing key in JWK format (default to `${PWD}/skey.json`) |
| `--alg`  | JWS algorithm |
| `<jwt-file>` | the signed EAR claims-set in JWT format |

### Output

A one-liner saying success status and path of the JWT file that was created.

## Verify

The `verify` sub-command is used to cryptographically verify and pretty-print the contents of a EAR, including the trustworthiness vector.

```sh
arc verify \
    [--pkey <file>] \
    [--alg <alg>] \
    [--verbose] \
    [--color] \
    <jwt-file>
```

### Parameters

| parameter | meaning |
| --- | --- |
| `--pkey`  | verification key in JWK format (default to `${PWD}/pkey.json`) |
| `--alg`  | JWS algorithm |
| `--verbose` | trustworthiness vector detailed report (default is brief) |
| `--color` | trustworthiness vector report colourises the tiers (default is B&W) |
| `<jwt-file>` | a JWT wrapping an EAR claims-set |

### Output

* Validation status of the cryptographic signature.

If successful:

* The EAR claims-set is printed to stdout.
* If present, the _decoded_ trust vector is also printed to stdout (the exact format depends on `--verbose` and `--color`).

## Print

The `print` sub-command is used to print the contents of a EAR, including the header.
No ERA validation or veryfing are executed.

```sh
arc verify <jwt-file>
```

### Parameters

| parameter | meaning |
| --- | --- |
| `<jwt-file>` | a JWT wrapping an EAR claims-set |

### Output

If EAR is successfully parsed:

* The EAR header and payload are printed to stdout.

# bridz

bridz is a stateless OIDC broker for downstream applications. It acts as an OpenID
Provider downstream and relies on one upstream OpenID Provider for authentication.

## Building

```sh
go build -o bridz .
./bridz config.yaml
```

## Configuration

Copy `config.example.yaml` to `config.yaml` and set the issuer, upstream IdP
credentials, and downstream clients. Generate the required keys with:

```sh
openssl rand -base64 32 | tr '+/' '-_'
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out signing-key.pem
```

Use the first value as `keys.state_encryption_key` and paste `signing-key.pem` under
`keys.signing_key_pem`. Run bridz behind a TLS-terminating reverse proxy.
`issuer` and `upstream.redirect_uri` must use its public HTTPS URL.

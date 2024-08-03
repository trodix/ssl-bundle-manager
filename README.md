# SSL Bundle Manager

## Generate Root certificate and domain certificate

Generate a root certificate
```bash
openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt
```

Generate domain private key and csr
```bash
openssl req -newkey rsa:2048 -keyout acme.ltd.key -out acme.ltd.csr
```

Create domain.ext file containing:
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = acme.ltd
```

Generate certificate for specific domain with root certificate
```bash
openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in acme.ltd.csr -out acme.ltd.crt -days 365 -CAcreateserial -extfile acme.ltd.ext
```

View certificate
```bash
openssl x509 -text -noout -in acme.ltd.crt
```

Verify certificate as been created by CA
```bash
openssl verify -verbose -CAfile rootCA.crt acme.ltd.crt
```

## Truststore

Import CA into truststore
```bash
keytool -importcert -alias rootCA -keystore mytruststore1.jks -storepass changeit -file rootCA.crt
```

Show Importer CA in truststore
```bash
 keytool -list -v -keystore mytruststore1.jks -storepass changeit -alias rootCA
```

## Keystore

Combine all certificates in a file from domain to CA to have a full cert chain
```bash
cat acme.ltd.crt rootCA.crt > cert-chain.txt
```

Create a Keystore and import domain key and certificate
```bash
openssl pkcs12 -export -in cert-chain.txt -inkey acme.ltd.key -name 'acme' -out mykeystore1.p12
```

Show imported key/cert-chain pair in keystore
```bash
keytool -list -v -keystore mykeystore1.p12 -storepass password -alias acme
```

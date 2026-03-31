# scala-native-crypto

`java.security` Scala Native implementation based on OpenSSL

## Getting started

You need to add the dependency to your Scala Native project.

On SBT:

```scala
libraryDependencies += "com.github.lolgab" %%% "scala-native-crypto" % "x.y.z"
```

On Mill:

```scala
def ivyDeps = super.ivyDeps() ++ Agg(ivy"com.github.lolgab::scala-native-crypto::x.y.z")
```

You need also to install OpenSSL:

On Ubuntu:

```
sudo apt install libssl-dev
```

On Mac OS X (with Homebrew):

```
brew install openssl
```

And you need to have `libcrypto.[so|dylib]` in your linking path.

In Ubuntu it works out of the box since openssl is installed in the main
lib directory.

In Mac OS X you will need to add the path via `nativeLinkingOptions`.

On SBT:

```scala
nativeConfig ~= { c => c.withLinkingOptions(c.nativeLinkingOptions :+ "-L/usr/local/opt/openssl@3/lib") }
```

On Mill:

```scala
def nativeLinkingOptions = super.nativeLinkingOptions() ++ Seq("-L/usr/local/opt/openssl@3/lib")
```

## Implemented classes

According [JDK Security Algorithm Implementation Requirements](https://docs.oracle.com/en/java/javase/25/docs/specs/security/standard-names.html#security-algorithm-implementation-requirements), the following classes and algorithm checked are implemented and those unchecked are minimal requirements for interoperable JDK shims.

(The sequence is in the same order of the reference table)

- `java.security..AlgorithmParameterGenerator`
  - [ ] DiffieHellman (1024, 2048)
  - [ ] DSA (1024, 2048)
- `java.security.AlgorithmParameters`
  - [ ] AES
  - [ ] ChaCha20-Poly1305
  - [ ] DESede
  - [ ] DiffieHellman
  - [ ] DSA
  - [ ] EC (secp256r1, secp384r1)
  - [ ] RSASSA-PSS (MGF1 mask generation function and SHA-256 or SHA-384 hash algorithms)
- `java.security.cert.CertificateFactory`
  - [x] X.509
- `java.security.cert.CertPath` Encoding
  - [ ] PKCS7
  - [ ] PkiPath
- `java.security.cert.CertPathBuilder`
  - [ ] PKIX
- `java.security.cert.CertPathValidator`
  - [ ] PKIX
- `java.security.cert.CertStore`
  - [x] Collection
- `javax.crypto.Cipher`
  - [ ] AES/CBC/NoPadding (128)
  - [ ] AES/CBC/PKCS5Padding (128)
  - [ ] AES/ECB/NoPadding (128)
  - [ ] AES/ECB/PKCS5Padding (128)
  - [ ] AES/GCM/NoPadding (128, 256)
  - [ ] ChaCha20-Poly1305
  - [ ] DESede/CBC/NoPadding (168)
  - [ ] DESede/CBC/PKCS5Padding (168)
  - [ ] DESede/ECB/NoPadding (168)
  - [ ] DESede/ECB/PKCS5Padding (168)
  - [ ] RSA/ECB/PKCS1Padding (1024, 2048)
  - [ ] RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
  - [ ] RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
- `javax.crypto.KeyAgreement`
  - [ ] DiffieHellman
  - [ ] ECDH (secp256r1, secp384r1)
  - [ ] X25519
- `java.security.KeyFactory`
  - [ ] DiffieHellman
  - [ ] DSA
  - [ ] EC
  - [ ] RSA
  - [ ] RSASSA-PSS
  - [ ] X25519
- `javax.crypto.KeyGenerator`
  - [ ] AES (128, 256)
  - [ ] ChaCha20
  - [ ] DESede (168)
  - [ ] HmacSHA1
  - [ ] HmacSHA256
- `java.security.KeyPairGenerator`
  - [ ] DiffieHellman (1024, 2048, 3072, 4096)
  - [ ] DSA (1024, 2048)
  - [ ] EC (secp256r1, secp384r1)
  - [ ] RSA (1024, 2048, 3072, 4096)
  - [ ] RSASSA-PSS (2048, 3072, 4096)
  - [ ] X25519
- `java.security.KeyStore`
  - [x] PKCS12
- `javax.crypto.Mac`
  - [x] HmacSHA1
  - [x] HmacSHA256
  - extra
    - [x] HmacSHA224
    - [x] HmacSHA384
    - [x] HmacSHA512
    - [x] HmacSHA3-224
    - [x] HmacSHA3-256
    - [x] HmacSHA3-384
    - [x] HmacSHA3-512
- `java.security.MessageDigest`
  - [x] SHA-1
  - [x] SHA-256
  - [x] SHA-384
  - extra
    - [x] SHA3-224
    - [x] SHA3-256
    - [x] SHA3-384
    - [x] SHA3-512
- `javax.crypto.SecretKeyFactory`
  - [ ] DESede
- [x] `java.security.SecureRandom`
- `java.security.Signature`
- `javax.net.ssl.SSLContext`: See downstream project [lqhuang/scala-native-http](https://github.com/lqhuang/scala-native-http)
  - [x] TLSv1.2
  - [x] TLSv1.3
- `javax.net.ssl.TrustManagerFactory`: See downstream project [lqhuang/scala-native-http](https://github.com/lqhuang/scala-native-http)
  - [x] PKIX

Welcome contributions to implement the missing algorithms/classes.

## Known issues

1. Create a `X500Principal` instance from string / bytes dones't support verification for now
   - Since OpenSSL doesn't expose individual verification and constructor for ASN1 Distinguished Name. There might have some workaround to hack the verification, for example try to create a fake X509 cert first, but it's not implemented yet.
   - The current implementation of `X500Principal` constructor just convert the input string to bytes and store it in RFC standards, without any verification. Basically, we majorly used `getSubjectX500Principal()` method of `X509Certificate` to get well formed `X500Principal` internally.
   - Through the `X500Principal` constructor is documented as a public API and can be used to create an instance, WE DON'T RECOMMEND TO USE THE CONSTRUCTOR DIRECTLY UNTIL THE VERIFICATION IS IMPLEMENTED.

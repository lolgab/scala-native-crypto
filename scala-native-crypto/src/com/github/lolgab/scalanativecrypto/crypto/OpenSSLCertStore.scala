package com.github.lolgab.scalanativecrypto.crypto

import java.security.{Provider}
import java.security.cert.{CertStore, CertStoreSpi, CertStoreParameters}

final class OpenSSLCertStore protected[scalanativecrypto] (
    provider: Provider,
    csType: String,
    csParameters: CertStoreParameters
) extends CertStore(null, provider, csType, csParameters)

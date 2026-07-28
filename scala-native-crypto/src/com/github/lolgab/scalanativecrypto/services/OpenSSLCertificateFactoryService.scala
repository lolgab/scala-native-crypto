package com.github.lolgab.scalanativecrypto.services

import com.github.lolgab.scalanativecrypto.JcaService
import com.github.lolgab.scalanativecrypto.crypto.OpenSSLX509CertificateFactory

import java.security.Provider
import java.util.{List => JList}
import java.util.{Map => JMap}

class OpenSSLCertificateFactoryService protected[scalanativecrypto] (
    private val provider: Provider,
    private val algorithm: String,
    private val aliases: JList[String],
    private val attributes: JMap[String, String]
) extends Provider.Service(
      provider,
      JcaService.CertificateFactory.name,
      algorithm,
      "com.github.lolgab.scalanativecrypto.services.OpenSSLCertificateFactoryService",
      aliases,
      attributes
    ) {

  override def supportsParameter(parameter: Object): Boolean =
    if (parameter == null) true
    else false

  override def newInstance(
      constructorParameter: Object
  ): OpenSSLX509CertificateFactory =
    new OpenSSLX509CertificateFactory(provider, algorithm)

}

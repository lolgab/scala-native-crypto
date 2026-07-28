package com.github.lolgab.scalanativecrypto.services

import java.security.Provider
import java.security.cert.CertStoreParameters
import java.util.{List => JList, Map => JMap}

import _root_.com.github.lolgab.scalanativecrypto.JcaService
import _root_.com.github.lolgab.scalanativecrypto.crypto.OpenSSLCertStore

class OpenSSLCertStoreService protected[scalanativecrypto] (
    private val provider: Provider,
    private val algorithm: String,
    private val aliases: JList[String],
    private val attributes: JMap[String, String]
) extends Provider.Service(
      provider,
      JcaService.CertStore.name,
      algorithm,
      "com.github.lolgab.scalanativecrypto.services.OpenSSLCertStoreService",
      aliases,
      attributes
    ) {

  override def supportsParameter(parameter: Object): Boolean =
    if (parameter.isInstanceOf[CertStoreParameters])
      true
    else
      false

  override def newInstance(
      constructorParameter: Object
  ): OpenSSLCertStore = {
    require(
      supportsParameter(constructorParameter),
      s"Unsupported parameter type: ${constructorParameter.getClass().getName()}"
    )

    new OpenSSLCertStore(
      provider,
      algorithm,
      constructorParameter.asInstanceOf[CertStoreParameters]
    )
  }

}

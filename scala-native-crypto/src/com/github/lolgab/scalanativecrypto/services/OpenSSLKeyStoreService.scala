package com.github.lolgab.scalanativecrypto.services

import java.security.Provider
import java.util.{List => JList, Map => JMap}

import _root_.com.github.lolgab.scalanativecrypto.JcaService
import _root_.com.github.lolgab.scalanativecrypto.crypto.OpenSSLKeyStore

class OpenSSLKeyStoreService protected[scalanativecrypto] (
    private val provider: Provider,
    private val algorithm: String,
    private val aliases: JList[String],
    private val attributes: JMap[String, String]
) extends Provider.Service(
      provider,
      JcaService.KeyStore.name,
      algorithm,
      "com.github.lolgab.scalanativecrypto.services.OpenSSLKeyStoreService",
      aliases,
      attributes
    ) {

  override def supportsParameter(parameter: Object): Boolean =
    if (parameter == null) true else false

  override def newInstance(constructorParameter: Object): OpenSSLKeyStore = {
    new OpenSSLKeyStore(provider, algorithm)
  }

}

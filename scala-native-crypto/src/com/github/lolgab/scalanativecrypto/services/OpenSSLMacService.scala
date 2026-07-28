package com.github.lolgab.scalanativecrypto.services

import com.github.lolgab.scalanativecrypto.JcaService
import com.github.lolgab.scalanativecrypto.crypto.OpenSSLMac
import com.github.lolgab.scalanativecrypto.internal.Utils

import java.security.Provider
import java.util.{List => JList, Map => JMap}
import javax.crypto.Mac

class OpenSSLMacService protected[scalanativecrypto] (
    private val provider: Provider,
    private val algorithm: String,
    private val aliases: JList[String],
    private val attributes: JMap[String, String]
) extends Provider.Service(
      provider,
      JcaService.Mac.name,
      algorithm,
      "com.github.lolgab.scalanativecrypto.services.OpenSSLMacService",
      aliases,
      attributes
    ) {

  override def supportsParameter(parameter: Object): Boolean =
    if (parameter == null) true else false

  override def newInstance(constructorParameter: Object): Mac = {
    val (name, length) =
      Utils.getAlgorithmNameAndLength(algorithm, prefix = "HMAC")

    new OpenSSLMac(
      provider,
      algorithm,
      name,
      length
    )
  }

}

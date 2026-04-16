package com.github.lolgab.scalanativecrypto.services

import com.github.lolgab.scalanativecrypto.JcaService
import com.github.lolgab.scalanativecrypto.crypto.OpenSSLMessageDigest
import com.github.lolgab.scalanativecrypto.internal.Utils

import java.security.{MessageDigest, Provider}
import java.util.{List => JList, Map => JMap}

class OpenSSLMessageDigestService protected[scalanativecrypto] (
    private val provider: Provider,
    private val algorithm: String,
    private val aliases: JList[String],
    private val attributes: JMap[String, String]
) extends Provider.Service(
      provider,
      JcaService.MessageDigest.name,
      algorithm,
      "com.github.lolgab.scalanativecrypto.services.OpenSSLMessageDigestService",
      aliases,
      attributes
    ) {

  override def supportsParameter(parameter: Object): Boolean =
    if (parameter == null) true else false

  override def newInstance(constructorParameter: Object): MessageDigest = {
    val (name, length) =
      Utils.getAlgorithmNameAndLength(algorithm, prefix = "")

    new OpenSSLMessageDigest(
      provider,
      algorithm,
      name,
      length
    )
  }

}

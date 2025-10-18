package com.github.lolgab.scalanativecrypto.services

import java.security.{Provider, MessageDigest}
import java.util.{List => JList, Map => JMap}

import com.github.lolgab.scalanativecrypto.internal.Utils
import com.github.lolgab.scalanativecrypto.crypto.OpenSslMessageDigest
import com.github.lolgab.scalanativecrypto.JcaService

class OpenSslMessageDigestSerice private (
    private val provider: Provider,
    private val algorithm: String,
    private val aliases: JList[String],
    private val attributes: JMap[String, String]
) extends Provider.Service(
      provider,
      JcaService.MessageDigest.name,
      algorithm,
      "com.github.lolgab.scalanativecrypto.services.OpenSslMessageDigest",
      aliases,
      attributes
    ) {

  override def supportsParameter(parameter: Object): Boolean =
    if (parameter == null) true else false

  override def newInstance(constructorParameter: Object): MessageDigest = {
    val (name, length) =
      Utils.getAlgorithmNameAndLength(algorithm, prefix = "")

    new OpenSslMessageDigest(
      provider,
      algorithm,
      name,
      length
    )
  }

}

object OpenSslMessageDigestSerice {
  def apply(
      provider: Provider,
      algorithm: String,
      aliases: JList[String],
      attributes: JMap[String, String]
  ): OpenSslMessageDigestSerice = new OpenSslMessageDigestSerice(
    provider,
    algorithm,
    aliases,
    attributes
  )
}

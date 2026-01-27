package com.github.lolgab.scalanativecrypto.services

import java.security.Provider
import java.util.{List => JList, Map => JMap}
import javax.crypto.Mac

import com.github.lolgab.scalanativecrypto.internal.Utils
import com.github.lolgab.scalanativecrypto.crypto.OpenSslMac
import com.github.lolgab.scalanativecrypto.JcaService

class OpenSslMacService private (
    private val provider: Provider,
    private val algorithm: String,
    private val aliases: JList[String],
    private val attributes: JMap[String, String]
) extends Provider.Service(
      provider,
      JcaService.Mac.name,
      algorithm,
      "com.github.lolgab.scalanativecrypto.services.OpenSslMacService",
      aliases,
      attributes
    ) {

  override def supportsParameter(parameter: Object): Boolean =
    if (parameter == null) true
    else false

  override def newInstance(constructorParameter: Object): Mac = {
    val (name, length) =
      Utils.getAlgorithmNameAndLength(algorithm, prefix = "HMAC")

    new OpenSslMac(
      provider,
      algorithm,
      name,
      length
    )
  }

}

object OpenSslMacService {
  def apply(
      provider: Provider,
      algorithm: String,
      aliases: JList[String],
      attributes: JMap[String, String]
  ): OpenSslMacService = new OpenSslMacService(
    provider,
    algorithm,
    aliases,
    attributes
  )
}

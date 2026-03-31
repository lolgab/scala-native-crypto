package com.github.lolgab.scalanativecrypto.services

import com.github.lolgab.scalanativecrypto.JcaService
import com.github.lolgab.scalanativecrypto.crypto.OpenSslCipher

import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.util.{List => JList}
import java.util.{Map => JMap}
import javax.crypto.Cipher

class OpenSslCipherService private (
    private val provider: Provider,
    private val algorithm: String,
    private val aliases: JList[String],
    private val attributes: JMap[String, String]
) extends Provider.Service(
      provider,
      JcaService.Cipher.name,
      algorithm,
      "com.github.lolgab.scalanativecrypto.services.OpenSslCipherService",
      aliases,
      attributes
    ) {

  override def supportsParameter(parameter: Object): Boolean =
    if (parameter == null) true
    else false

  override def newInstance(constructorParameter: Object): Cipher = {
    // Parse transformation: "AES/GCM/NoPadding" or "AES/CBC/PKCS5Padding"
    val parts = algorithm.split("/")
    if (parts.length != 3)
      throw new NoSuchAlgorithmException(
        s"Invalid transformation: $algorithm"
      )

    val mode = parts(1).toUpperCase()
    val padding = parts(2)

    new OpenSslCipher(
      provider,
      algorithm,
      mode,
      padding
    )
  }
}

object OpenSslCipherService {
  def apply(
      provider: Provider,
      algorithm: String,
      aliases: JList[String],
      attributes: JMap[String, String]
  ): OpenSslCipherService = new OpenSslCipherService(
    provider,
    algorithm,
    aliases,
    attributes
  )
}

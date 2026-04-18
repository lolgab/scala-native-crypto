package com.github.lolgab.scalanativecrypto.services

import com.github.lolgab.scalanativecrypto.crypto.OpenSslEd25519KeyPairGenerator

import java.security.Provider
import java.util.{List => JList, Map => JMap}

class OpenSslKeyPairGeneratorService(
    provider: Provider,
    algorithm: String,
    aliases: JList[String],
    attributes: JMap[String, String]
) extends Provider.Service(provider, "KeyPairGenerator", algorithm, "", aliases, attributes) {

  override def newInstance(constructorParameter: Object): Object = {
    algorithm match {
      case "Ed25519" | "EdDSA" => new OpenSslEd25519KeyPairGenerator(provider)
      case _ =>
        throw new java.security.NoSuchAlgorithmException(
          s"Unsupported key pair generator algorithm: $algorithm"
        )
    }
  }
}

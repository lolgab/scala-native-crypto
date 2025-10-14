package javax.crypto

import java.security.Provider
import java.security.{
  InvalidKeyException,
  NoSuchAlgorithmException,
  NoSuchProviderException
}
import java.security.spec.KeySpec
import java.security.spec.InvalidKeySpecException

class SecretKeyFactory protected (
    // keyFacSpi: SecretKeyFactorySpi,
    provider: Provider,
    algorithm: String
) {

  def getProvider(): Provider = ???

  def getAlgorithm(): String = {
    ???
  }

  def generateSecret(keySpec: KeySpec): SecretKey = {
    ???
  }

  def getKeySpec(key: SecretKey, keySpec: Class[_]): KeySpec = {
    ???
  }

  def translateKey(key: SecretKey): SecretKey = {
    ???
  }
}

object SecretKeyFactory {
  def getInstance(algorithm: String): SecretKeyFactory = ???

  def getInstance(algorithm: String, provider: String): SecretKeyFactory = ???

  def getInstance(algorithm: String, provider: Provider): SecretKeyFactory = ???
}

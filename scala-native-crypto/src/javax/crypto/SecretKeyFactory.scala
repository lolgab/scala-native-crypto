package javax.crypto

import java.security.Provider
import java.security.spec.KeySpec

abstract class SecretKeyFactorySpi {}

abstract class SecretKeyFactory protected (
    spi: SecretKeyFactorySpi,
    provider: Provider,
    algorithm: String
) {

  final def getProvider(): Provider = provider

  final def getAlgorithm(): String = algorithm

  def generateSecret(keySpec: KeySpec): SecretKey = ???

  def getKeySpec(key: SecretKey, keySpec: Class[_]): KeySpec = ???

  def translateKey(key: SecretKey): SecretKey = ???
}

object SecretKeyFactory {
  def getInstance(algorithm: String): SecretKeyFactory = ???

  def getInstance(algorithm: String, provider: String): SecretKeyFactory =
    throw new UnsupportedOperationException()

  def getInstance(algorithm: String, provider: Provider): SecretKeyFactory = ???
}

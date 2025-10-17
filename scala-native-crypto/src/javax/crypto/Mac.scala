package javax.crypto

import java.security.{Provider, Key}
import java.security.NoSuchAlgorithmException

import java.security.spec.AlgorithmParameterSpec
import java.nio.ByteBuffer
import java.util.Objects.requireNonNull

abstract class MacSpi

/// ## Refs
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/Mac.html
abstract class Mac protected (
    spi: MacSpi,
    provider: Provider,
    algorithm: String
) extends Cloneable {

  final def getAlgorithm(): String = algorithm

  final def getProvider(): Provider = provider

  def getMacLength(): Int

  def init(key: Key): Unit

  def init(key: Key, params: AlgorithmParameterSpec): Unit = ???

  // mark as ??? for compilation now, should be implemented later
  def update(data: Byte): Unit = ???

  def update(data: Array[Byte]): Unit

  def update(data: Array[Byte], offset: Int, len: Int): Unit = ???

  def update(data: ByteBuffer): Unit = ???

  def doFinal(): Array[Byte]

  def doFinal(data: Array[Byte], outOffset: Int): Array[Byte] = ???

  def doFinal(data: Array[Byte]): Array[Byte]

  def reset(): Unit
}

object Mac {
  import com.github.lolgab.scalanativecrypto.{OpenSslProvider, JcaService}

  def getInstance(algorithm: String): Mac =
    getInstance(algorithm, OpenSslProvider.defaultInstance)

  def getInstance(algorithm: String, provider: String): Mac =
    throw new UnsupportedOperationException()

  def getInstance(algorithm: String, provider: Provider): Mac = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty)

    val service = provider
      .getService(JcaService.Mac.name, algorithm)
    if (service == null)
      throw new NoSuchAlgorithmException(
        s"Mac $algorithm not found in provider ${provider.getName}"
      )

    service
      .newInstance(null)
      .asInstanceOf[Mac]
  }
}

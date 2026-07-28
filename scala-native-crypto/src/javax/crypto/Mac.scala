package javax.crypto

import java.nio.ByteBuffer
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.security.spec.AlgorithmParameterSpec
import java.util.Objects.requireNonNull

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/MacSpi.html
abstract class MacSpi {
  def engineGetMacLength(): Int

  def engineInit(key: Key, params: AlgorithmParameterSpec): Unit

  def engineUpdate(data: Byte): Unit

  def engineUpdate(data: Array[Byte], offset: Int, len: Int): Unit

  def engineUpdate(data: ByteBuffer): Unit = {
    requireNonNull(data, "Data ByteBuffer must not be null")
    if (data.hasRemaining()) {
      val len = data.remaining()
      val arr = new Array[Byte](len)
      data.get(arr)
      engineUpdate(arr, 0, len)
    }
  }

  def engineDoFinal(): Array[Byte]

  def engineReset(): Unit
}

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/Mac.html
abstract class Mac protected (
    protected val spi: MacSpi,
    protected val provider: Provider,
    protected val algorithm: String
) extends Cloneable {

  final def getAlgorithm(): String =
    algorithm

  final def getProvider(): Provider =
    provider

  final def getMacLength(): Int =
    spi.engineGetMacLength()

  final def init(key: Key): Unit =
    init(key, null)

  final def init(key: Key, params: AlgorithmParameterSpec): Unit =
    spi.engineInit(key, params)

  final def update(data: Byte): Unit =
    spi.engineUpdate(data)

  final def update(data: Array[Byte]): Unit =
    spi.engineUpdate(data, 0, data.length)

  final def update(data: Array[Byte], offset: Int, len: Int): Unit =
    spi.engineUpdate(data, offset, len)

  final def update(data: ByteBuffer): Unit =
    spi.engineUpdate(data)

  final def doFinal(): Array[Byte] =
    spi.engineDoFinal()

  final def doFinal(data: Array[Byte], outOffset: Int): Array[Byte] = {
    if ((data.length - outOffset) <= 0)
      throw new ShortBufferException(
        "Output buffer too small to hold the result"
      )
    update(data, outOffset, data.length - outOffset)
    spi.engineDoFinal()
  }

  final def doFinal(data: Array[Byte]): Array[Byte] = {
    update(data)
    spi.engineDoFinal()
  }

  final def reset(): Unit =
    spi.engineReset()

}

object Mac {

  import com.github.lolgab.scalanativecrypto.{OpenSSLProvider, JcaService}

  final def getInstance(algorithm: String): Mac =
    getInstance(algorithm, OpenSSLProvider.defaultInstance)

  final def getInstance(algorithm: String, provider: String): Mac =
    throw new UnsupportedOperationException()

  final def getInstance(algorithm: String, provider: Provider): Mac = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty)

    val service = provider
      .getService(JcaService.Mac.name, algorithm)
    if (service == null)
      throw new NoSuchAlgorithmException(
        s"Mac $algorithm not found in provider ${provider.getName()}"
      )

    service.newInstance(null).asInstanceOf[Mac]
  }

}

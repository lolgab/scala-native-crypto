package java.security

import java.nio.ByteBuffer
import java.security.Provider
import java.util.Objects.requireNonNull

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/MessageDigestSpi.html
abstract class MessageDigestSpi {
  def engineGetDigestLength(): Int

  def engineUpdate(input: Byte): Unit

  def engineUpdate(input: Array[Byte], offset: Int, len: Int): Unit

  def engineUpdate(input: ByteBuffer): Unit =
    if (input.hasRemaining()) {
      if (input.hasArray()) {
        val array = input.array()
        val offset = input.arrayOffset() + input.position()
        val length = input.remaining()
        engineUpdate(array, offset, length)
        input.position(input.position() + length)
      } else {
        while (input.hasRemaining()) engineUpdate(input.get())
      }
    }

  def engineDigest(): Array[Byte]

  def engineDigest(buf: Array[Byte], offset: Int, len: Int): Int

  def engineReset(): Unit
}

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/MessageDigest.html
abstract class MessageDigest(algorithm: String) extends MessageDigestSpi {

  def getProvider(): Provider

  final def getAlgorithm(): String =
    algorithm

  def update(input: Byte): Unit =
    engineUpdate(input)

  def update(input: Array[Byte], offset: Int, len: Int): Unit =
    engineUpdate(input, offset, len)

  def update(input: Array[Byte]): Unit =
    update(input, 0, input.length)

  def update(input: ByteBuffer): Unit =
    engineUpdate(input)

  def digest(): Array[Byte] =
    engineDigest()

  def digest(buf: Array[Byte], offset: Int, len: Int): Int =
    engineDigest(buf, offset, len)

  def digest(input: Array[Byte]): Array[Byte] = {
    update(input)
    digest()
  }

  override def toString(): String = ???

  def reset(): Unit =
    engineReset()

  final def getDigestLength(): Int =
    engineGetDigestLength()

}

object MessageDigest {
  import com.github.lolgab.scalanativecrypto.{OpenSSLProvider, JcaService}

  def getInstance(algorithm: String): MessageDigest =
    getInstance(algorithm, OpenSSLProvider.defaultInstance)

  def getInstance(algorithm: String, provider: String): MessageDigest =
    throw new UnsupportedOperationException()

  def getInstance(algorithm: String, provider: Provider): MessageDigest = {
    requireNonNull(provider)
    requireNonNull(algorithm)
    require(algorithm.nonEmpty)

    val service = provider.getService(JcaService.MessageDigest.name, algorithm)
    if (service == null)
      throw new NoSuchAlgorithmException(
        s"Algorithm $algorithm not found in provider ${provider.getName()}"
      )
    service.newInstance(null).asInstanceOf[MessageDigest]
  }

  // mark as ??? for compilation now, should be implemented
  def isEqual(digesta: Array[Byte], digestb: Array[Byte]): Boolean = ???
}

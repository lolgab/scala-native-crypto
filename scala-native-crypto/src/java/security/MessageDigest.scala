package java.security

import com.github.lolgab.scalanativecrypto.internal._

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer
import java.lang.ref.WeakReference
import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

abstract class MessageDigest(algorithm: String) extends MessageDigestSpi {
  def digest(): Array[Byte] = engineDigest()
  def digest(input: Array[Byte]): Array[Byte] = {
    engineUpdate(input, 0, input.length)
    engineDigest()
  }
  def digest(buf: Array[Byte], offset: Int, len: Int): Int = {
    engineDigest(buf, offset, len)
  }
  def getAlgorithm(): String = algorithm
  def getDigestLength(): Int = engineGetDigestLength()
  def update(input: Array[Byte], offset: Int, len: Int): Unit =
    engineUpdate(input, offset, len)
  def update(input: Array[Byte]): Unit =
    engineUpdate(input, 0, input.length)
  def update(input: Byte): Unit = engineUpdate(input)
  def reset(): Unit = engineReset()
}

object MessageDigest {
  def getInstance(algorithm: String): MessageDigest = {
    val (name, length) = Utils.getAlgorithmNameAndLength(algorithm, prefix = "")
    new CryptoMessageDigest(algorithm, name, length)
  }
}

private final class CryptoMessageDigest(
    algorithm: String,
    name: CString,
    length: Int
) extends MessageDigest(algorithm) {
  val ctx = crypto.EVP_MD_CTX_new()
  val md = crypto.EVP_get_digestbyname(name)

  if (LinktimeInfo.isWeakReferenceSupported) {
    val wr = new WeakReference(this)
    new CtxFinalizer(wr, ctx, crypto.EVP_MD_CTX_free(_))
  } else {
    System.err.println(
      "[java.security.MessageDigest] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  initDigest()

  override def engineGetDigestLength(): Int = length
  override def engineDigest(): Array[Byte] = {
    val result = new Array[Byte](length)
    val lengthPtr = stackalloc[Int]()
    if (
      crypto.EVP_DigestFinal(
        ctx,
        result.asInstanceOf[ByteArray].at(0),
        lengthPtr
      ) != 1
    ) {
      throw new DigestException("Failed to finalize digest")
    }
    result
  }
  override def engineReset(): Unit = {
    crypto.EVP_MD_CTX_reset(ctx)
    initDigest()
  }
  private def initDigest() = {
    if (crypto.EVP_DigestInit(ctx, md) != 1) {
      throw new DigestException("Failed to initialize digest")
    }
  }
  override def engineUpdate(input: Byte): Unit = {
    val buf = stackalloc[Byte]()
    !buf = input
    if (crypto.EVP_DigestUpdate(ctx, buf, 1.toCSize) != 1) {
      throw new DigestException("Failed to update digest")
    }
  }
  override def engineUpdate(input: Array[Byte], offset: Int, len: Int): Unit = {
    if (offset < 0 || len < 0 || len > input.length - offset) {
      throw new IndexOutOfBoundsException
    }
    if (len > 0) {
      if (
        crypto.EVP_DigestUpdate(
          ctx,
          input.asInstanceOf[ByteArray].at(offset),
          len.toCSize
        ) != 1
      ) {
        throw new DigestException("Failed to update digest")
      }
    }
  }
}

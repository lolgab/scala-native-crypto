package java.security

import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import java.lang.ref.{WeakReference, WeakReferenceRegistry}

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
    val (name, length) = algorithm.toUpperCase() match {
      case "MD5"                    => (c"MD5", 16)
      case "SHA-1" | "SHA" | "SHA1" => (c"SHA-1", 20)
      case "SHA-224"                => (c"SHA-224", 28)
      case "SHA-256"                => (c"SHA-256", 32)
      case "SHA-384"                => (c"SHA-384", 48)
      case "SHA-512"                => (c"SHA-512", 64)
      case _ =>
        throw new NoSuchAlgorithmException(
          s"$algorithm MessageDigest not available"
        )
    }
    new CryptoMessageDigest(algorithm, name, length)
  }
}

@link("crypto")
@extern
private object crypto {
  type EVP_MD_* = CVoidPtr
  type EVP_MD_CTX_* = CVoidPtr

  def RAND_bytes(buf: Ptr[Byte], num: CInt): CInt = extern

  def EVP_get_digestbyname(name: CString): EVP_MD_* = extern
  def EVP_MD_CTX_new(): EVP_MD_CTX_* = extern
  def EVP_MD_CTX_free(ctx: EVP_MD_CTX_*): Unit = extern
  def EVP_MD_CTX_reset(ctx: EVP_MD_CTX_*): Unit = extern

  def EVP_DigestInit(ctx: EVP_MD_CTX_*, tpe: EVP_MD_*): CInt = extern
  def EVP_DigestUpdate(ctx: EVP_MD_CTX_*, d: Ptr[Byte], cnt: CSize): CInt =
    extern
  def EVP_DigestFinal(ctx: EVP_MD_CTX_*, md: Ptr[Byte], s: Ptr[Int]): CInt =
    extern
}

private final class CtxFinalizer(
    weakRef: WeakReference[_ >: Null <: AnyRef],
    ctx: crypto.EVP_MD_CTX_*
) {
  WeakReferenceRegistry.addHandler(weakRef, apply)

  def apply(): Unit = {
    crypto.EVP_MD_CTX_free(ctx)
  }
}

private final class CryptoMessageDigest(
    algorithm: String,
    name: CString,
    length: Int
) extends MessageDigest(algorithm) {
  val ctx = crypto.EVP_MD_CTX_new()
  val md = crypto.EVP_get_digestbyname(name)
  val wr = new WeakReference(this)

  if (LinktimeInfo.isWeakReferenceSupported) {
    new CtxFinalizer(wr, ctx)
  }
  else {
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

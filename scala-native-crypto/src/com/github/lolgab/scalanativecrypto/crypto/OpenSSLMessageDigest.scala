package com.github.lolgab.scalanativecrypto.crypto

import com.github.lolgab.scalanativecrypto.internal._

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer
import java.security.DigestException
import java.security.{Provider, MessageDigest}
import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

final class OpenSSLMessageDigest protected[scalanativecrypto] (
    provider: Provider,
    algorithm: String,
    name: CString,
    length: Int
) extends MessageDigest(algorithm) {

  val ctx = crypto.EVP_MD_CTX_new()
  val md = crypto.EVP_get_digestbyname(name)

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_EVP_MD_CTX(this, ctx)
  } else {
    System.err.println(
      "[java.security.MessageDigest] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  initDigest()

  def getProvider(): Provider = provider

  final override def engineGetDigestLength(): Int = length

  final def engineReset(): Unit = {
    crypto.EVP_MD_CTX_reset(ctx)
    initDigest()
  }

  final def initDigest() =
    if (crypto.EVP_DigestInit(ctx, md) != 1) {
      throw new DigestException("Failed to initialize digest")
    }

  final def engineDigest(): Array[Byte] = {
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

  final override def engineDigest(
      buf: Array[Byte],
      offset: Int,
      len: Int
  ): Int =
    if (len < engineGetDigestLength()) {
      engineReset()
      throw new DigestException(
        "The value of len parameter is less than the actual digest length."
      )
    } else if (offset < 0) {
      engineReset()
      throw new DigestException("Invalid negative offset")
    } else if (offset + len > buf.length) {
      engineReset()
      throw new DigestException("Incorrect offset or len value")
    } else {
      val tmp = engineDigest()
      if (len < tmp.length) {
        throw new DigestException(
          "The value of len parameter is less than the actual digest length."
        )
      } else {
        System.arraycopy(tmp, 0, buf, offset, tmp.length)
        tmp.length
      }
    }

  final def engineUpdate(input: Byte): Unit = {
    val buf = stackalloc[Byte]()
    !buf = input
    if (crypto.EVP_DigestUpdate(ctx, buf, 1.toCSize) != 1) {
      throw new DigestException("Failed to update digest")
    }
  }

  final def engineUpdate(input: Array[Byte], offset: Int, len: Int): Unit = {
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

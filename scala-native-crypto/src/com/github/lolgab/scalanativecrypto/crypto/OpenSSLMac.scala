package com.github.lolgab.scalanativecrypto.crypto

import com.github.lolgab.scalanativecrypto.internal.Constants._
import com.github.lolgab.scalanativecrypto.internal._

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer
import java.security.{Provider, Key}
import java.security.InvalidAlgorithmParameterException
import java.security.spec.AlgorithmParameterSpec
import java.util.concurrent.atomic.AtomicBoolean
import java.util.Objects.requireNonNull
import javax.crypto.{Mac, MacSpi}
import javax.crypto.spec.SecretKeySpec

import scala.scalanative.annotation.alwaysinline
import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.unsafe._

final class OpenSSLMac protected[scalanativecrypto] (
    provider: Provider,
    algorithm: String,
    name: CString,
    length: Int
) extends Mac(new OpenSSLMacSpi(algorithm, name, length), provider, algorithm)

private[scalanativecrypto] final class OpenSSLMacSpi(
    algorithm: String,
    name: CString,
    length: Int
) extends MacSpi {

  private val ctx: crypto.HMAC_CTX_* = crypto.HMAC_CTX_new()
  if (ctx == null) {
    throw new RuntimeException("Failed to create HMAC context")
  }

  private val isInitialized = new AtomicBoolean(false)

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_HMAC_CTX(this, ctx)
  } else {
    System.err.println(
      "[javax.crypto.Mac] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  final def engineGetMacLength(): Int =
    length

  // Initialize the Mac instance with the given key
  final def engineInit(key: Key, params: AlgorithmParameterSpec): Unit = {
    requireNonNull(key, "Key must not be null")

    if (!isInitialized.get()) {
      val keySpec = key match {
        case k: SecretKeySpec => k
        case _ =>
          throw new InvalidAlgorithmParameterException(
            s"Unsupported key type: ${key.getClass.getName}"
          )
      }

      // Convert the key to a C pointer
      val keyArray = keySpec.getEncoded()
      val keyPtr = keyArray.at(0)

      val md = crypto.EVP_get_digestbyname(name)
      if (md == null) {
        throw new RuntimeException(s"Failed to get algorithm ${algorithm}")
      }

      // Initialize the HMAC context with key and algorithm
      if (crypto.HMAC_Init_ex(ctx, keyPtr, keyArray.length, md, null) != 1) {
        throw new RuntimeException("Failed to initialize HMAC context")
      }

      isInitialized.compareAndExchange(false, true)
    }

  }

  final def engineUpdate(data: Byte): Unit = {
    throwIfNotInitialized()

    val bytePtr = stackalloc[Byte]()
    !bytePtr = data
    if (crypto.HMAC_Update(ctx, bytePtr, 1) != 1)
      throw new RuntimeException("Failed to update HMAC with byte data")
  }

  // Update the MAC with more data
  final def engineUpdate(data: Array[Byte], offset: Int, len: Int): Unit = {
    throwIfNotInitialized()

    if (len == 0) return

    if (offset < 0 || len < 0 || len > data.length - offset)
      throw new ArrayIndexOutOfBoundsException()

    val dataPtr = data.at(offset)
    if (crypto.HMAC_Update(ctx, dataPtr, len) != 1)
      throw new RuntimeException("Failed to update HMAC with data")
  }

  final def engineDoFinal(): Array[Byte] = {
    throwIfNotInitialized()

    // Allocate memory for result and its length
    val result = stackalloc[Byte](EVP_MAX_MD_SIZE)
    val resultLen = stackalloc[Int]()

    // Finalize and obtain the HMAC result
    if (crypto.HMAC_Final(ctx, result, resultLen) != 1) {
      throw new RuntimeException("Failed to finalize HMAC computation")
    }

    // Convert result to Scala Array[Byte]
    val len = (!resultLen).toInt
    val hmacResult = new Array[Byte](len)
    for (i <- 0 until len) {
      hmacResult(i) = !(result + i)
    }

    hmacResult
  }

  final def engineReset(): Unit =
    if (ctx != null) {
      crypto.HMAC_CTX_reset(ctx)
      isInitialized.compareAndExchange(true, false)
    }

  // TODO: we can use HMAC_CTX_copy to implement cloning
  final override def clone(): Object =
    throw new CloneNotSupportedException(
      "OpenSSLMacSpi does not support cloning now"
    )

  /*
   * Helper methods
   */

  @alwaysinline
  private def throwIfNotInitialized(): Unit =
    if (!isInitialized.get()) {
      throw new IllegalStateException("MAC not initialized")
    }

}

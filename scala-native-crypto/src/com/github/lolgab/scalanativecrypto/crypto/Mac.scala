package com.github.lolgab.scalanativecrypto.crypto

import com.github.lolgab.scalanativecrypto.internal.Constants._
import com.github.lolgab.scalanativecrypto.internal._

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer
import java.security.Key
import java.security.Provider
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.unsafe._

final class OpenSslMac protected[scalanativecrypto] (
    provider: Provider,
    algorithm: String,
    name: CString,
    length: Int
) extends Mac(null, provider, algorithm) {

  private val ctx: crypto.HMAC_CTX_* = crypto.HMAC_CTX_new()
  if (ctx == null) {
    throw new RuntimeException("Failed to create HMAC context")
  }

  private var isInitialized: Boolean = false

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_HMAC_CTX(this, ctx)
  } else {
    System.err.println(
      "[javax.crypto.Mac] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  def getMacLength(): Int = length

  // Initialize the Mac instance with the given key
  def init(key: Key): Unit = {
    val keySpec = key match {
      case k: SecretKeySpec => k
      case _                => sys.error("Only SecretKeySpec supported for now")
    }

    // Convert the key to a C pointer
    val keyArray = keySpec.getEncoded()
    val keyPtr = keyArray.at(0)

    val md = crypto.EVP_get_digestbyname(name)
    if (md == null) {
      throw new RuntimeException(s"Failed to get algorithm $algorithm")
    }

    // Initialize the HMAC context with key and algorithm
    if (crypto.HMAC_Init_ex(ctx, keyPtr, keyArray.length, md, null) != 1) {
      throw new RuntimeException("Failed to initialize HMAC context")
    }

    isInitialized = true
  }

  // Update the MAC with more data
  def update(data: Array[Byte]): Unit = {
    if (!isInitialized) {
      throw new IllegalStateException("MAC not initialized")
    }
    val dataPtr = data.at(0)
    if (crypto.HMAC_Update(ctx, dataPtr, data.length) != 1)
      throw new RuntimeException("Failed to update HMAC with data")
  }

  def doFinal(data: Array[Byte]): Array[Byte] = {
    update(data)
    doFinal()
  }

  def doFinal(): Array[Byte] = {
    require(isInitialized, "Mac has not been initialized with a key")

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

  def reset(): Unit =
    if (ctx != null)
      crypto.HMAC_CTX_reset(ctx)

}

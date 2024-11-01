package javax.crypto

import com.github.lolgab.scalanativecrypto.internal._
import com.github.lolgab.scalanativecrypto.internal.Constants._
import scala.scalanative.unsafe._
import java.security
import javax.crypto.spec.SecretKeySpec
import scala.scalanative.meta.LinktimeInfo

import java.lang.ref.WeakReference
import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer

class Mac private (algorithm: String, name: CString, length: Int) {
  private val ctx: crypto.HMAC_CTX_* = crypto.HMAC_CTX_new()
  if (ctx == null) {
    throw new RuntimeException("Failed to create HMAC context")
  }

  private var isInitialized: Boolean = false

  if (LinktimeInfo.isWeakReferenceSupported) {
    val wr = new WeakReference(this)
    new CtxFinalizer(wr, ctx, crypto.HMAC_CTX_free(_))
  } else {
    System.err.println(
      "[javax.crypto.Mac] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  // Initialize the Mac instance with the given key
  def init(key: security.Key): Unit = {
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

  def reset(): Unit = {
    if (ctx != null) {
      crypto.HMAC_CTX_reset(ctx)
    }
  }
}

object Mac {
  // Factory method to create a Mac instance with the specified algorithm
  def getInstance(algorithm: String): Mac = {
    val (name, length) =
      Utils.getAlgorithmNameAndLength(algorithm, prefix = "HMAC")
    new Mac(algorithm, name, length)
  }
}

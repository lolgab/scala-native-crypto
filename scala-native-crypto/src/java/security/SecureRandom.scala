package java.security

import java.util.Random

import com.github.lolgab.scalanativecrypto.internal._

import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsafe._

class SecureRandom() extends Random(0L) {

  override def setSeed(x: Long): Unit = ()

  override def nextBytes(bytes: Array[Byte]): Unit = {
    val len = bytes.length
    nextBytes(bytes.asInstanceOf[ByteArray].at(0), len)
  }

  // Adapted from Scala.js
  // https://github.com/scala-js/scala-js-java-securerandom/blob/d6cf1c8651006047bb8c8bfc754ef10500d3bd06/src/main/scala/java/security/SecureRandom.scala#L47
  override protected final def next(numBits: Int): Int = {
    if (numBits <= 0) {
      0 // special case because the formula on the last line is incorrect for numBits == 0
    } else {
      val bytes = stackalloc[Int]()
      nextBytes(bytes.asInstanceOf[Ptr[Byte]], 4)
      val rand32 = !bytes
      rand32 & (-1 >>> (32 - numBits)) // Clear the (32 - numBits) higher order bits
    }
  }

  private def nextBytes(bytes: Ptr[Byte], len: Int): Unit = {
    if (crypto.RAND_bytes(bytes, len) < 0)
      throw new GeneralSecurityException("Failed to generate random bytes")
  }

}

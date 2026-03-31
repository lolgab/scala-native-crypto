package javax.crypto

import java.security.GeneralSecurityException

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/ShortBufferException.html
 */
class ShortBufferException(msg: String) extends GeneralSecurityException(msg) {
  def this() = this(null)
}

package javax.crypto

import java.security.GeneralSecurityException

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/BadPaddingException.html
 */
class BadPaddingException(msg: String) extends GeneralSecurityException(msg) {
  def this() = this(null)
}

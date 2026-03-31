package javax.crypto

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/AEADBadTagException.html
 */
class AEADBadTagException(msg: String) extends BadPaddingException(msg) {
  def this() = this(null)
}

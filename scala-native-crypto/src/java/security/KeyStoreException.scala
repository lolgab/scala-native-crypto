package java.security

class KeyStoreException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

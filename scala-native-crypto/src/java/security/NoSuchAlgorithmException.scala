package java.security

class NoSuchAlgorithmException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cuase: Throwable) = this(null, cuase)
}

package java.security;

class NoSuchAlgorithmException(message: String, cause: Throwable)
    extends GeneralSecurityException(message, cause) {
  def this(message: String) = this(message, null)
  def this(cuase: Throwable) = this(null, cuase)
  def this() = this(null, null)
}

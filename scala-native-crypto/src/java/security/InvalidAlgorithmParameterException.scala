package java.security

class InvalidAlgorithmParameterException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null);
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

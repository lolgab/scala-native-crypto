package java.security.spec

import java.security.GeneralSecurityException

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/spec/InvalidParameterSpecException.html
class InvalidParameterSpecException(msg: String)
    extends GeneralSecurityException(msg, null) {
  def this() = this(null)
}

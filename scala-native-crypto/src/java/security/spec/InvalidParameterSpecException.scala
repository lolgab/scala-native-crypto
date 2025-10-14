package java.security.spec

import java.security.GeneralSecurityException

class InvalidParameterSpecException(msg: String)
    extends GeneralSecurityException(msg, null) {
  def this() = this(null)
}

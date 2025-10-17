package java.security

import java.security.spec.AlgorithmParameterSpec

/// @since JDK 22
///
/// ## Refs
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/AsymmetricKey.html
///
///
trait AsymmetricKey extends Key {
  // Mark as not implemented yet, subclasses don't need to impl it.
  //
  // Major version is still JDK 11/17/21,
  // so we delay this implementation until JDK 25 join in our runtime infra
  def getParams(): AlgorithmParameterSpec = throw new NotImplementedError()
}

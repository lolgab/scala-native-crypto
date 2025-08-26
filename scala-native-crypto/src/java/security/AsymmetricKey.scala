package java.security

import java.security.spec.AlgorithmParameterSpec

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/AsymmetricKey.html
// @since JDK 22
trait AsymmetricKey extends Key with DEREncodable {
  // Mark as not implemented yet, subclasses don't need to impl it.
  //
  // Major version is still JDK 11/17/21,
  // so we delay this implementation until JDK 25 join in our runtime infra
  def getParams(): AlgorithmParameterSpec = throw new NotImplementedError()
}

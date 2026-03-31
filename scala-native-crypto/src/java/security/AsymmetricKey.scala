package java.security

import java.security.spec.AlgorithmParameterSpec

// Refs
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/AsymmetricKey.html

//
// @since JDK 22
trait AsymmetricKey extends Key {
  def getParams(): AlgorithmParameterSpec = throw new NotImplementedError()
}

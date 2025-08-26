package java.security

import java.util.{Set => JSet}

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/AlgorithmConstraints.html
trait AlgorithmConstraints {
  def permits(
      primitives: JSet[CryptoPrimitive],
      algorithm: String,
      parameters: AlgorithmParameters
  ): Boolean

  def permits(primitives: JSet[CryptoPrimitive], key: Key): Boolean

  def permits(
      primitives: JSet[CryptoPrimitive],
      algorithm: String,
      key: Key,
      parameters: AlgorithmParameters
  ): Boolean
}

package java.security

import java.util.{Set => JSet}

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/AlgorithmConstraints.html
 */
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

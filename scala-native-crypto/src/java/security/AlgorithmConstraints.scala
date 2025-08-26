package java.security

import java.util.{Set => JSet}

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

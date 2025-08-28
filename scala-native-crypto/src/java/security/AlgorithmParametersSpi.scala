package java.security

import java.security.spec.AlgorithmParameterSpec
import java.security.spec.InvalidParameterSpecException

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/AlgorithmParametersSpi.html
abstract class AlgorithmParametersSpi {
  protected def engineInit(paramSpec: AlgorithmParameterSpec): Unit = ???

  protected def engineInit(params: Array[Byte]): Unit = ???

  protected def engineInit(params: Array[Byte], format: String): Unit = ???

  protected def engineGetParameterSpec[T <: AlgorithmParameterSpec](
      paramSpec: Class[T]
  ): T = ???

  protected def engineGetEncoded(): Array[Byte] = ???

  protected def engineGetEncoded(format: String): Array[Byte] = ???

  protected def engineToString(): String = ???
}

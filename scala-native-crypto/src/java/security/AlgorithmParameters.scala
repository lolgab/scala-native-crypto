package java.security

import java.io.IOException
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.InvalidParameterSpecException
import java.util.Objects.requireNonNull
import java.util.concurrent.atomic.AtomicBoolean

// NOTE:
//
// There is no `paramSpi` in the constructor.
//
// All documentated methods of `AlgorithmParametersSpi` have been marked as `protected`,
// so they are not callable from `AlgorithmParameters`
//
// If you do follow the official doc that passing `paramSpi` to the constructor, you will get compile error
//
// ```
// ...
// [error] protected method engineInit can only be accessed from class AlgorithmParametersSpi in package java.security or one of its subclasses.
// ...
// ```
//
// AlgorithmParameters's constructor is `protected`, so it's fine and safe to violate the doc here.
//
// References:
//  - https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/AlgorithmParameters.html
//  - https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/AlgorithmParametersSpi.html
class AlgorithmParameters protected (
    // paramSpi: AlgorithmParametersSpi,
    provider: Provider,
    algorithm: String
) extends AlgorithmParametersSpi {

  private val _initialized: AtomicBoolean = AtomicBoolean(false)

  final def getAlgorithm(): String = algorithm

  final def getProvider(): Provider = provider

  final def init(paramSpec: AlgorithmParameterSpec): Unit = {
    if (_initialized.get())
      throw InvalidParameterSpecException("already initialized")

    engineInit(paramSpec)

    _initialized.compareAndSet(false, true)
  }

  final def init(params: Array[Byte]): Unit = {
    if (_initialized.get()) throw IOException("already initialized")

    engineInit(params)

    _initialized.compareAndSet(false, true)
  }

  final def init(params: Array[Byte], format: String): Unit = {
    if (_initialized.get()) throw IOException("already initialized")

    engineInit(params, format)

    _initialized.compareAndSet(false, true)
  }

  final def getParameterSpec[T <: AlgorithmParameterSpec](
      paramSpec: Class[T]
  ): T = {
    if (!_initialized.get())
      throw InvalidParameterSpecException("not initialized")

    engineGetParameterSpec(paramSpec)
  }

  final def getEncoded(): Array[Byte] = {
    if (!_initialized.get()) throw IOException("not initialized")

    engineGetEncoded()
  }

  final def getEncoded(format: String): Array[Byte] = {
    requireNonNull(format)
    require(format.nonEmpty)
    if (!_initialized.get()) throw IOException("not initialized")

    engineGetEncoded(format)
  }

  final override def toString(): String = {
    if (!_initialized.get()) ""
    else engineToString()
  }
}

object AlgorithmParameters {

  def getInstance(algorithm: String): AlgorithmParameters = {
    requireNonNull(algorithm)
    require(algorithm.nonEmpty)

    ???
  }

  def getInstance(algorithm: String, provider: String): AlgorithmParameters = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty)
    require(provider.nonEmpty)

    ???
  }

  def getInstance(
      algorithm: String,
      provider: Provider
  ): AlgorithmParameters = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty)

    ???
  }
}

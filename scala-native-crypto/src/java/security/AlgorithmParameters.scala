package java.security

import java.io.IOException
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.InvalidParameterSpecException
import java.util.Objects.requireNonNull

import java.util.concurrent.atomic.AtomicBoolean

class AlgorithmParameters protected (
    paramSpi: AlgorithmParametersSpi,
    provider: Provider,
    algorithm: String
) {

  private val _initialized: AtomicBoolean = AtomicBoolean(false)

  final def getAlgorithm(): String = algorithm

  final def getProvider(): Provider = provider

  final def init(paramSpec: AlgorithmParameterSpec): Unit = {
    if (_initialized.get())
      throw InvalidParameterSpecException("already initialized")

    paramSpi.engineInit(paramSpec)

    _initialized.compareAndSet(false, true)
  }

  final def init(params: Array[Byte]): Unit = {
    if (_initialized.get()) throw IOException("already initialized")

    paramSpi.engineInit(params)

    _initialized.compareAndSet(false, true)
  }

  final def init(params: Array[Byte], format: String): Unit = {
    if (_initialized.get()) throw IOException("already initialized")

    paramSpi.engineInit(params, format)

    _initialized.compareAndSet(false, true)
  }

  final def getParameterSpec[T <: AlgorithmParameterSpec](
      paramSpec: Class[T]
  ): T = {
    if (!_initialized.get())
      throw InvalidParameterSpecException("not initialized")

    paramSpi.engineGetParameterSpec(paramSpec)
  }

  final def getEncoded(): Array[Byte] = {
    if (!_initialized.get()) throw IOException("not initialized")

    paramSpi.engineGetEncoded()
  }

  final def getEncoded(format: String): Array[Byte] = {
    if (!_initialized.get()) throw IOException("not initialized")

    paramSpi.engineGetEncoded(format)
  }

  final override def toString(): String = {
    if (!_initialized.get()) ""
    else paramSpi.engineToString()
  }
}

object AlgorithmParameters {

  def getInstance(algorithm: String): AlgorithmParameters = {
    requireNonNull(algorithm, "null algorithm name")

    ???
  }

  def getInstance(algorithm: String, provider: String): AlgorithmParameters = {
    requireNonNull(algorithm, "null algorithm name")
    requireNonNull(provider, "null provider")
    require(provider.nonEmpty)

    ???
  }

  def getInstance(
      algorithm: String,
      provider: Provider
  ): AlgorithmParameters = {
    requireNonNull(algorithm, "null algorithm name")
    requireNonNull(provider, "null provider")

    ???
  }
}

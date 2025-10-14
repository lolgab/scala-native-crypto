package java.security

import java.nio.ByteBuffer
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.Objects.requireNonNull

import javax.crypto.Cipher

// ref: https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/Signature.html
abstract class Signature protected (algorithm: String) extends SignatureSpi {

  @volatile private var _provider: Provider = null

  protected val UNINITIALIZED = 0
  protected val SIGN = 2
  protected val VERIFY = 3

  @volatile protected var state = UNINITIALIZED

  final def getProvider(): Provider = _provider

  final def initVerify(publicKey: PublicKey): Unit = {
    engineInitVerify(publicKey)
    state = VERIFY
  }

  final def initVerify(certificate: Certificate): Unit = {
    engineInitVerify(getPublicKeyFromCert(certificate))
    state = VERIFY
  }

  final def initSign(privateKey: PrivateKey): Unit = {
    engineInitSign(privateKey)
    state = SIGN
  }

  final def initSign(privateKey: PrivateKey, random: SecureRandom): Unit = {
    engineInitSign(privateKey, random)
    state = SIGN
  }

  final def sign(): Array[Byte] = {
    if (state == SIGN) engineSign()
    else throw new SignatureException("object not initialized for signing")
  }

  final def sign(outbuf: Array[Byte], off: Int, len: Int): Int = {
    requireNonNull(outbuf == null)
    require(off >= 0 && len > 0 && (off + len) <= outbuf.length)

    if (state != SIGN)
      throw new SignatureException("object not initialized for signing")

    engineSign(outbuf, off, len)
  }

  final def verify(sig: Array[Byte]): Boolean = {
    if (state == VERIFY) engineVerify(sig)
    else throw new SignatureException("object not initialized for verification")
  }

  final def verify(sig: Array[Byte], off: Int, len: Int): Boolean = {
    requireNonNull(sig)
    require(off >= 0 && len > 0 && (off + len) <= sig.length)

    if (state == VERIFY) engineVerify(sig, off, len)
    else throw new SignatureException("object not initialized for verification")
  }

  final def update(b: Byte): Unit = {
    if (state == VERIFY || state == SIGN) engineUpdate(b)
    else
      throw new SignatureException(
        "object not initialized for signature or verification"
      )
  }

  final def update(data: Array[Byte]): Unit = update(data, 0, data.length)

  final def update(data: Array[Byte], off: Int, len: Int): Unit = {
    requireNonNull(data)
    require(off >= 0 && len >= 0 && off + len <= data.length)

    if (state == SIGN || state == VERIFY) engineUpdate(data, off, len)
    else
      throw new SignatureException(
        "object not initialized for signature or verification"
      )
  }

  final def update(data: ByteBuffer): Unit = {
    if (state != SIGN && state != VERIFY) {
      throw new SignatureException(
        "object not initialized for signature or verification"
      )
    }
    requireNonNull(data)

    engineUpdate(data)
  }
  final def getAlgorithm(): String = algorithm

  override def toString: String = {
    val s = state match {
      case UNINITIALIZED => "<not initialized>"
      case VERIFY        => "<initialized for verifying>"
      case SIGN          => "<initialized for signing>"
      case _             => ""
    }
    s"Signature object: ${algorithm} ${s}"
  }

  // @deprecated
  // final def setParameter(param: String, value: Object): Unit

  final def setParameter(params: AlgorithmParameterSpec): Unit =
    engineSetParameter(params)

  final def getParameters(): AlgorithmParameters = engineGetParameters()

  // @deprecated
  // private def getProviderName: String =

  override def clone(): Object = {
    if (this.isInstanceOf[Cloneable]) super.clone()
    else throw new CloneNotSupportedException()
  }

  //
  // Private helpers
  //

  private def getPublicKeyFromCert(certificate: Certificate): PublicKey = {
    requireNonNull(certificate)
    if (!certificate.isInstanceOf[X509Certificate]) {
      throw new InvalidKeyException("Only X.509 certificates are supported")
    }

    val x509cert = certificate.asInstanceOf[X509Certificate]
    val publicKey = x509cert.getPublicKey()
    if (publicKey == null) {
      throw new InvalidKeyException("Null public key in certificate")
    }

    publicKey
  }
}

object Signature {

  def getInstance(algorithm: String): Signature = {
    requireNonNull(algorithm)
    require(algorithm.nonEmpty)

    ???
  }

  def getInstance(algorithm: String, provider: String): Signature = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty && provider.nonEmpty)

    ???
  }

  def getInstance(algorithm: String, provider: Provider): Signature = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty)

    ???
  }

}

package com.github.lolgab.scalanativecrypto.crypto

import com.github.lolgab.scalanativecrypto.internal.crypto
import com.github.lolgab.scalanativecrypto.internal.crypto._

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer
import java.nio.ByteBuffer
import java.security._
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec

import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

/** OpenSSL-backed Ed25519 signature implementation. */
class OpenSslEd25519Signature(provider: Provider)
    extends Signature(new SignatureSpi {}, provider, "Ed25519") {

  private val ED25519_SIG_SIZE = 64
  private val EVP_PKEY_ED25519 = 1087

  private var pkey: EVP_PKEY_* = null
  private val dataBuffer = new java.io.ByteArrayOutputStream()

  override def initVerify(publicKey: PublicKey): Unit = {
    if (publicKey == null) throw new InvalidKeyException("Public key is null")
    publicKey match {
      case k: OpenSslEd25519PublicKey =>
        pkey = k.evpPkey
        state = VERIFY
        dataBuffer.reset()
      case _ =>
        throw new InvalidKeyException(
          s"Unsupported key type: ${publicKey.getClass.getName}"
        )
    }
  }

  override def initVerify(certificate: Certificate): Unit =
    throw new UnsupportedOperationException("Certificate-based verification not supported")

  override def initSign(privateKey: PrivateKey): Unit = {
    if (privateKey == null) throw new InvalidKeyException("Private key is null")
    privateKey match {
      case k: OpenSslEd25519PrivateKey =>
        pkey = k.evpPkey
        state = SIGN
        dataBuffer.reset()
      case _ =>
        throw new InvalidKeyException(
          s"Unsupported key type: ${privateKey.getClass.getName}"
        )
    }
  }

  override def initSign(privateKey: PrivateKey, random: SecureRandom): Unit =
    initSign(privateKey)

  override def update(b: Byte): Unit = {
    if (state == UNINITIALIZED)
      throw new SignatureException("Signature not initialized")
    dataBuffer.write(b.toInt)
  }

  override def update(data: Array[Byte], off: Int, len: Int): Unit = {
    if (state == UNINITIALIZED)
      throw new SignatureException("Signature not initialized")
    dataBuffer.write(data, off, len)
  }

  override def update(data: ByteBuffer): Unit = {
    if (state == UNINITIALIZED)
      throw new SignatureException("Signature not initialized")
    if (data.hasArray) {
      dataBuffer.write(data.array(), data.position(), data.remaining())
      data.position(data.limit())
    } else {
      val bytes = new Array[Byte](data.remaining())
      data.get(bytes)
      dataBuffer.write(bytes)
    }
  }

  override def sign(): Array[Byte] = {
    if (state != SIGN)
      throw new SignatureException("Signature not initialized for signing")

    val data = dataBuffer.toByteArray
    dataBuffer.reset()

    val mdCtx = crypto.EVP_MD_CTX_new()
    if (mdCtx == null) throw new SignatureException("Failed to create EVP_MD_CTX")

    try {
      val nullPctx: Ptr[EVP_PKEY_CTX_*] = null
      val nullMd: EVP_MD_* = null
      val nullEngine: ENGINE_* = null

      if (crypto.EVP_DigestSignInit(mdCtx, nullPctx, nullMd, nullEngine, pkey) != 1)
        throw new SignatureException("EVP_DigestSignInit failed")

      val sigLen = stackalloc[CSize]()
      !sigLen = ED25519_SIG_SIZE.toCSize
      val sigBuf = stackalloc[Byte](ED25519_SIG_SIZE)

      val dataPtr = if (data.isEmpty) null else data.asInstanceOf[ByteArray].at(0)
      if (crypto.EVP_DigestSign(mdCtx, sigBuf, sigLen, dataPtr, data.length.toCSize) != 1)
        throw new SignatureException("EVP_DigestSign failed")

      val result = new Array[Byte]((!sigLen).toInt)
      var i = 0
      while (i < result.length) {
        result(i) = sigBuf(i)
        i += 1
      }
      result
    } finally {
      crypto.EVP_MD_CTX_free(mdCtx)
    }
  }

  override def sign(outbuf: Array[Byte], off: Int, len: Int): Int = {
    val sig = sign()
    if (len < sig.length)
      throw new SignatureException(s"Buffer too small: need ${sig.length}, got $len")
    System.arraycopy(sig, 0, outbuf, off, sig.length)
    sig.length
  }

  override def verify(sig: Array[Byte]): Boolean = {
    if (state != VERIFY)
      throw new SignatureException("Signature not initialized for verification")

    val data = dataBuffer.toByteArray
    dataBuffer.reset()

    val mdCtx = crypto.EVP_MD_CTX_new()
    if (mdCtx == null) throw new SignatureException("Failed to create EVP_MD_CTX")

    try {
      val nullPctx: Ptr[EVP_PKEY_CTX_*] = null
      val nullMd: EVP_MD_* = null
      val nullEngine: ENGINE_* = null

      if (crypto.EVP_DigestVerifyInit(mdCtx, nullPctx, nullMd, nullEngine, pkey) != 1)
        throw new SignatureException("EVP_DigestVerifyInit failed")

      val sigPtr = sig.asInstanceOf[ByteArray].at(0)
      val dataPtr = if (data.isEmpty) null else data.asInstanceOf[ByteArray].at(0)
      crypto.EVP_DigestVerify(mdCtx, sigPtr, sig.length.toCSize, dataPtr, data.length.toCSize) == 1
    } finally {
      crypto.EVP_MD_CTX_free(mdCtx)
    }
  }

  override def verify(sig: Array[Byte], off: Int, len: Int): Boolean = {
    val subSig = new Array[Byte](len)
    System.arraycopy(sig, off, subSig, 0, len)
    verify(subSig)
  }

  override def setParameter(params: AlgorithmParameterSpec): Unit =
    throw new UnsupportedOperationException("Ed25519 does not use parameters")

  override def getParameters(): AlgorithmParameters = null
}

/** Ed25519 public key backed by an OpenSSL EVP_PKEY. */
class OpenSslEd25519PublicKey(private[crypto] val evpPkey: EVP_PKEY_*) extends PublicKey {

  override def getAlgorithm(): String = "Ed25519"
  override def getFormat(): String = "RAW"

  override def getEncoded(): Array[Byte] = {
    val len = stackalloc[CSize]()
    !len = 32.toCSize
    val buf = stackalloc[Byte](32)
    if (crypto.EVP_PKEY_get_raw_public_key(evpPkey, buf, len) != 1)
      throw new java.security.spec.InvalidKeySpecException("Failed to export public key")
    val result = new Array[Byte]((!len).toInt)
    var i = 0
    while (i < result.length) {
      result(i) = buf(i)
      i += 1
    }
    result
  }
}

/** Ed25519 private key backed by an OpenSSL EVP_PKEY. */
class OpenSslEd25519PrivateKey(private[crypto] val evpPkey: EVP_PKEY_*) extends PrivateKey {

  override def getAlgorithm(): String = "Ed25519"
  override def getFormat(): String = "RAW"

  override def getEncoded(): Array[Byte] = {
    val len = stackalloc[CSize]()
    !len = 32.toCSize
    val buf = stackalloc[Byte](32)
    if (crypto.EVP_PKEY_get_raw_private_key(evpPkey, buf, len) != 1)
      throw new java.security.spec.InvalidKeySpecException("Failed to export private key")
    val result = new Array[Byte]((!len).toInt)
    var i = 0
    while (i < result.length) {
      result(i) = buf(i)
      i += 1
    }
    result
  }
}

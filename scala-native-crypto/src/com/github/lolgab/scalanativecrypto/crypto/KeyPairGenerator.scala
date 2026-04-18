package com.github.lolgab.scalanativecrypto.crypto

import com.github.lolgab.scalanativecrypto.internal.crypto
import com.github.lolgab.scalanativecrypto.internal.crypto._

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer
import java.security._
import java.security.spec.AlgorithmParameterSpec

import scala.scalanative.unsafe._

/** OpenSSL-backed Ed25519 key pair generator. */
class OpenSslEd25519KeyPairGenerator(provider: Provider)
    extends KeyPairGenerator(new KeyPairGeneratorSpi {}, provider, "Ed25519") {

  private val EVP_PKEY_ED25519 = 1087

  override def initialize(keysize: Int): Unit = ()
  override def initialize(keysize: Int, random: SecureRandom): Unit = ()
  override def initialize(param: AlgorithmParameterSpec): Unit = ()
  override def initialize(param: AlgorithmParameterSpec, random: SecureRandom): Unit = ()

  override def generateKeyPair(): KeyPair = {
    val ctx = crypto.EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, null)
    if (ctx == null) throw new ProviderException("EVP_PKEY_CTX_new_id failed for Ed25519")

    try {
      if (crypto.EVP_PKEY_keygen_init(ctx) != 1)
        throw new ProviderException("EVP_PKEY_keygen_init failed")

      val pkeyPtr = stackalloc[EVP_PKEY_*]()
      !pkeyPtr = null
      if (crypto.EVP_PKEY_keygen(ctx, pkeyPtr) != 1)
        throw new ProviderException("EVP_PKEY_keygen failed for Ed25519")

      val pkey = !pkeyPtr
      val pubKey = new OpenSslEd25519PublicKey(pkey)
      val privKey = new OpenSslEd25519PrivateKey(pkey)
      CtxFinalizer.register_EVP_PKEY(pubKey, pkey)

      new KeyPair(pubKey, privKey)
    } finally {
      crypto.EVP_PKEY_CTX_free(ctx)
    }
  }
}

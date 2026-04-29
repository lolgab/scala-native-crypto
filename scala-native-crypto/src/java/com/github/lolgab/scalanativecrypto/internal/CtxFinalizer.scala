package java.com.github.lolgab.scalanativecrypto.internal

import com.github.lolgab.scalanativecrypto.internal.crypto

import java.lang.ref.Cleaner

import scala.scalanative.unsafe.Ptr

object CtxFinalizer {
  private val cleaner: Cleaner = Cleaner.create()

  private final class EVP_MD_CTX_State(ctx: crypto.EVP_MD_CTX_*)
      extends Runnable {
    override def run(): Unit = crypto.EVP_MD_CTX_free(ctx)
  }
  def register_EVP_MD_CTX(owner: AnyRef, ctx: crypto.EVP_MD_CTX_*): Unit =
    cleaner.register(owner, new EVP_MD_CTX_State(ctx))

  private final class EVP_PKEY_State(ptr: crypto.EVP_PKEY_*) extends Runnable {
    override def run(): Unit = crypto.EVP_PKEY_free(ptr)
  }
  def register_EVP_PKEY(owner: AnyRef, ptr: crypto.EVP_PKEY_*): Unit =
    cleaner.register(owner, new EVP_PKEY_State(ptr))

  private final class HMAC_CTX_State(ctx: crypto.HMAC_CTX_*) extends Runnable {
    override def run(): Unit = crypto.HMAC_CTX_free(ctx)
  }
  def register_HMAC_CTX(owner: AnyRef, ctx: crypto.HMAC_CTX_*): Unit =
    cleaner.register(owner, new HMAC_CTX_State(ctx))

  private final class PKCS12_State(ptr: crypto.PKCS12_*) extends Runnable {
    override def run(): Unit = crypto.PKCS12_free(ptr)
  }
  def register_PKCS12(owner: AnyRef, ptr: crypto.PKCS12_*): Unit =
    cleaner.register(owner, new PKCS12_State(ptr))

  private final class X509_State(ptr: crypto.X509_*) extends Runnable {
    override def run(): Unit = crypto.X509_free(ptr)
  }
  def register_X509(owner: AnyRef, ptr: crypto.X509_*): Unit =
    cleaner.register(owner, new X509_State(ptr))

  private final class StackOfX509_State(ptr: Ptr[crypto.stack_st_X509])
      extends Runnable {
    override def run(): Unit = crypto.sncrypto_ossl_sk_X509_free(ptr)
  }
  def register_StackOfX509(
      owner: AnyRef,
      ptr: Ptr[crypto.stack_st_X509]
  ): Unit =
    cleaner.register(owner, new StackOfX509_State(ptr))

}

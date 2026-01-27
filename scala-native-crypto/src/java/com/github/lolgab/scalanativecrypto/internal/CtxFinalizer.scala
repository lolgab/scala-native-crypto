package java.com.github.lolgab.scalanativecrypto.internal

import com.github.lolgab.scalanativecrypto.internal.crypto
import java.lang.ref.Cleaner

object CtxFinalizer {
  private val cleaner: Cleaner = Cleaner.create()

  private final class EVP_MD_CTX_State(ctx: crypto.EVP_MD_CTX_*)
      extends Runnable {
    override def run(): Unit = crypto.EVP_MD_CTX_free(ctx)
  }

  def register_EVP_MD_CTX(owner: AnyRef, ctx: crypto.EVP_MD_CTX_*): Unit =
    cleaner.register(owner, new EVP_MD_CTX_State(ctx))

  private final class HMAC_CTX_State(ctx: crypto.HMAC_CTX_*) extends Runnable {
    override def run(): Unit = crypto.HMAC_CTX_free(ctx)
  }

  def register_HMAC_CTX(owner: AnyRef, ctx: crypto.HMAC_CTX_*): Unit =
    cleaner.register(owner, new HMAC_CTX_State(ctx))

}

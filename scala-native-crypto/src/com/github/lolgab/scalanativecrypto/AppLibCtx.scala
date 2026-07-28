package com.github.lolgab.scalanativecrypto

import java.util.concurrent.atomic.AtomicBoolean
import java.nio.file.{Files, Path}

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer

import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.unsafe.{CQuote, fromCString}
import scala.scalanative.unsigned.UnsignedRichInt

import internal.crypto.OSSL_LIB_CTX_*
import internal.crypto.{
  OSSL_LIB_CTX_new,
  OSSL_PROVIDER_load,
  CONF_get1_default_config_file,
  CONF_modules_load_file_ex,
  ERR_get_error,
  ERR_error_string,
  OSSL_PROVIDER_unload
}

private[scalanativecrypto] object AppLibCtx {

  final val osslLibCtx: OSSL_LIB_CTX_* = OSSL_LIB_CTX_new()
  if (osslLibCtx == null) {
    val msg = ERR_error_string(ERR_get_error(), null)
    throw new RuntimeException(
      s"Failed to create OpenSSL library context: ${msg}"
    )
  }

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_OSSL_LIB_CTX(this, osslLibCtx)
  } else {
    System.err.println(
      "[java.security.Provider] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  private final val confLoaded: AtomicBoolean = new AtomicBoolean(false)
  private final val provLoaded: AtomicBoolean = new AtomicBoolean(false)

  def loadDefaultConfig(): Unit = {
    val defaultConfigFile = CONF_get1_default_config_file()

    if (Files.isReadable(Path.of(fromCString(defaultConfigFile)))) {
      if (!confLoaded.compareAndExchange(false, true)) {
        val ret =
          CONF_modules_load_file_ex(
            osslLibCtx,
            defaultConfigFile,
            null,
            0.toUByte
          )
        if (ret <= 0) {
          val msg = fromCString(ERR_error_string(ERR_get_error(), null))
          throw new RuntimeException(
            s"Failed to load OpenSSL configuration: ${msg}"
          )
        }
      }
    }
  }

  def loadLegacyAndDefaultProvider(): Unit =
    if (!provLoaded.compareAndExchange(false, true)) {
      // Load legacy provider to support old algorithms, e.g. DES, RC2, etc.
      // Required by legacy PKCS#12 files, more specifically, thoses tests with
      // BadSSL's certs in our own tests and upstream scala-requests' tests.
      val legacy = OSSL_PROVIDER_load(osslLibCtx, c"legacy")
      if (legacy == null)
        System.err.println(
          "[java.security.Provider] OpenSSL legacy provider is not available, Some algorithms may not work"
        )

      // load the default provider explicitly
      val default = OSSL_PROVIDER_load(osslLibCtx, c"default")
      if (default == null) {
        if (legacy != null)
          OSSL_PROVIDER_unload(legacy)
        throw new IllegalStateException(
          "[java.security.Provider] Failed to load OpenSSL default provider, no provider is available"
        )
      }
    }
}

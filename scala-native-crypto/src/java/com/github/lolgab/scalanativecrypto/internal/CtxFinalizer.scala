package java.com.github.lolgab.scalanativecrypto.internal

import java.lang.ref.{WeakReference, WeakReferenceRegistry}

final class CtxFinalizer[T](
    weakRef: WeakReference[_],
    private var ctx: T,
    finalizationFunction: T => Unit
) {
  WeakReferenceRegistry.addHandler(weakRef, apply)

  def apply(): Unit = {
    if (ctx != null) {
      finalizationFunction(ctx)
      ctx = null.asInstanceOf[T]
    }
  }
}

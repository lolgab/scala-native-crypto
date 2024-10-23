package java.lang.ref

private[java] object WeakReferenceRegistry {
  def addHandler(
      weakRef: WeakReference[_],
      handler: Function0[Unit]
  ): Unit = throw new NotImplementedError(
    "This is a shim. Real implementation resides in official javalib"
  )
}

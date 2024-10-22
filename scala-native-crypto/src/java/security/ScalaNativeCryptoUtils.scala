package java.security

import scala.scalanative.unsafe._
import scala.scalanative.runtime.Intrinsics._
import scala.scalanative.runtime._

import java.lang.ref.WeakReference

private[security] object ScalaNativeCryptoUtils {
  def setWeakReferenceHandler[T](
      wr: WeakReference[T],
      handler: () => Unit
  ): Unit = {
    val wrPtr = fromRawPtr[Byte](castObjectToRawPtr(wr))

    val handlerPtr = fromRawPtr[Byte](castObjectToRawPtr(handler))

    !((wrPtr + 24).asInstanceOf[Ptr[Ptr[Byte]]]) = handlerPtr
  }
}

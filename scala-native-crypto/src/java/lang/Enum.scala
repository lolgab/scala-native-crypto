// Ported from
// https://github.com/scala-native/scala-native/blob/main/javalib/src/main/scala/java/lang/Enum.scala
package java.lang

import java.io.Serializable

abstract class _Enum[E <: _Enum[E]] protected (_name: String, _ordinal: Int)
    extends Comparable[E]
    with Serializable {
  def name(): String = _name

  def ordinal(): Int = _ordinal

  override def toString(): String = _name

  final def compareTo(o: E): Int = _ordinal.compareTo(o.ordinal())
}

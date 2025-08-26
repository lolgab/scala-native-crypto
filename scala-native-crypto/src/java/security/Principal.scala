package java.security

import javax.security.auth.Subject

trait Principal {
  def equals(another: Any): Boolean

  def toString: String

  def hashCode(): Int

  def getName(): String

  def implies(subject: Subject): Boolean = {
    if (subject == null) false
    else subject.getPrincipals().contains(this)
  }
}

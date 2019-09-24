package org.folio.auth.authtokenmodule;

public class CacheEntry<E> {

  private final Long createTime;
  private final E entry;

  public CacheEntry(E entry) {
    this.entry = entry;
    this.createTime = System.currentTimeMillis();
  }

  public E getEntry() {
    return entry;
  }

  public Long getAge() {
    return System.currentTimeMillis() - createTime;
  }

}

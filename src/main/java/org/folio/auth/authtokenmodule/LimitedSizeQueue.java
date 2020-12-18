package org.folio.auth.authtokenmodule;

import java.util.LinkedHashMap;
import java.util.Map;

public class LimitedSizeQueue<K>
    extends LinkedHashMap<K, Boolean> {
  private final int maxSize;

  public LimitedSizeQueue(int size) {
    maxSize = size;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) {
      return false;
    }
    LimitedSizeQueue<K> fobj = (LimitedSizeQueue<K>) obj;
    return fobj.maxSize == maxSize;
  }

  @Override
  public int hashCode() {
    return super.hashCode() + 31 * maxSize;
  }

  @Override
  protected boolean removeEldestEntry(Map.Entry<K, Boolean> eldest) {
    return size() > maxSize;
  }

  /**
   * Adds key if not already in queue. If key exists, its queue position doesn't change.
   * @param k key
   */
  public void add(K k) {
    super.put(k, Boolean.TRUE);
  }

  public boolean contains(K k) {
    return super.containsKey(k);
  }

}

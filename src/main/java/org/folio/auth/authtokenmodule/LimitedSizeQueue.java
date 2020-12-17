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
  protected boolean removeEldestEntry(Map.Entry<K, Boolean> eldest) {
    return size() > maxSize;
  }

  public void add(K k) {
    super.put(k, Boolean.TRUE);
  }

  public boolean contains(K k) {
    return super.containsKey(k);
  }

}

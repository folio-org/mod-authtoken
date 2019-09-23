package org.folio.auth.authtokenmodule;

import java.util.LinkedHashMap;
import java.util.Map;


/**
 *
 * @author kurt
 */
public class LimitedSizeMap<K,V> extends LinkedHashMap<K, V> {
  private final int maxSize;
  public LimitedSizeMap(int maxSize) {
    this.maxSize = maxSize;
  }

  @Override
  protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
    return size() > maxSize;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) {
      return false;
    }
    LimitedSizeMap fobj = (LimitedSizeMap) obj;
    return fobj.maxSize == maxSize;
  }
}

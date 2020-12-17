package org.folio.auth.authtokenmodule;

import java.util.ArrayList;

public class LimitedSizeQueue<K> extends ArrayList<K> {

  private final int maxSize;

  public LimitedSizeQueue(int size){
    this.maxSize = size;
  }

  @Override
  public boolean add(K k){
    boolean r = super.add(k);
    if (size() > maxSize) {
      removeRange(0, size() - maxSize);
    }
    return r;
  }
}

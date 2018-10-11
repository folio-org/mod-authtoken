/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.folio.auth.authtokenmodule;

import java.util.LinkedHashMap;
import java.util.Map;


/**
 *
 * @author kurt
 */
public class LimitedSizeMap<K,V> extends LinkedHashMap<K, V> {
  final private int maxSize;
  public LimitedSizeMap(int maxSize) {
    this.maxSize = maxSize;
  }
  
  @Override
  protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
    return size() > maxSize;
  }
  
}
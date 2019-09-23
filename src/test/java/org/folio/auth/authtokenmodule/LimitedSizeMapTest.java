package org.folio.auth.authtokenmodule;

import org.junit.Assert;
import org.junit.Test;

public class LimitedSizeMapTest {

  @Test
  public void test1() {
    LimitedSizeMap<String, String> map2 = new LimitedSizeMap<>(2);
    LimitedSizeMap<String, String> map2a = new LimitedSizeMap<>(2);
    LimitedSizeMap<String, String> map1 = new LimitedSizeMap<>(1);

    Assert.assertTrue(map2.equals(map2));
    Assert.assertTrue(map2.equals(map2a));
    Assert.assertEquals(map2.hashCode(), map2a.hashCode());
    Assert.assertFalse(map2.equals(map1));

    map2.put("k1", "v1");
    Assert.assertNotNull(map2.get("k1"));
    map2.put("k2", "v2");
    Assert.assertNotNull(map2.get("k1"));
    map2.put("k3", "v3");
    Assert.assertNull(map2.get("k1"));
  }
}

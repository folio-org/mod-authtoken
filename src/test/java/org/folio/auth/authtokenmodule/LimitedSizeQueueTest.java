package org.folio.auth.authtokenmodule;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.Assert;
import org.junit.Test;

public class LimitedSizeQueueTest {
  @Test
  public void testQueueSize1() {
    LimitedSizeQueue<Integer> q = new LimitedSizeQueue<>(1);
    Assert.assertTrue(q.isEmpty());
    q.add(1);
    Assert.assertEquals(1, q.size());
    Assert.assertTrue(q.contains(1));
    q.add(2);
    Assert.assertEquals(1, q.size());
    Assert.assertFalse(q.contains(1));
    Assert.assertTrue(q.contains(2));
    q.add(3);
    Assert.assertEquals(1, q.size());
    Assert.assertFalse(q.contains(2));
    Assert.assertTrue(q.contains(3));
  }

  @Test
  public void testQueueSize2() {
    LimitedSizeQueue<Integer> q = new LimitedSizeQueue<>(2);
    Assert.assertTrue(q.isEmpty());
    q.add(1);
    Assert.assertEquals(1, q.size());
    Assert.assertTrue(q.contains(1));
    q.add(2);
    Assert.assertEquals(2, q.size());
    Assert.assertTrue(q.contains(1));
    Assert.assertTrue(q.contains(2));
    // observe that putting 1 here does NOT put it in front of queuee
    q.add(1);
    q.add(3);
    Assert.assertEquals(2, q.size());
    Assert.assertTrue(q.contains(2));
    Assert.assertTrue(q.contains(3));
  }

  @Test
  public void testQueueSize100() {
    final int count = 1000000;
    final int sz = 100;
    final String prefix = UUID.randomUUID().toString() + UUID.randomUUID().toString();
    LimitedSizeQueue<String> q = new LimitedSizeQueue<>(sz);
    Assert.assertTrue(q.isEmpty());
    long start = System.nanoTime();
    for (int i = 0; i < count; i++) {
      q.add(prefix + i);
    }
    for (int i = 0; i < count; i++) {
      if (i < count - sz) {
        Assert.assertFalse(q.contains(prefix + i));
      } else {
        Assert.assertTrue(q.contains(prefix + i));
      }
    }
    long end = System.nanoTime();
    System.out.printf("time = " + (end - start) / 1000000 + " ms");
  }

  @Test
  public void testQueueCompare() {
    LimitedSizeQueue<String> a1 = new LimitedSizeQueue<>(1);
    LimitedSizeQueue<String> a2 = new LimitedSizeQueue<>(2);

    Assert.assertNotEquals(a1, a2);
    Assert.assertEquals(a1.hashCode(), a2.hashCode());

    LimitedSizeQueue<String> b1 = new LimitedSizeQueue<>(1);
    Assert.assertEquals(a1, b1);

    LimitedSizeQueue<Integer> i1 = new LimitedSizeQueue<>(1);
    Assert.assertEquals(a1, i1);
    Assert.assertEquals(i1, a1);

    a1.add("1");
    Assert.assertNotEquals(a1, a2);
  }
}

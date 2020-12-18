package org.folio.auth.authtokenmodule;

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
  public void testQueueCompare() {
    LimitedSizeQueue<String> a1 = new LimitedSizeQueue<>(1);
    LimitedSizeQueue<String> a2 = new LimitedSizeQueue<>(2);

    Assert.assertNotEquals(a1, a2);
    Assert.assertNotEquals(a1.hashCode(), a2.hashCode());

    LimitedSizeQueue<String> b1 = new LimitedSizeQueue<>(1);
    Assert.assertEquals(a1, b1);
    Assert.assertEquals(a1.hashCode(), b1.hashCode());

    LimitedSizeQueue<Integer> i1 = new LimitedSizeQueue<>(1);
    Assert.assertEquals(a1, i1);
    Assert.assertEquals(i1, a1);

    a1.add("1");
    Assert.assertNotEquals(a1, a2);
  }
}

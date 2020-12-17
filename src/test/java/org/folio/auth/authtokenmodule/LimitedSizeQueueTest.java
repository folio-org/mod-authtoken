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
    q.add(3);
    Assert.assertEquals(2, q.size());
    Assert.assertTrue(q.contains(2));
    Assert.assertTrue(q.contains(3));
  }

}

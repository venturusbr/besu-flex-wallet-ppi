package br.org.venturus.flexwallet.batch;

import java.util.concurrent.TimeUnit;

/**
 * Single-threaded leaky-bucket throttle used to pace submissions to the worker pool.
 *
 * <p>Each call to {@link #acquire()} blocks until the configured inter-arrival interval has
 * elapsed since the previous permit was issued. The first call returns immediately; subsequent
 * calls sleep as needed. Drift protection ({@code Math.max(now, nextPermitNanos)}) prevents a
 * slow caller from "banking" permits and bursting later.
 *
 * <p>Not thread-safe by design — only the submission loop on the main thread calls it. Workers
 * inside the pool do their work uncontended.
 */
public final class RateLimiter {
  private final long intervalNanos;
  private long nextPermitNanos;

  public RateLimiter(double permitsPerSecond) {
    if (!(permitsPerSecond > 0)) {
      throw new IllegalArgumentException("rate must be positive");
    }
    this.intervalNanos = Math.max(1L, Math.round(1_000_000_000.0 / permitsPerSecond));
    this.nextPermitNanos = System.nanoTime();
  }

  public void acquire() {
    long now = System.nanoTime();
    long waitNanos = nextPermitNanos - now;
    if (waitNanos > 0) {
      try {
        TimeUnit.NANOSECONDS.sleep(waitNanos);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
    }
    nextPermitNanos = Math.max(System.nanoTime(), nextPermitNanos) + intervalNanos;
  }
}

package br.org.venturus.flexwallet.batch;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Prints a live, single-line status during batch runs. The line is rewritten in place every
 * {@link #UPDATE_INTERVAL_MS} ms using carriage return, so the terminal shows one continuously
 * updating row rather than a flood of output. On {@link #close()} the final state is emitted
 * and a newline is appended so anything printed afterwards (e.g. the batch summary) starts on
 * a fresh line.
 *
 * <p>Sample output:
 *
 * <pre>
 *   [ 45.2%] 4523/10000  ok=4500 fail=23  rate=85.3 tx/s  elapsed=00:00:53  eta=00:01:04
 * </pre>
 *
 * <p>Workers update the {@link AtomicInteger} counters as transactions complete; this class
 * only reads them, so no locks and no contention on the worker side.
 */
public final class ProgressReporter implements AutoCloseable {
  private static final long UPDATE_INTERVAL_MS = 500L;

  private final int total;
  private final AtomicInteger completed;
  private final AtomicInteger succeeded;
  private final AtomicInteger failed;
  private final long startNanos;
  private final ScheduledExecutorService scheduler;

  public ProgressReporter(
      int total, AtomicInteger completed, AtomicInteger succeeded, AtomicInteger failed) {
    this.total = total;
    this.completed = completed;
    this.succeeded = succeeded;
    this.failed = failed;
    this.startNanos = System.nanoTime();
    this.scheduler =
        Executors.newSingleThreadScheduledExecutor(
            r -> {
              Thread t = new Thread(r, "ProgressReporter");
              t.setDaemon(true);
              return t;
            });
    scheduler.scheduleAtFixedRate(
        this::tick, UPDATE_INTERVAL_MS, UPDATE_INTERVAL_MS, TimeUnit.MILLISECONDS);
  }

  private synchronized void tick() {
    int done = completed.get();
    int ok = succeeded.get();
    int fail = failed.get();
    long elapsedNanos = System.nanoTime() - startNanos;
    double elapsedSec = elapsedNanos / 1_000_000_000.0;
    double rate = elapsedSec > 0 ? done / elapsedSec : 0.0;
    double pct = total > 0 ? (done * 100.0) / total : 0.0;
    long etaSec = (done > 0 && total > done && rate > 0) ? (long) ((total - done) / rate) : 0L;

    // Trailing spaces clear residue left over from a longer previous line. \r returns the
    // cursor to column 0 so the next tick overwrites this one in place.
    String line =
        String.format(
            "\r[%5.1f%%] %d/%d  ok=%d fail=%d  rate=%.1f tx/s  elapsed=%s  eta=%s     ",
            pct,
            done,
            total,
            ok,
            fail,
            rate,
            formatDuration((long) elapsedSec),
            formatDuration(etaSec));
    System.out.print(line);
    System.out.flush();
  }

  @Override
  public void close() {
    scheduler.shutdown();
    try {
      scheduler.awaitTermination(1, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    // Print one last update so the final state is visible, then drop to a fresh line for the
    // summary that follows.
    tick();
    System.out.println();
  }

  private static String formatDuration(long seconds) {
    long h = seconds / 3600;
    long m = (seconds / 60) % 60;
    long s = seconds % 60;
    return String.format("%02d:%02d:%02d", h, m, s);
  }
}

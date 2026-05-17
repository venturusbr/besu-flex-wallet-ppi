package br.org.venturus.flexwallet.batch;

import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.web3j.utils.Convert;

import br.org.venturus.flexwallet.cli.CliArgs;
import br.org.venturus.flexwallet.model.Transaction;
import br.org.venturus.flexwallet.model.encoder.EIP1559Encoder;
import br.org.venturus.flexwallet.model.encoder.FlexibleEIP1559Encoder;
import br.org.venturus.flexwallet.model.encoder.TransactionEncoder;
import br.org.venturus.flexwallet.request.EthSendRawTransaction;

/**
 * Orchestrates the parallel batch send: builds, signs, and POSTs {@code txAmount} transactions
 * across the configured endpoints round-robin by nonce, throttled by a {@link RateLimiter} if
 * one was configured, with a live {@link ProgressReporter} showing per-tick stats. Writes a CSV
 * of every outcome at the end and prints a console summary.
 */
public final class BatchRunner {

  /**
   * Worker threads used to send transactions concurrently. Distributing across N endpoints means
   * each route sees roughly DEFAULT_CONCURRENCY / N concurrent connections, comfortably below
   * the per-route pool limit configured in {@code EthSendRawTransaction}.
   */
  private static final int DEFAULT_CONCURRENCY = 16;

  /** Hard upper bound on time spent waiting for the worker pool to drain. */
  private static final long POOL_SHUTDOWN_TIMEOUT_SECONDS = 120L;

  private final CliArgs cli;
  private final byte[] pubBytes;
  private final PrivateKey sk;
  private final TransactionEncoder encoder;

  // Counters updated by workers, read by the ProgressReporter.
  private final AtomicInteger completed = new AtomicInteger();
  private final AtomicInteger succeeded = new AtomicInteger();
  private final AtomicInteger failed = new AtomicInteger();

  public BatchRunner(CliArgs cli, byte[] pubBytes, PrivateKey sk, TransactionEncoder encoder) {
    this.cli = cli;
    this.pubBytes = pubBytes;
    this.sk = sk;
    this.encoder = encoder;
  }

  /** Run the configured batch end-to-end: submit, drain, write CSV, print summary. */
  public void run() throws Exception {
    int txAmount = cli.txAmount();
    String[] endpoints = cli.batchEndpoints();

    int threads = Math.min(txAmount, DEFAULT_CONCURRENCY);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    List<Future<TxResult>> futures = new ArrayList<>(txAmount);
    List<TxResult> results = new ArrayList<>(txAmount);

    RateLimiter rateLimiter = cli.maxRate() != null ? new RateLimiter(cli.maxRate()) : null;

    // Track wall-clock duration of the whole batch so the final summary can report a real
    // elapsed time and average rate, not just the per-task elapsedMs values in the CSV.
    long startNanos = System.nanoTime();

    try (ProgressReporter reporter =
        new ProgressReporter(txAmount, completed, succeeded, failed)) {
      try {
        for (int i = 0; i < txAmount; i++) {
          if (rateLimiter != null) {
            rateLimiter.acquire();
          }
          final BigInteger nonce = BigInteger.valueOf(i);
          final String endpoint = endpoints[i % endpoints.length];
          futures.add(pool.submit(() -> sendOne(nonce, endpoint)));
        }

        // Drain in submission (= nonce) order.
        for (Future<TxResult> future : futures) {
          try {
            results.add(future.get());
          } catch (ExecutionException ee) {
            Throwable cause = ee.getCause() != null ? ee.getCause() : ee;
            results.add(
                TxResult.failure(
                    BigInteger.valueOf(-1),
                    "<unknown>",
                    "task crashed: "
                        + cause.getClass().getSimpleName()
                        + (cause.getMessage() == null ? "" : ": " + cause.getMessage()),
                    0L,
                    Instant.now()));
            failed.incrementAndGet();
            completed.incrementAndGet();
          } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            results.add(
                TxResult.failure(
                    BigInteger.valueOf(-1),
                    "<unknown>",
                    "interrupted while waiting",
                    0L,
                    Instant.now()));
            failed.incrementAndGet();
            completed.incrementAndGet();
            break;
          }
        }
      } finally {
        pool.shutdown();
        try {
          if (!pool.awaitTermination(POOL_SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            pool.shutdownNow();
          }
        } catch (InterruptedException ie) {
          pool.shutdownNow();
          Thread.currentThread().interrupt();
        }
      }
    }

    long elapsedNanos = System.nanoTime() - startNanos;

    Path csvPath = cli.outputPath() != null ? Paths.get(cli.outputPath()) : CsvWriter.defaultPath();
    CsvWriter.write(csvPath, results);

    printSummary(results, csvPath, elapsedNanos);
  }

  // -----------------------------------------------------------------------------------------
  // Worker
  // -----------------------------------------------------------------------------------------

  private TxResult sendOne(BigInteger nonce, String endpoint) {
    Instant timestamp = Instant.now();
    long startNs = System.nanoTime();
    TxResult result;
    try {
      Transaction unsigned = buildTransaction(nonce);
      byte[] raw = encoder.createRawTransaction(unsigned, sk);
      String tx = "0x" + bytesToHex(raw);

      String response = EthSendRawTransaction.send(tx, endpoint, false);
      long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;

      if (JsonRpcResponses.isError(response)) {
        result =
            TxResult.failure(
                nonce, endpoint, JsonRpcResponses.extractErrorMessage(response), elapsedMs, timestamp);
      } else {
        result =
            TxResult.success(
                nonce, endpoint, JsonRpcResponses.extractResult(response), elapsedMs, timestamp);
      }
    } catch (Exception e) {
      long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;
      result =
          TxResult.failure(
              nonce,
              endpoint,
              e.getClass().getSimpleName()
                  + (e.getMessage() == null ? "" : ": " + e.getMessage()),
              elapsedMs,
              timestamp);
    }

    // Update live counters before returning so ProgressReporter sees progress.
    if (result.success()) {
      succeeded.incrementAndGet();
    } else {
      failed.incrementAndGet();
    }
    completed.incrementAndGet();
    return result;
  }

 private Transaction buildTransaction(BigInteger nonce) {
    boolean isLegacy = encoder instanceof EIP1559Encoder;
 
    Transaction.Builder builder = new Transaction.Builder()
        .chainId(381660666L)
        .nonce(nonce)
        .to("0xf17f52151EbEF6C7334FAD080c5704D77216b732")
        .value(Convert.toWei("0", Convert.Unit.ETHER).toBigInteger())
        .data("")
        .gasLimit(BigInteger.valueOf(1_000_000))
        .maxPriorityFeePerGas(BigInteger.ZERO)
        .maxFeePerGas(BigInteger.ZERO);
 
    if (!isLegacy) {
      // Flexible/PQC transactions carry dsaType and publicKey
      builder.dsaType((short) 0x0060).publicKey(pubBytes);
    }
 
    return builder.build();
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) sb.append(String.format("%02x", b));
    return sb.toString();
  }

  // -----------------------------------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------------------------------

  private void printSummary(List<TxResult> results, Path csvPath, long elapsedNanos) {
    int successCount = 0;
    int failureCount = 0;
    Map<String, Integer> failureCountsByMessage = new LinkedHashMap<>();
    Map<String, int[]> perEndpoint = new TreeMap<>(); // value: [success, failure]
    for (TxResult r : results) {
      int[] bucket = perEndpoint.computeIfAbsent(r.endpoint(), k -> new int[2]);
      if (r.success()) {
        successCount++;
        bucket[0]++;
      } else {
        failureCount++;
        bucket[1]++;
        failureCountsByMessage.merge(
            r.errorMessage() == null ? "<unknown>" : r.errorMessage(), 1, Integer::sum);
      }
    }

    double elapsedSec = elapsedNanos / 1_000_000_000.0;
    double rate = elapsedSec > 0 ? results.size() / elapsedSec : 0.0;

    System.out.println();
    System.out.println("================ Transaction Batch Summary ================");
    System.out.println("Total:     " + results.size());
    System.out.println("Succeeded: " + successCount);
    System.out.println("Failed:    " + failureCount);
    System.out.println("Elapsed:   " + formatDuration((long) elapsedSec));
    System.out.println("Rate:      " + String.format("%.2f tx/s", rate));
    System.out.println("Per-endpoint:");
    for (Map.Entry<String, int[]> e : perEndpoint.entrySet()) {
      int ok = e.getValue()[0];
      int fail = e.getValue()[1];
      System.out.println(
          "  - " + e.getKey() + "  ok=" + ok + "  fail=" + fail + "  total=" + (ok + fail));
    }
    if (!failureCountsByMessage.isEmpty()) {
      System.out.println("Failure breakdown:");
      for (Map.Entry<String, Integer> e : failureCountsByMessage.entrySet()) {
        System.out.println("  - " + e.getValue() + "x  " + e.getKey());
      }
    }
    System.out.println("CSV:       " + csvPath.toAbsolutePath());
    System.out.println("===========================================================");
  }

  /** Format seconds as HH:MM:SS — matches {@link ProgressReporter}'s in-flight format. */
  private static String formatDuration(long seconds) {
    long h = seconds / 3600;
    long m = (seconds / 60) % 60;
    long s = seconds % 60;
    return String.format("%02d:%02d:%02d", h, m, s);
  }
}

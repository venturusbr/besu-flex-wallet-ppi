package br.org.venturus.flexwallet;

import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Security;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.web3j.utils.Convert;

import br.org.venturus.flexwallet.crypto.DigitalSignatureAlgorithm;
import br.org.venturus.flexwallet.crypto.NestedHybridDSA;
import br.org.venturus.flexwallet.crypto.Secp256k1;
import br.org.venturus.flexwallet.crypto.key.types.GenericPrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;
import br.org.venturus.flexwallet.crypto.MLDSA;
import br.org.venturus.flexwallet.model.Transaction;
import br.org.venturus.flexwallet.model.encoder.EIP1559Encoder;
import br.org.venturus.flexwallet.request.EthSendRawTransaction;
import br.org.venturus.flexwallet.utils.FileUtils;
import br.org.venturus.flexwallet.crypto.key.types.CompositePrivateKey;

public class App {

  /**
   * Worker threads used to send transactions concurrently in --txAmount batch mode.
   *
   * <p>Bumping this raises throughput up to the point where Besu's mempool / RPC handler becomes
   * the bottleneck; 16 is a safe default that keeps `localhost:8545` busy without flooding it.
   */
  private static final int DEFAULT_CONCURRENCY = 16;

  /** Hard upper bound on time spent waiting for the worker pool to drain. */
  private static final long POOL_SHUTDOWN_TIMEOUT_SECONDS = 120L;

  /** CSV header for batch-mode result file. */
  private static final String CSV_HEADER = "nonce,status,txHash,errorMessage,elapsedMs,timestamp";

  public static void main(String[] args) {
    try {
      // Register the PQC provider if it is not already registered
      if (Security.getProvider("BCPQC") == null) {
        Security.addProvider(new BouncyCastlePQCProvider());
      }

      boolean shouldGenerateKeys = false;

      // Checks if the --generateKeys flag is present
      for (String arg : args) {
        if (arg.equalsIgnoreCase("--generateKeys")) {
          shouldGenerateKeys = true;
          break;
        }
      }

      // Parse --txAmount (null when the flag is not provided -> original single-tx behavior).
      Integer txAmountArg = parseTxAmount(args);
      boolean batchMode = txAmountArg != null;
      int txAmount = batchMode ? txAmountArg : 1;
      if (batchMode && txAmount < 1) {
        throw new IllegalArgumentException("--txAmount must be >= 1, got " + txAmount);
      }

      // Optional --output PATH for the batch CSV; defaults to tx_results_<ts>.csv in cwd.
      String outputPath = parseOutputPath(args);

      // Only write the keys once, if the file doesn't already exist
      FileUtils fileUtils = new FileUtils();
      Path keyFile = fileUtils.getFilePath();
      DigitalSignatureAlgorithm signatureAlgorithm = new NestedHybridDSA(new Secp256k1(), new MLDSA());
      // DigitalSignatureAlgorithm signatureAlgorithm = new Secp256k1();
      // DigitalSignatureAlgorithm signatureAlgorithm = new Falcon();
      // DigitalSignatureAlgorithm signatureAlgorithm = new MLDSA();

      // Generates the key only if the flag is present or the file does not exist
      if (shouldGenerateKeys || !Files.exists(keyFile)) {
        NodeKeyPair keyPair = signatureAlgorithm.generateKeyPair();
        fileUtils.writeKeys(keyPair);
        System.out.println("Generated new keys. File Path: " + keyFile);
      }

      // Read the keys back from the file (PEM → Base64)
      String[] keys = fileUtils.readKeys();
      byte[] pubBytes = Base64.getDecoder().decode(keys[0]);
      byte[] privBytes = Base64.getDecoder().decode(keys[1]);
      PrivateKey sk;

      if (signatureAlgorithm instanceof NestedHybridDSA) {
        if (keys.length != 4) {
          throw new UnsupportedOperationException(
              "When using a nested hybrid digital signature algorithm, 2 key pairs are expected.");
        }

        byte[] secondPubBytes = Base64.getDecoder().decode(keys[2]);
        byte[] secondPrivBytes = Base64.getDecoder().decode(keys[3]);

        // In case SECP256K1/MLDSA: the first algorithm supports PKR and the second doesn't.
        // Send the Public Key of the second one.
        pubBytes = secondPubBytes;

        sk = CompositePrivateKey.create(
            new GenericPrivateKey(Bytes.wrap(privBytes)),
            new GenericPrivateKey(Bytes.wrap(secondPrivBytes)));
      } else {
        sk = new GenericPrivateKey(Bytes.wrap(privBytes));
      }

      // Suppress key-length / signature-length debug prints in batch mode.
      if (!batchMode) {
        System.out.println("~~~~~~~~~~~~~~~~~~ Public key length ~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        System.out.println(pubBytes.length);
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

        System.out.println("~~~~~~~~~~~~~~~~~~ Secret key length ~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        System.out.println(sk.getEncoded().length);
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
      }

      // The encoder's signature-length printlns are also disabled in batch mode via the verbose
      // flag in EIP1559Encoder.
      EIP1559Encoder encoder = new EIP1559Encoder(signatureAlgorithm, !batchMode);

      if (!batchMode) {
        // Original single-transaction path: nonce = 0, no thread pool, no CSV, no summary.
        Transaction unsignedTransaction = buildTransaction(BigInteger.ZERO, pubBytes);
        byte[] rawTransaction = encoder.createRawTransaction(unsignedTransaction, sk);
        String tx = "0x" + EIP1559Encoder.bytesToHex(rawTransaction);
        EthSendRawTransaction.send(tx); // verbose=true by default — prints "Result: ..."
        return;
      }

      // ------------------------- Parallel batch send ----------------------------
      // Each task builds its own transaction, signs it, POSTs to localhost:8545, and returns a
      // TxResult. EthSendRawTransaction.send is invoked with verbose=false so the per-call
      // "Result: ..." line is suppressed — every outcome is captured in the CSV instead.
      int threads = Math.min(txAmount, DEFAULT_CONCURRENCY);
      ExecutorService pool = Executors.newFixedThreadPool(threads);
      List<Future<TxResult>> futures = new ArrayList<>(txAmount);

      // Effectively-final captures for the lambda.
      final byte[] pubBytesCapt = pubBytes;
      final PrivateKey skCapt = sk;
      final EIP1559Encoder encoderCapt = encoder;

      List<TxResult> results = new ArrayList<>(txAmount);

      try {
        for (int i = 0; i < txAmount; i++) {
          final BigInteger nonce = BigInteger.valueOf(i);
          futures.add(pool.submit(() -> sendOne(nonce, pubBytesCapt, skCapt, encoderCapt)));
        }

        // Drain results in submission (= nonce) order. Each future.get() blocks until that task
        // completes, but other tasks continue running in parallel, so total wall-clock time is
        // bounded by the slowest task, not the sum.
        for (Future<TxResult> future : futures) {
          try {
            results.add(future.get());
          } catch (ExecutionException ee) {
            // The Callable shouldn't throw — it catches everything internally — but stay defensive.
            Throwable cause = ee.getCause() != null ? ee.getCause() : ee;
            results.add(
                TxResult.failure(
                    BigInteger.valueOf(-1),
                    null,
                    "task crashed: "
                        + cause.getClass().getSimpleName()
                        + (cause.getMessage() == null ? "" : ": " + cause.getMessage()),
                    0L,
                    Instant.now()));
          } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            results.add(
                TxResult.failure(
                    BigInteger.valueOf(-1), null, "interrupted while waiting", 0L, Instant.now()));
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

      // ------------------------- Summary + CSV ---------------------------------
      Path csvPath = outputPath != null ? Paths.get(outputPath) : defaultCsvPath();
      writeCsv(csvPath, results);

      int successCount = 0;
      int failureCount = 0;
      // LinkedHashMap so we preserve first-seen order when grouping failures by message.
      Map<String, Integer> failureCountsByMessage = new LinkedHashMap<>();
      for (TxResult r : results) {
        if (r.success) {
          successCount++;
        } else {
          failureCount++;
          failureCountsByMessage.merge(
              r.errorMessage == null ? "<unknown>" : r.errorMessage, 1, Integer::sum);
        }
      }

      System.out.println();
      System.out.println("================ Transaction Batch Summary ================");
      System.out.println("Total:     " + txAmount);
      System.out.println("Succeeded: " + successCount);
      System.out.println("Failed:    " + failureCount);
      if (!failureCountsByMessage.isEmpty()) {
        System.out.println("Failure breakdown:");
        for (Map.Entry<String, Integer> e : failureCountsByMessage.entrySet()) {
          System.out.println("  - " + e.getValue() + "x  " + e.getKey());
        }
      }
      System.out.println("CSV:       " + csvPath.toAbsolutePath());
      System.out.println("===========================================================");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /** Build a fresh unsigned EIP-1559 transaction for the given nonce. */
  private static Transaction buildTransaction(BigInteger nonce, byte[] pubBytes) {
    return new Transaction.Builder()
        .dsaType((short) 0x0060)
        .chainId(381660666L)
        .nonce(nonce)
        .to("0xf17f52151EbEF6C7334FAD080c5704D77216b732")
        .value(Convert.toWei("0", Convert.Unit.ETHER).toBigInteger())
        .data("")
        .gasLimit(BigInteger.valueOf(1_000_000))
        .maxPriorityFeePerGas(BigInteger.ZERO)
        .maxFeePerGas(BigInteger.ZERO)
        .publicKey(pubBytes)
        .build();
  }

  /**
   * Build, sign, and POST a single transaction. Always returns a {@link TxResult} — the worker
   * never throws, so a single bad request can't take down the whole batch.
   */
  private static TxResult sendOne(
      BigInteger nonce, byte[] pubBytes, PrivateKey sk, EIP1559Encoder encoder) {
    Instant timestamp = Instant.now();
    long startNs = System.nanoTime();
    try {
      Transaction unsignedTransaction = buildTransaction(nonce, pubBytes);
      byte[] rawTransaction = encoder.createRawTransaction(unsignedTransaction, sk);
      String tx = "0x" + EIP1559Encoder.bytesToHex(rawTransaction);

      // verbose=false: don't print "Result: ..." — the caller (App.main) captures the response
      // in the CSV instead.
      String response = EthSendRawTransaction.send(tx, false);
      long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;

      if (isJsonRpcError(response)) {
        return TxResult.failure(
            nonce, null, extractJsonRpcErrorMessage(response), elapsedMs, timestamp);
      }
      return TxResult.success(nonce, extractJsonRpcResult(response), elapsedMs, timestamp);
    } catch (Exception e) {
      long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;
      return TxResult.failure(
          nonce,
          null,
          e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()),
          elapsedMs,
          timestamp);
    }
  }

  // -----------------------------------------------------------------------------------------
  // CLI parsing
  // -----------------------------------------------------------------------------------------

  /**
   * Look for {@code --txAmount N} or {@code --txAmount=N} on the command line.
   *
   * @return the integer N, or {@code null} if the flag is not present (preserves original
   *     single-transaction behavior).
   */
  private static Integer parseTxAmount(String[] args) {
    for (int i = 0; i < args.length; i++) {
      String a = args[i];
      String lower = a.toLowerCase();

      if (lower.equals("--txamount")) {
        if (i + 1 >= args.length) {
          throw new IllegalArgumentException("--txAmount requires an integer value");
        }
        return parseIntOrThrow(args[i + 1]);
      }

      if (lower.startsWith("--txamount=")) {
        return parseIntOrThrow(a.substring("--txamount=".length()));
      }
    }
    return null;
  }

  /**
   * Optional {@code --output PATH} or {@code --output=PATH}. When absent we fall back to
   * {@code tx_results_<timestamp>.csv} in the current working directory.
   */
  private static String parseOutputPath(String[] args) {
    for (int i = 0; i < args.length; i++) {
      String a = args[i];
      String lower = a.toLowerCase();

      if (lower.equals("--output")) {
        if (i + 1 >= args.length) {
          throw new IllegalArgumentException("--output requires a path");
        }
        return args[i + 1];
      }

      if (lower.startsWith("--output=")) {
        return a.substring("--output=".length());
      }
    }
    return null;
  }

  private static int parseIntOrThrow(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("--txAmount value must be an integer; got: " + value);
    }
  }

  // -----------------------------------------------------------------------------------------
  // JSON-RPC response helpers (deliberately string-walking to avoid pulling in Jackson/Gson)
  // -----------------------------------------------------------------------------------------

  /** Look for an {@code "error"} field in the body — its presence indicates a JSON-RPC error. */
  private static boolean isJsonRpcError(String response) {
    return response != null && response.contains("\"error\"");
  }

  /**
   * Best-effort extraction of {@code error.message} from a JSON-RPC response. Falls back to the
   * whole response when the structure is unexpected.
   */
  private static String extractJsonRpcErrorMessage(String response) {
    return extractStringField(response, "error", "message");
  }

  /**
   * Pull the {@code "result":"..."} value out of a successful JSON-RPC response — for {@code
   * eth_sendRawTransaction} this is the transaction hash. Returns {@code null} when missing.
   */
  private static String extractJsonRpcResult(String response) {
    if (response == null) {
      return null;
    }
    int idx = response.indexOf("\"result\"");
    if (idx < 0) {
      return null;
    }
    int colon = response.indexOf(':', idx);
    if (colon < 0) {
      return null;
    }
    int firstQuote = response.indexOf('"', colon + 1);
    if (firstQuote < 0) {
      return null;
    }
    int secondQuote = response.indexOf('"', firstQuote + 1);
    if (secondQuote < 0) {
      return null;
    }
    return response.substring(firstQuote + 1, secondQuote);
  }

  /**
   * Find {@code outerKey} in {@code response}, then within that scope find the string value of
   * {@code innerKey}. If anything is missing, returns the substring from the outer key onward as a
   * diagnostic fallback.
   */
  private static String extractStringField(String response, String outerKey, String innerKey) {
    if (response == null) {
      return "<no response>";
    }
    int outerIdx = response.indexOf("\"" + outerKey + "\"");
    if (outerIdx < 0) {
      return response;
    }
    int innerIdx = response.indexOf("\"" + innerKey + "\"", outerIdx);
    if (innerIdx < 0) {
      return response.substring(outerIdx);
    }
    int colon = response.indexOf(':', innerIdx);
    if (colon < 0) {
      return response.substring(outerIdx);
    }
    int firstQuote = response.indexOf('"', colon + 1);
    if (firstQuote < 0) {
      return response.substring(outerIdx);
    }
    int secondQuote = response.indexOf('"', firstQuote + 1);
    if (secondQuote < 0) {
      return response.substring(outerIdx);
    }
    return response.substring(firstQuote + 1, secondQuote);
  }

  // -----------------------------------------------------------------------------------------
  // CSV output
  // -----------------------------------------------------------------------------------------

  private static Path defaultCsvPath() {
    String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
    return Paths.get("tx_results_" + stamp + ".csv");
  }

  private static void writeCsv(Path path, List<TxResult> results) throws IOException {
    if (path.getParent() != null) {
      Files.createDirectories(path.getParent());
    }
    try (BufferedWriter w = Files.newBufferedWriter(path)) {
      w.write(CSV_HEADER);
      w.newLine();
      for (TxResult r : results) {
        w.write(r.nonce.toString());
        w.write(',');
        w.write(r.success ? "success" : "failure");
        w.write(',');
        w.write(csvEscape(r.txHash));
        w.write(',');
        w.write(csvEscape(r.errorMessage));
        w.write(',');
        w.write(Long.toString(r.elapsedMs));
        w.write(',');
        w.write(r.timestamp.toString());
        w.newLine();
      }
    }
  }

  /** Quote and escape a CSV field per RFC 4180 when it contains special characters. */
  private static String csvEscape(String value) {
    if (value == null) {
      return "";
    }
    boolean needsQuoting =
        value.indexOf(',') >= 0
            || value.indexOf('"') >= 0
            || value.indexOf('\n') >= 0
            || value.indexOf('\r') >= 0;
    if (!needsQuoting) {
      return value;
    }
    return "\"" + value.replace("\"", "\"\"") + "\"";
  }

  // -----------------------------------------------------------------------------------------
  // Result struct
  // -----------------------------------------------------------------------------------------

  /** Per-task outcome carried back from a worker thread and serialized to CSV. */
  private static final class TxResult {
    final BigInteger nonce;
    final boolean success;
    final String txHash; // populated on success, null on failure
    final String errorMessage; // populated on failure, null on success
    final long elapsedMs;
    final Instant timestamp;

    private TxResult(
        BigInteger nonce,
        boolean success,
        String txHash,
        String errorMessage,
        long elapsedMs,
        Instant timestamp) {
      this.nonce = nonce;
      this.success = success;
      this.txHash = txHash;
      this.errorMessage = errorMessage;
      this.elapsedMs = elapsedMs;
      this.timestamp = timestamp;
    }

    static TxResult success(BigInteger nonce, String txHash, long elapsedMs, Instant timestamp) {
      return new TxResult(nonce, true, txHash, null, elapsedMs, timestamp);
    }

    static TxResult failure(
        BigInteger nonce, String txHash, String errorMessage, long elapsedMs, Instant timestamp) {
      return new TxResult(nonce, false, txHash, errorMessage, elapsedMs, timestamp);
    }
  }
}

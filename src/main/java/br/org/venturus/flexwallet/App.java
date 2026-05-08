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
import java.util.TreeMap;
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
import br.org.venturus.flexwallet.crypto.key.types.GenericPublicKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;
import br.org.venturus.flexwallet.crypto.MLDSA;
import br.org.venturus.flexwallet.model.Transaction;
import br.org.venturus.flexwallet.model.encoder.EIP1559Encoder;
import br.org.venturus.flexwallet.request.EthSendRawTransaction;
import br.org.venturus.flexwallet.utils.FileUtils;
import br.org.venturus.flexwallet.crypto.key.types.CompositePrivateKey;

public class App {

  /**
   * Default RPC endpoints used in --txAmount batch mode when --nodes is not provided. Round-robin
   * by nonce: nonce 0 -> [0], nonce 1 -> [1], …
   */
  private static final String[] DEFAULT_BATCH_ENDPOINTS = {
      "http://localhost:8545",
      "http://localhost:8546",
      "http://localhost:8547",
      "http://localhost:8548",
  };

  /**
   * Worker threads used to send transactions concurrently in --txAmount batch mode. Distributing
   * across multiple endpoints means each route sees roughly DEFAULT_CONCURRENCY / N_ENDPOINTS
   * concurrent connections, so the per-route 5-connection default in Apache HttpClient's fluent
   * pool is comfortable for the default 4-node fan-out.
   */
  private static final int DEFAULT_CONCURRENCY = 16;

  /** Hard upper bound on time spent waiting for the worker pool to drain. */
  private static final long POOL_SHUTDOWN_TIMEOUT_SECONDS = 120L;

  /** CSV header for batch-mode result file. */
  private static final String CSV_HEADER =
      "nonce,endpoint,status,txHash,errorMessage,elapsedMs,timestamp";

  public static void main(String[] args) {
    // --help short-circuits all setup so that calling it on a misconfigured environment
    // (missing key file, no provider, etc.) still prints usage instead of crashing.
    if (parseHelp(args)) {
      printHelp();
      return;
    }

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

      // Optional --nodes URL1,URL2,... ; null means "use the default endpoints".
      String[] nodesArg = parseNodes(args);

      // Resolve the endpoints used for batch and single-tx modes from --nodes (if provided)
      // or fall back to defaults. In single-tx mode we use the first URL the user supplied
      // — sending a single tx to multiple endpoints doesn't make sense.
      String[] batchEndpoints = nodesArg != null ? nodesArg : DEFAULT_BATCH_ENDPOINTS;
      String singleEndpoint =
          nodesArg != null ? nodesArg[0] : EthSendRawTransaction.DEFAULT_ENDPOINT;

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
        // Original single-transaction path: nonce = 0, single endpoint, no thread pool, no CSV.
        Transaction unsignedTransaction = buildTransaction(BigInteger.ZERO, pubBytes);
        byte[] rawTransaction = encoder.createRawTransaction(unsignedTransaction, sk);
        String tx = "0x" + EIP1559Encoder.bytesToHex(rawTransaction);
        EthSendRawTransaction.send(tx, singleEndpoint, true);
        return;
      }

      // ------------------------- Parallel batch send ----------------------------
      // Each task builds its own transaction, signs it, POSTs to its assigned endpoint, and
      // returns a TxResult. EthSendRawTransaction.send is invoked with verbose=false so the
      // per-call "Result: ..." line is suppressed — every outcome is captured in the CSV.
      //
      // Endpoints are assigned round-robin by nonce: nonce 0 -> [0], nonce 1 -> [1], ... so over
      // a long batch each node sees roughly txAmount / batchEndpoints.length transactions.
      int threads = Math.min(txAmount, DEFAULT_CONCURRENCY);
      ExecutorService pool = Executors.newFixedThreadPool(threads);
      List<Future<TxResult>> futures = new ArrayList<>(txAmount);

      // Effectively-final captures for the lambda.
      final byte[] pubBytesCapt = pubBytes;
      final PrivateKey skCapt = sk;
      final EIP1559Encoder encoderCapt = encoder;
      final String[] endpointsCapt = batchEndpoints;

      List<TxResult> results = new ArrayList<>(txAmount);

      try {
        for (int i = 0; i < txAmount; i++) {
          final BigInteger nonce = BigInteger.valueOf(i);
          final String endpoint = endpointsCapt[i % endpointsCapt.length];
          futures.add(
              pool.submit(() -> sendOne(nonce, endpoint, pubBytesCapt, skCapt, encoderCapt)));
        }

        // Drain results in submission (= nonce) order.
        for (Future<TxResult> future : futures) {
          try {
            results.add(future.get());
          } catch (ExecutionException ee) {
            // The Callable shouldn't throw — it catches everything internally — but stay defensive.
            Throwable cause = ee.getCause() != null ? ee.getCause() : ee;
            results.add(
                TxResult.failure(
                    BigInteger.valueOf(-1),
                    "<unknown>",
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
                    BigInteger.valueOf(-1),
                    "<unknown>",
                    null,
                    "interrupted while waiting",
                    0L,
                    Instant.now()));
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
      // TreeMap so the per-endpoint breakdown is sorted by URL — easy to scan.
      Map<String, int[]> perEndpoint = new TreeMap<>(); // value: [success, failure]
      for (TxResult r : results) {
        int[] bucket = perEndpoint.computeIfAbsent(r.endpoint, k -> new int[2]);
        if (r.success) {
          successCount++;
          bucket[0]++;
        } else {
          failureCount++;
          bucket[1]++;
          failureCountsByMessage.merge(
              r.errorMessage == null ? "<unknown>" : r.errorMessage, 1, Integer::sum);
        }
      }

      System.out.println();
      System.out.println("================ Transaction Batch Summary ================");
      System.out.println("Total:     " + txAmount);
      System.out.println("Succeeded: " + successCount);
      System.out.println("Failed:    " + failureCount);
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
   * Build, sign, and POST a single transaction to {@code endpoint}. Always returns a {@link
   * TxResult} — the worker never throws, so a single bad request can't take down the whole batch.
   */
  private static TxResult sendOne(
      BigInteger nonce, String endpoint, byte[] pubBytes, PrivateKey sk, EIP1559Encoder encoder) {
    Instant timestamp = Instant.now();
    long startNs = System.nanoTime();
    try {
      Transaction unsignedTransaction = buildTransaction(nonce, pubBytes);
      byte[] rawTransaction = encoder.createRawTransaction(unsignedTransaction, sk);
      String tx = "0x" + EIP1559Encoder.bytesToHex(rawTransaction);

      String response = EthSendRawTransaction.send(tx, endpoint, false);
      long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;

      if (isJsonRpcError(response)) {
        return TxResult.failure(
            nonce, endpoint, null, extractJsonRpcErrorMessage(response), elapsedMs, timestamp);
      }
      return TxResult.success(
          nonce, endpoint, extractJsonRpcResult(response), elapsedMs, timestamp);
    } catch (Exception e) {
      long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;
      return TxResult.failure(
          nonce,
          endpoint,
          null,
          e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()),
          elapsedMs,
          timestamp);
    }
  }

  // -----------------------------------------------------------------------------------------
  // CLI parsing
  // -----------------------------------------------------------------------------------------

  /** True when {@code --help} or {@code -h} is anywhere in the args list. */
  private static boolean parseHelp(String[] args) {
    for (String a : args) {
      if (a == null) continue;
      String lower = a.toLowerCase();
      if (lower.equals("--help") || lower.equals("-h")) {
        return true;
      }
    }
    return false;
  }

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

  /**
   * Optional {@code --nodes URL1,URL2,...} or {@code --nodes=URL1,URL2,...}. Returns the list of
   * trimmed, non-empty URLs, or {@code null} when the flag is absent (use the defaults).
   */
  private static String[] parseNodes(String[] args) {
    for (int i = 0; i < args.length; i++) {
      String a = args[i];
      String lower = a.toLowerCase();

      if (lower.equals("--nodes")) {
        if (i + 1 >= args.length) {
          throw new IllegalArgumentException(
              "--nodes requires a comma-separated list of URLs");
        }
        return splitNodes(args[i + 1]);
      }

      if (lower.startsWith("--nodes=")) {
        return splitNodes(a.substring("--nodes=".length()));
      }
    }
    return null;
  }

  private static String[] splitNodes(String value) {
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException("--nodes value cannot be empty");
    }
    String[] parts = value.split(",");
    List<String> cleaned = new ArrayList<>(parts.length);
    for (String p : parts) {
      String trimmed = p.trim();
      if (!trimmed.isEmpty()) {
        cleaned.add(trimmed);
      }
    }
    if (cleaned.isEmpty()) {
      throw new IllegalArgumentException("--nodes value must contain at least one URL");
    }
    return cleaned.toArray(new String[0]);
  }

  private static int parseIntOrThrow(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("--txAmount value must be an integer; got: " + value);
    }
  }

  /** Print the usage block to stdout. Called when --help / -h is detected. */
  private static void printHelp() {
    StringBuilder sb = new StringBuilder();
    sb.append("Flexwallet — sign EIP-1559-style transactions and POST them to JSON-RPC nodes.\n")
        .append('\n')
        .append("USAGE\n")
        .append("  mvn exec:java -Dexec.args=\"[OPTIONS]\"\n")
        .append("  (omit -Dexec.args to run with no flags)\n")
        .append('\n')
        .append("OPTIONS\n")
        .append("  --help, -h              Print this help and exit.\n")
        .append('\n')
        .append("  --generateKeys          Force regeneration of the key pair file. Without\n")
        .append("                          this flag, keys are generated only if the key file\n")
        .append("                          does not already exist.\n")
        .append('\n')
        .append("  --txAmount N            Batch mode. Sign and send N transactions in\n")
        .append("                          parallel using nonces 0..N-1, distributing them\n")
        .append("                          round-robin across the endpoints in --nodes. Per-\n")
        .append("                          transaction outcomes are written to a CSV instead\n")
        .append("                          of stdout. Without this flag the app sends a\n")
        .append("                          single transaction with nonce 0 and prints the\n")
        .append("                          JSON-RPC response to stdout.\n")
        .append('\n')
        .append("  --nodes URL1,URL2,...   Comma-separated JSON-RPC endpoints. In batch mode\n")
        .append("                          (--txAmount), transactions are distributed across\n")
        .append("                          them round-robin by nonce. In single-tx mode only\n")
        .append("                          the first URL is used.\n")
        .append("                          Defaults: ")
        .append(joinDefault(DEFAULT_BATCH_ENDPOINTS))
        .append("\n                                    in batch mode,\n")
        .append("                                    ")
        .append(EthSendRawTransaction.DEFAULT_ENDPOINT)
        .append(" in single-tx mode.\n")
        .append('\n')
        .append("  --output PATH           Path for the batch CSV. Defaults to\n")
        .append("                          tx_results_<yyyyMMdd-HHmmss>.csv in the current\n")
        .append("                          working directory. Ignored in single-tx mode.\n")
        .append('\n')
        .append("EXAMPLES\n")
        .append("  Single tx to ").append(EthSendRawTransaction.DEFAULT_ENDPOINT).append(":\n")
        .append("    mvn exec:java\n")
        .append('\n')
        .append("  Generate keys and send 100 tx across the 4 default nodes:\n")
        .append("    mvn exec:java -Dexec.args=\"--generateKeys --txAmount 100\"\n")
        .append('\n')
        .append("  10k tx with a custom CSV path:\n")
        .append("    mvn exec:java -Dexec.args=\"--txAmount 10000 --output /tmp/run42.csv\"\n")
        .append('\n')
        .append("  1k tx across 2 specific nodes:\n")
        .append("    mvn exec:java -Dexec.args=\"--txAmount 1000 \\\n")
        .append("      --nodes http://node1:8545,http://node2:8545\"\n")
        .append('\n')
        .append("  Show this help:\n")
        .append("    mvn exec:java -Dexec.args=\"--help\"\n");
    System.out.print(sb);
  }

  private static String joinDefault(String[] urls) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < urls.length; i++) {
      if (i > 0) sb.append(',');
      sb.append(urls[i]);
    }
    return sb.toString();
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
        w.write(csvEscape(r.endpoint));
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
    final String endpoint;
    final boolean success;
    final String txHash; // populated on success, null on failure
    final String errorMessage; // populated on failure, null on success
    final long elapsedMs;
    final Instant timestamp;

    private TxResult(
        BigInteger nonce,
        String endpoint,
        boolean success,
        String txHash,
        String errorMessage,
        long elapsedMs,
        Instant timestamp) {
      this.nonce = nonce;
      this.endpoint = endpoint;
      this.success = success;
      this.txHash = txHash;
      this.errorMessage = errorMessage;
      this.elapsedMs = elapsedMs;
      this.timestamp = timestamp;
    }

    static TxResult success(
        BigInteger nonce, String endpoint, String txHash, long elapsedMs, Instant timestamp) {
      return new TxResult(nonce, endpoint, true, txHash, null, elapsedMs, timestamp);
    }

    static TxResult failure(
        BigInteger nonce,
        String endpoint,
        String txHash,
        String errorMessage,
        long elapsedMs,
        Instant timestamp) {
      return new TxResult(nonce, endpoint, false, txHash, errorMessage, elapsedMs, timestamp);
    }
  }
}

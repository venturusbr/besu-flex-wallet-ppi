package br.org.venturus.flexwallet.cli;

import java.util.ArrayList;
import java.util.List;

import br.org.venturus.flexwallet.request.EthSendRawTransaction;

/**
 * Parsed view of the command-line arguments. {@link #parse(String[])} is the only construction
 * path; callers query the configuration via the named accessors. {@link #hasHelpFlag(String[])}
 * is a separate static utility because it short-circuits before any setup happens in
 * {@code App.main}.
 */
public final class CliArgs {

  /**
   * RPC endpoints used in batch mode when {@code --nodes} is not provided. Distribution is
   * round-robin by nonce. Edit this list (or use {@code --nodes}) to change the fan-out.
   */
  public static final String[] DEFAULT_BATCH_ENDPOINTS = {
      "http://localhost:8545",
      "http://localhost:8546",
      "http://localhost:8547",
      "http://localhost:8548",
  };

  private final Integer txAmount; // null -> single-tx mode
  private final String outputPath; // null -> default path
  private final String[] nodes; // null -> use defaults
  private final Double maxRate; // null -> no throttling
  private final boolean generateKeys;
  private final String dsaMode; // new field
  

  private CliArgs(
      Integer txAmount, String outputPath, String[] nodes, Double maxRate, boolean generateKeys, String dsaMode) {
    this.txAmount = txAmount;
    this.outputPath = outputPath;
    this.nodes = nodes;
    this.maxRate = maxRate;
    this.generateKeys = generateKeys;
    this.dsaMode = dsaMode;
  }

  // --- Accessors ---------------------------------------------------------------------------

  public boolean batchMode() {
    return txAmount != null;
  }

  /** Number of transactions to send in batch mode; 1 in single-tx mode. */
  public int txAmount() {
    return txAmount != null ? txAmount : 1;
  }

  /** Caller-supplied CSV output path, or {@code null} to use the default. */
  public String outputPath() {
    return outputPath;
  }

  /** Caller-supplied endpoint list, or {@code null} to fall back on the defaults. */
  public String[] nodes() {
    return nodes;
  }

  /** Caller-supplied max TPS, or {@code null} for no throttling. */
  public Double maxRate() {
    return maxRate;
  }

  /** Returns the DSA mode string, e.g. "EIP1559" or "FlexibleEIP1559". Defaults to "FlexibleEIP1559". */
  public String dsaMode() {
    return dsaMode != null ? dsaMode : "FlexibleEIP1559";
  }

  public boolean generateKeys() {
    return generateKeys;
  }

  /** Endpoints used for the batch fan-out: caller-provided when present, defaults otherwise. */
  public String[] batchEndpoints() {
    return nodes != null ? nodes : DEFAULT_BATCH_ENDPOINTS;
  }

  /**
   * Single-tx endpoint: first node from {@code --nodes} when present, otherwise the default
   * shipped by {@link EthSendRawTransaction#DEFAULT_ENDPOINT}.
   */
  public String singleEndpoint() {
    return nodes != null ? nodes[0] : EthSendRawTransaction.DEFAULT_ENDPOINT;
  }

  // --- Parsing -----------------------------------------------------------------------------

  /** True when {@code --help} or {@code -h} is anywhere in the args list. */
  public static boolean hasHelpFlag(String[] args) {
    for (String a : args) {
      if (a == null) continue;
      String lower = a.toLowerCase();
      if (lower.equals("--help") || lower.equals("-h")) {
        return true;
      }
    }
    return false;
  }

  /** Parse the full argument vector. Throws {@link IllegalArgumentException} on malformed input. */
  public static CliArgs parse(String[] args) {
    boolean generateKeys = false;
    for (String arg : args) {
      if (arg != null && arg.equalsIgnoreCase("--generateKeys")) {
        generateKeys = true;
        break;
      }
    }

    Integer txAmount = parseTxAmount(args);
    if (txAmount != null && txAmount < 1) {
      throw new IllegalArgumentException("--txAmount must be >= 1, got " + txAmount);
    }

    return new CliArgs(
        txAmount, parseOutputPath(args), parseNodes(args), parseMaxRate(args), generateKeys, parseDsaMode(args));
  }

  // --- Individual flag parsers ------------------------------------------------------------

  private static Integer parseTxAmount(String[] args) {
    for (int i = 0; i < args.length; i++) {
      String a = args[i];
      String lower = a.toLowerCase();
      if (lower.equals("--txamount")) {
        if (i + 1 >= args.length) {
          throw new IllegalArgumentException("--txAmount requires an integer value");
        }
        return parseIntOrThrow("--txAmount", args[i + 1]);
      }
      if (lower.startsWith("--txamount=")) {
        return parseIntOrThrow("--txAmount", a.substring("--txamount=".length()));
      }
    }
    return null;
  }

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

  private static Double parseMaxRate(String[] args) {
    for (int i = 0; i < args.length; i++) {
      String a = args[i];
      String lower = a.toLowerCase();
      if (lower.equals("--maxrate")) {
        if (i + 1 >= args.length) {
          throw new IllegalArgumentException(
              "--maxRate requires a number (transactions/second)");
        }
        return parsePositiveDoubleOrThrow("--maxRate", args[i + 1]);
      }
      if (lower.startsWith("--maxrate=")) {
        return parsePositiveDoubleOrThrow("--maxRate", a.substring("--maxrate=".length()));
      }
    }
    return null;
  }

  private static String parseDsaMode(String[] args) {
    for (int i = 0; i < args.length; i++) {
      String lower = args[i].toLowerCase();
      if (lower.equals("--dsa-mode")) {
        if (i + 1 >= args.length) throw new IllegalArgumentException("--dsa-mode requires a value (e.g. EIP1559 or FlexibleEIP1559)");
        return args[i + 1];
      }
      if (lower.startsWith("--dsa-mode=")) {
        return args[i].substring("--dsa-mode=".length());
      }
    }
    return null;
  }

  // --- Low-level helpers -------------------------------------------------------------------

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

  private static int parseIntOrThrow(String flag, String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(flag + " value must be an integer; got: " + value);
    }
  }

  private static double parsePositiveDoubleOrThrow(String flag, String value) {
    double parsed;
    try {
      parsed = Double.parseDouble(value);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(flag + " value must be a number; got: " + value);
    }
    if (!(parsed > 0) || Double.isInfinite(parsed)) {
      throw new IllegalArgumentException(
          flag + " must be a positive finite number; got: " + value);
    }
    return parsed;
  }
}

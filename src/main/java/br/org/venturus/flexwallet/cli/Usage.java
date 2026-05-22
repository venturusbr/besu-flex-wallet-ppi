package br.org.venturus.flexwallet.cli;

import br.org.venturus.flexwallet.request.EthSendRawTransaction;

/** Holder for the --help text. Kept separate from CliArgs so the parser stays readable. */
public final class Usage {
  private Usage() {}

  /** Print the usage block to stdout. Called when --help / -h is detected. */
  public static void print() {
    StringBuilder sb = new StringBuilder();
    sb.append("Flexwallet — sign EIP-1559-style transactions and POST them to JSON-RPC nodes.\n")
        .append('\n')
        .append("USAGE\n")
        .append("  mvn exec:java -Dexec.args=\"--txType <TYPE> [OPTIONS]\"\n")
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
        .append(join(CliArgs.DEFAULT_BATCH_ENDPOINTS))
        .append("\n                                    in batch mode,\n")
        .append("                                    ")
        .append(EthSendRawTransaction.DEFAULT_ENDPOINT)
        .append(" in single-tx mode.\n")
        .append('\n')
        .append("  --output PATH           Path for the batch CSV. Defaults to\n")
        .append("                          tx_results_<yyyyMMdd-HHmmss>.csv in the current\n")
        .append("                          working directory. Ignored in single-tx mode.\n")
        .append('\n')
        .append("  --maxRate TPS           Upper bound on the batch submission rate, in\n")
        .append("                          transactions per second (fractional values\n")
        .append("                          allowed, e.g. 0.5 = 1 tx every 2s). When the flag\n")
        .append("                          is omitted, the submission loop runs as fast as\n")
        .append("                          the worker pool can dispatch — which can flood a\n")
        .append("                          co-located Besu's tx pool faster than consensus\n")
        .append("                          drains it. Pick a value that matches your block\n")
        .append("                          time × txs-per-block budget. Ignored in single-tx\n")
        .append("                          mode.\n")
        .append('\n')
        .append("  --txType TYPE           Type of transaction, \"EIP1559\" or \"FlexibleEIP1559\".\n")
        .append("                          Required.\n")
        .append('\n')
        .append("EXAMPLES\n")
        .append("  Single tx to ").append(EthSendRawTransaction.DEFAULT_ENDPOINT).append(":\n")
        .append("    mvn exec:java -Dexec.args=\"--txType FlexibleEIP1559\"\n")
        .append('\n')
        .append("  Generate keys and send 100 legacy EIP1559 tx across the 4 default nodes:\n")
        .append("    mvn exec:java -Dexec.args=\"--generateKeys --txAmount 100 --txType EIP1559\"\n")
        .append('\n')
        .append("  10k tx with a custom CSV path:\n")
        .append("    mvn exec:java -Dexec.args=\"--txAmount 10000 --output /tmp/run42.csv --txType FlexibleEIP1559\"\n")
        .append('\n')
        .append("  1k tx across 2 specific nodes:\n")
        .append("    mvn exec:java -Dexec.args=\"--txAmount 1000 \\\n")
        .append("      --nodes http://node1:8545,http://node2:8545 --txType FlexibleEIP1559\"\n")
        .append('\n')
        .append("  10k tx, capped at 20 TPS — gentle on a co-located qbft node:\n")
        .append("    mvn exec:java -Dexec.args=\"--txAmount 10000 --maxRate 20 --txType FlexibleEIP1559\"\n")
        .append('\n')
        .append("  Show this help:\n")
        .append("    mvn exec:java -Dexec.args=\"--help\"\n");
    System.out.print(sb);
  }

  private static String join(String[] urls) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < urls.length; i++) {
      if (i > 0) sb.append(',');
      sb.append(urls[i]);
    }
    return sb.toString();
  }
}

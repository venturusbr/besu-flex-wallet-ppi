package br.org.venturus.flexwallet.batch;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Writes a list of {@link TxResult}s to disk as RFC-4180-compliant CSV. */
public final class CsvWriter {
  private static final String HEADER =
      "nonce,endpoint,status,txHash,errorMessage,elapsedMs,timestamp";

  private CsvWriter() {}

  /**
   * @return the default CSV path: {@code tx_results_<yyyyMMdd-HHmmss>.csv} in the current
   *     working directory. Stable within a single run; a fresh path is produced per call.
   */
  public static Path defaultPath() {
    String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
    return Paths.get("tx_results_" + stamp + ".csv");
  }

  /** Write {@code results} to {@code path}, creating parent directories as needed. */
  public static void write(Path path, List<TxResult> results) throws IOException {
    if (path.getParent() != null) {
      Files.createDirectories(path.getParent());
    }
    try (BufferedWriter w = Files.newBufferedWriter(path)) {
      w.write(HEADER);
      w.newLine();
      for (TxResult r : results) {
        w.write(r.nonce().toString());
        w.write(',');
        w.write(escape(r.endpoint()));
        w.write(',');
        w.write(r.success() ? "success" : "failure");
        w.write(',');
        w.write(escape(r.txHash()));
        w.write(',');
        w.write(escape(r.errorMessage()));
        w.write(',');
        w.write(Long.toString(r.elapsedMs()));
        w.write(',');
        w.write(r.timestamp().toString());
        w.newLine();
      }
    }
  }

  /** Quote and escape a CSV field per RFC 4180 when it contains special characters. */
  private static String escape(String value) {
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
}

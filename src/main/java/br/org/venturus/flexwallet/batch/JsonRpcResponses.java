package br.org.venturus.flexwallet.batch;

/**
 * Tiny, dependency-free helpers for picking apart {@code eth_sendRawTransaction} JSON-RPC
 * responses. Deliberately string-walking rather than calling Jackson — it keeps the project
 * free of a JSON-databind dependency for what's essentially a diagnostic log line.
 */
public final class JsonRpcResponses {
  private JsonRpcResponses() {}

  /** Returns {@code true} when {@code response} contains an {@code "error"} field. */
  public static boolean isError(String response) {
    return response != null && response.contains("\"error\"");
  }

  /**
   * Best-effort extraction of {@code error.message}. Falls back to the substring from
   * {@code "error"} onward when the structure is unexpected — better than swallowing the payload.
   */
  public static String extractErrorMessage(String response) {
    return extractStringField(response, "error", "message");
  }

  /**
   * For {@code eth_sendRawTransaction} the {@code "result"} field is the transaction hash on
   * success (or absent on error). Returns {@code null} when the field isn't present or the
   * response is malformed.
   */
  public static String extractResult(String response) {
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
   * Walk the response for {@code outerKey}, then within that scope find the string value of
   * {@code innerKey}. Returns the substring starting at {@code outerKey} as a diagnostic
   * fallback when anything is missing.
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
}

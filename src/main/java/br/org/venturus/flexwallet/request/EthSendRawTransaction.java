package br.org.venturus.flexwallet.request;

import org.apache.hc.client5.http.fluent.Request;
import org.apache.hc.core5.http.ContentType;

public class EthSendRawTransaction {
  private static final String endpointURL = "http://localhost:8545";

  /**
   * POST {@code eth_sendRawTransaction} to the local node and return the raw JSON-RPC response.
   *
   * <p>This single-arg form prints {@code Result: <body>} to stdout — the body is the raw JSON
   * object returned by the node, on a single line. Use {@link #send(String, boolean)} to
   * suppress the print (e.g. in batch mode where thousands of lines would drown the summary
   * and the per-tx outcome is captured in CSV).
   */
  public static String send(String rawTransaction) throws Exception {
    return send(rawTransaction, true);
  }

  /**
   * @param verbose when {@code true}, echo {@code Result: <response>} to stdout. When {@code
   *     false}, return silently — the caller is responsible for logging.
   */
  public static String send(String rawTransaction, boolean verbose) throws Exception {
    String jsonTransaction = String.format(
        "{ \"jsonrpc\": \"2.0\", \"method\": \"eth_sendRawTransaction\", \"params\": [\"%s\"], \"id\": 1 }",
        rawTransaction
    );

    String response = Request.post(endpointURL)
        .bodyString(jsonTransaction, ContentType.APPLICATION_JSON)
        .execute()
        .returnContent()
        .asString();

    if (verbose) {
      System.out.println("Result: " + response);
    }
    return response;
  }
}

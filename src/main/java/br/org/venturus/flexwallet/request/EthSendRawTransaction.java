package br.org.venturus.flexwallet.request;

import org.apache.hc.client5.http.fluent.Request;
import org.apache.hc.core5.http.ContentType;

public class EthSendRawTransaction {
  private static final String endpointURL = "http://localhost:8545";

  public static void send(String rawTransaction) throws Exception {
    String jsonTransaction = String.format(
        "{ \"jsonrpc\": \"2.0\", \"method\": \"eth_sendRawTransaction\", \"params\": [\"%s\"], \"id\": 1 }",
        rawTransaction
    );

    String response = Request.post(endpointURL)
        .bodyString(jsonTransaction, ContentType.APPLICATION_JSON)
        .execute()
        .returnContent()
        .asString();

    System.out.println("Result: " + response);
  }
}

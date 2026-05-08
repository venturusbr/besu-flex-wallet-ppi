package br.org.venturus.flexwallet.request;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.BasicHttpClientResponseHandler;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;

public class EthSendRawTransaction {
  /** Single-tx default — keeps the original behavior when no endpoint is supplied. */
  public static final String DEFAULT_ENDPOINT = "http://localhost:8545";

  /**
   * Total connection pool budget across all endpoints. The fluent {@code Request} API would cap
   * total connections at 25 by default, which serializes large concurrent batches. 64 leaves
   * comfortable headroom for App.DEFAULT_CONCURRENCY = 16 even when fan-out shrinks to a single
   * endpoint. Bump this in lockstep with the worker pool size.
   */
  private static final int MAX_TOTAL_CONNECTIONS = 64;

  /**
   * Maximum concurrent connections per endpoint (per "route"). The HttpClient default is 5, which
   * is the actual bottleneck when {@code --nodes} resolves to a single URL. 32 covers
   * App.DEFAULT_CONCURRENCY = 16 and leaves room to bump it.
   */
  private static final int MAX_CONNECTIONS_PER_ROUTE = 32;

  /** TCP connect timeout — fast-fail on a node that's down rather than hanging the worker. */
  private static final Timeout CONNECT_TIMEOUT = Timeout.ofSeconds(5);

  /** How long to wait for the JSON-RPC response before giving up. */
  private static final Timeout RESPONSE_TIMEOUT = Timeout.ofSeconds(30);

  /**
   * One client + one pool, shared across all calls and threads. Apache HttpClient is designed for
   * multi-threaded use; {@code execute(...)} is thread-safe.
   */
  private static final CloseableHttpClient HTTP_CLIENT;

  static {
    PoolingHttpClientConnectionManager connectionManager =
        PoolingHttpClientConnectionManagerBuilder.create()
            .setMaxConnTotal(MAX_TOTAL_CONNECTIONS)
            .setMaxConnPerRoute(MAX_CONNECTIONS_PER_ROUTE)
            .build();

    RequestConfig requestConfig = RequestConfig.custom()
        .setConnectTimeout(CONNECT_TIMEOUT)
        .setResponseTimeout(RESPONSE_TIMEOUT)
        .build();

    HTTP_CLIENT = HttpClients.custom()
        .setConnectionManager(connectionManager)
        .setDefaultRequestConfig(requestConfig)
        .build();

    // No shutdown hook on purpose. The pool only owns sockets + a manager thread, both of which
    // the OS reclaims on process exit; there's no buffered state to flush. A hook would also race
    // with mvn exec:java's classloader teardown — the plugin closes its custom classloader before
    // shutdown hooks run, which makes HttpClient.close() throw NoClassDefFoundError when it tries
    // to reference org.apache.hc.core5.io.CloseMode.
  }

  /**
   * POST {@code eth_sendRawTransaction} to {@link #DEFAULT_ENDPOINT} and return the raw JSON-RPC
   * response. Prints {@code Result: <body>} to stdout.
   */
  public static String send(String rawTransaction) throws Exception {
    return send(rawTransaction, DEFAULT_ENDPOINT, true);
  }

  /** Same as {@link #send(String)} but with an explicit verbose toggle. */
  public static String send(String rawTransaction, boolean verbose) throws Exception {
    return send(rawTransaction, DEFAULT_ENDPOINT, verbose);
  }

  /**
   * POST {@code eth_sendRawTransaction} to the given JSON-RPC endpoint via the shared pooled
   * client.
   *
   * @param endpoint full URL, e.g. {@code "http://localhost:8546"}.
   * @param verbose when {@code true}, echo {@code Result: <response>} to stdout.
   */
  public static String send(String rawTransaction, String endpoint, boolean verbose)
      throws Exception {
    String jsonTransaction = String.format(
        "{ \"jsonrpc\": \"2.0\", \"method\": \"eth_sendRawTransaction\", \"params\": [\"%s\"], \"id\": 1 }",
        rawTransaction
    );

    HttpPost post = new HttpPost(endpoint);
    post.setEntity(new StringEntity(jsonTransaction, ContentType.APPLICATION_JSON));

    // BasicHttpClientResponseHandler returns the body as a String for 2xx and throws
    // HttpResponseException for non-2xx — caught upstream as a per-tx failure in batch mode.
    String response = HTTP_CLIENT.execute(post, new BasicHttpClientResponseHandler());

    if (verbose) {
      System.out.println("Result: " + response);
    }
    return response;
  }
}

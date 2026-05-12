package br.org.venturus.flexwallet.batch;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Per-task outcome carried back from a worker thread and serialized to CSV.
 *
 * @param nonce sender nonce assigned to this transaction
 * @param endpoint JSON-RPC URL the transaction was POSTed to
 * @param success {@code true} when the node returned a JSON-RPC {@code result} (tx hash)
 * @param txHash hex transaction hash returned by the node on success, {@code null} on failure
 * @param errorMessage error message extracted from the JSON-RPC body, or the exception
 *     class name + message on local failure; {@code null} on success
 * @param elapsedMs wall-clock time spent building + signing + POSTing this transaction
 * @param timestamp when the task started (UTC)
 */
public record TxResult(
    BigInteger nonce,
    String endpoint,
    boolean success,
    String txHash,
    String errorMessage,
    long elapsedMs,
    Instant timestamp) {

  public static TxResult success(
      BigInteger nonce, String endpoint, String txHash, long elapsedMs, Instant timestamp) {
    return new TxResult(nonce, endpoint, true, txHash, null, elapsedMs, timestamp);
  }

  public static TxResult failure(
      BigInteger nonce,
      String endpoint,
      String errorMessage,
      long elapsedMs,
      Instant timestamp) {
    return new TxResult(nonce, endpoint, false, null, errorMessage, elapsedMs, timestamp);
  }
}

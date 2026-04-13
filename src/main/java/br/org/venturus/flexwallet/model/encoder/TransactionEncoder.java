package br.org.venturus.flexwallet.model.encoder;

import br.org.venturus.flexwallet.model.Transaction;
import java.security.PrivateKey;

public abstract class TransactionEncoder {
  public abstract byte[] encodeToRlp(Transaction tx);
  public abstract byte[] createRawTransaction(Transaction unsignedTx, PrivateKey sk);
  public abstract byte[] createDigest(Transaction unsignedTx);
}

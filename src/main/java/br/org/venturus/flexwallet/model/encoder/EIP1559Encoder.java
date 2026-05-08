package br.org.venturus.flexwallet.model.encoder;

import br.org.venturus.flexwallet.crypto.DigitalSignatureAlgorithm;
import br.org.venturus.flexwallet.model.Transaction;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpType;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.util.List;
import java.util.Optional;

public class EIP1559Encoder extends TransactionEncoder {
  private final DigitalSignatureAlgorithm signatureAlgorithm;
  private final boolean verbose;

  /** Default-verbose constructor — preserves the existing console output for single-tx runs. */
  public EIP1559Encoder(DigitalSignatureAlgorithm signatureAlgorithm) {
    this(signatureAlgorithm, true);
  }

  /**
   * @param verbose when {@code false}, suppress the inline {@code Signature length} debug
   *     printlns. App.java sets this to {@code false} for {@code --txAmount} batch runs so the
   *     output of N concurrent signs doesn't drown out the summary.
   */
  public EIP1559Encoder(DigitalSignatureAlgorithm signatureAlgorithm, boolean verbose) {
    this.signatureAlgorithm = signatureAlgorithm;
    this.verbose = verbose;
  }

  @Override
  public byte[] encodeToRlp(Transaction tx) {
    List<RlpType> values = tx.asRlpValues(tx.getSignature());
    RlpList rlpList = new RlpList(values);
    byte[] encoded = RlpEncoder.encode(rlpList);
    return ByteBuffer.allocate(encoded.length + 1)
        .put((byte) 0x42) // Flexible EIP-1559 type
        .put(encoded)
        .array();
  }

  @Override
  public byte[] createRawTransaction(Transaction unsignedTx, PrivateKey sk) {
    byte[] digest = createDigest(unsignedTx);
    byte[] signature = signatureAlgorithm.sign(digest, sk);
    if (verbose) {
      System.out.println("~~~~~~~~~~~~~~~~~~~ Signature length ~~~~~~~~~~~~~~~~~~~~~~~~~~~");
      System.out.println(signature.length);
      System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    }
    unsignedTx.setSignature(Optional.of(signature));
    return encodeToRlp(unsignedTx);
  }

  @Override
  public byte[] createDigest(Transaction unsignedTx) {
    byte[] encodedUnsignedTx = encodeToRlp(unsignedTx);
    Keccak.Digest256 keccak256 = new Keccak.Digest256();
    return keccak256.digest(encodedUnsignedTx);
  }

  public static String bytesToHex(byte[] bytes) {
    StringBuilder hexString = new StringBuilder();
    for (byte b : bytes) {
      hexString.append(String.format("%02x", b));
    }
    return hexString.toString();
  }
}

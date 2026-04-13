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

  public EIP1559Encoder(DigitalSignatureAlgorithm signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
  }

  @Override
  public byte[] encodeToRlp(Transaction tx) {
    List<RlpType> values = tx.asRlpValues(tx.getSignature());
    RlpList rlpList = new RlpList(values);
    byte[] encoded = RlpEncoder.encode(rlpList);
    return ByteBuffer.allocate(encoded.length + 1)
        .put((byte) 0x02) // EIP-1559 type
        .put(encoded)
        .array();
  }

  @Override
  public byte[] createRawTransaction(Transaction unsignedTx, PrivateKey sk) {
    byte[] digest = createDigest(unsignedTx);
    byte[] signature = signatureAlgorithm.sign(digest, sk);
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

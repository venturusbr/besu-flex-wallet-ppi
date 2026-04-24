package br.org.venturus.flexwallet.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;

import br.org.venturus.flexwallet.crypto.key.types.CompositeKeyPair;
import br.org.venturus.flexwallet.crypto.key.types.CompositePrivateKey;

public class NestedHybridDSA implements DigitalSignatureAlgorithm {
  private final DigitalSignatureAlgorithm firstAlg;
  private final DigitalSignatureAlgorithm secondAlg;

  public NestedHybridDSA(DigitalSignatureAlgorithm firstAlg, DigitalSignatureAlgorithm secondAlg) {
    this.firstAlg = firstAlg;
    this.secondAlg = secondAlg;
  }

  @Override
  public CompositeKeyPair generateKeyPair() {
    CompositeKeyPair firstKeyPair = firstAlg.generateKeyPair();
    CompositeKeyPair secondKeyPair = secondAlg.generateKeyPair();
    return CompositeKeyPair.of(firstKeyPair, secondKeyPair);
  }

  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    CompositePrivateKey hybridPrivateKey = (CompositePrivateKey) privateKey;

    byte[] signature1 = firstAlg.sign(data, hybridPrivateKey.getFirstKey());
    byte[] dataWithSignature1 = Bytes.concatenate(
            Bytes.wrap(data),
            Bytes.wrap(signature1)).toArrayUnsafe();

    byte[] signature2 = secondAlg.sign(dataWithSignature1, hybridPrivateKey.getSecondKey());
    byte[] result = Bytes.concatenate(
            Bytes.wrap(signature1),
            Bytes.wrap(signature2)).toArrayUnsafe();
    return result;



  }

  @Override
  public PrivateKey getPrivateKeyFromEncoded(byte[] encoded) {
    throw new UnsupportedOperationException();
  }

  public PrivateKey getPrivateKeyFromEncoded(byte[] firstSk, byte[] secondSk) {
    return CompositePrivateKey.create(
      firstAlg.getPrivateKeyFromEncoded(firstSk),
      secondAlg.getPrivateKeyFromEncoded(secondSk)
    );
  }

  @Override
  public PublicKey getPublicKeyFromEncoded(byte[] encoded) {
    throw new UnsupportedOperationException();
  }
}

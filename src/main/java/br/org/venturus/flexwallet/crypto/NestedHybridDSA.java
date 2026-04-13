package br.org.venturus.flexwallet.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

import br.org.venturus.flexwallet.crypto.key.types.CompositeKeyPair;

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

  // TODO Ver referência no besu crypto/algorithms/src/main/java/org/hyperledger/besu/crypto/key/types/CompositePrivateKey.java
  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    throw new UnsupportedOperationException("Use sign(byte[], PrivateKey, PrivateKey) for hybrid.");
  }

  // TODO Trazer comportamento pro sign de cima que recebe a CompositePrivateKey. Este sign q recebe 2 chaves deixa de existir
  public byte[] sign(byte[] data, PrivateKey firstKey, PrivateKey secondKey) {
    byte[] sig1 = firstAlg.sign(data, firstKey);
    byte[] dataWithSig1 = new byte[data.length + sig1.length];
    System.arraycopy(data, 0, dataWithSig1, 0, data.length);
    System.arraycopy(sig1, 0, dataWithSig1, data.length, sig1.length);

    byte[] sig2 = secondAlg.sign(dataWithSig1, secondKey);
    byte[] result = new byte[sig1.length + sig2.length];
    System.arraycopy(sig1, 0, result, 0, sig1.length);
    System.arraycopy(sig2, 0, result, sig1.length, sig2.length);
    return result;
  }

  @Override
  public PrivateKey getPrivateKeyFromEncoded(byte[] encoded) {
    throw new UnsupportedOperationException();
  }

  @Override
  public PublicKey getPublicKeyFromEncoded(byte[] encoded) {
    throw new UnsupportedOperationException();
  }
}

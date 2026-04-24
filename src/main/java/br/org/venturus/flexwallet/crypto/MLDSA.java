package br.org.venturus.flexwallet.crypto;

import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;

public class MLDSA implements DigitalSignatureAlgorithm {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  public NodeKeyPair generateKeyPair() {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
      kpg.initialize(DilithiumParameterSpec.dilithium3);
      KeyPair kp = kpg.generateKeyPair();
      return NodeKeyPair.of(kp.getPrivate(), kp.getPublic());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    try {
      Signature sig = Signature.getInstance("Dilithium", "BCPQC");
      sig.initSign(privateKey, new SecureRandom());
      sig.update(data);
      return sig.sign();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public PrivateKey getPrivateKeyFromEncoded(byte[] encoded) {
    try {
      return java.security.KeyFactory.getInstance("Dilithium", "BCPQC")
          .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(encoded));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public PublicKey getPublicKeyFromEncoded(byte[] encoded) {
    try {
      return java.security.KeyFactory.getInstance("Dilithium", "BCPQC")
          .generatePublic(new java.security.spec.X509EncodedKeySpec(encoded));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}

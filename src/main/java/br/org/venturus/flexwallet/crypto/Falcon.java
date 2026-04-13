package br.org.venturus.flexwallet.crypto;

import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import br.org.venturus.flexwallet.crypto.key.types.CompositeKeyPair;

public class Falcon implements DigitalSignatureAlgorithm {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  public CompositeKeyPair generateKeyPair() {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", "BCPQC");
      kpg.initialize(FalconParameterSpec.falcon_512); // Falcon-512
      KeyPair kp = kpg.generateKeyPair();
      return CompositeKeyPair.of(kp.getPrivate(), kp.getPublic());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    try {
      Signature sig = Signature.getInstance("Falcon", "BCPQC");
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
      return java.security.KeyFactory.getInstance("Falcon", "BCPQC")
          .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(encoded));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public PublicKey getPublicKeyFromEncoded(byte[] encoded) {
    try {
      return java.security.KeyFactory.getInstance("Falcon", "BCPQC")
          .generatePublic(new java.security.spec.X509EncodedKeySpec(encoded));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}

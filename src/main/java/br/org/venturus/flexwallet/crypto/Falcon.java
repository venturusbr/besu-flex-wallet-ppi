package br.org.venturus.flexwallet.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;

import br.org.venturus.flexwallet.crypto.key.types.GenericPrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.GenericPublicKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;

/**
 * Falcon-512 using BouncyCastle's low-level API, with the same raw encodings as Besu:
 * the public key is {@code h} (896 bytes) and the private key is {@code f || g || F || h}
 * (2176 bytes). Signatures are variable-length.
 */
public class Falcon implements DigitalSignatureAlgorithm {
  private static final FalconParameters PARAMS = FalconParameters.falcon_512;
  private static final int F_LENGTH = 384;
  private static final int G_LENGTH = 384;
  private static final int CAPITAL_F_LENGTH = 512;
  private static final int PUBLIC_KEY_LENGTH = 896;
  private static final int PRIVATE_KEY_LENGTH =
      F_LENGTH + G_LENGTH + CAPITAL_F_LENGTH + PUBLIC_KEY_LENGTH;

  @Override
  public NodeKeyPair generateKeyPair() {
    FalconKeyPairGenerator generator = new FalconKeyPairGenerator();
    generator.init(new FalconKeyGenerationParameters(new SecureRandom(), PARAMS));
    AsymmetricCipherKeyPair kp = generator.generateKeyPair();

    FalconPrivateKeyParameters skParams = (FalconPrivateKeyParameters) kp.getPrivate();
    FalconPublicKeyParameters pkParams = (FalconPublicKeyParameters) kp.getPublic();

    Bytes rawPk = Bytes.wrap(pkParams.getH());
    Bytes rawSk = Bytes.concatenate(
        Bytes.wrap(skParams.getSpolyf()),
        Bytes.wrap(skParams.getG()),
        Bytes.wrap(skParams.getSpolyF()),
        rawPk);

    return NodeKeyPair.of(new GenericPrivateKey(rawSk), new GenericPublicKey(rawPk));
  }

  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    // A fresh signer per call: FalconSigner holds per-operation state and is not thread-safe.
    FalconSigner signer = new FalconSigner();
    signer.init(true, new ParametersWithRandom(toBouncyCastle(privateKey.getEncoded()), new SecureRandom()));
    return signer.generateSignature(data);
  }

  @Override
  public PrivateKey getPrivateKeyFromEncoded(byte[] encoded) {
    return new GenericPrivateKey(Bytes.wrap(encoded));
  }

  @Override
  public PublicKey getPublicKeyFromEncoded(byte[] encoded) {
    return new GenericPublicKey(Bytes.wrap(encoded));
  }

  private static FalconPrivateKeyParameters toBouncyCastle(byte[] sk) {
    if (sk.length != PRIVATE_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "Falcon-512 private key must be " + PRIVATE_KEY_LENGTH + " bytes, got " + sk.length);
    }
    int gStart = F_LENGTH;
    int capitalFStart = gStart + G_LENGTH;
    int hStart = capitalFStart + CAPITAL_F_LENGTH;
    return new FalconPrivateKeyParameters(
        PARAMS,
        Arrays.copyOfRange(sk, 0, gStart),
        Arrays.copyOfRange(sk, gStart, capitalFStart),
        Arrays.copyOfRange(sk, capitalFStart, hStart),
        Arrays.copyOfRange(sk, hStart, sk.length));
  }
}

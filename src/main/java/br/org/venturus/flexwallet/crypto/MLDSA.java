package br.org.venturus.flexwallet.crypto;

import java.security.*;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import br.org.venturus.flexwallet.crypto.key.types.GenericPrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.GenericPublicKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;

public class MLDSA implements DigitalSignatureAlgorithm {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  public NodeKeyPair generateKeyPair() {
    MLDSAKeyPairGenerator mldsaKpGenerator = new MLDSAKeyPairGenerator();
    KeyGenerationParameters genParams = new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44);

    mldsaKpGenerator.init(genParams);
    AsymmetricCipherKeyPair mldsaKp = mldsaKpGenerator.generateKeyPair();

    MLDSAPrivateKeyParameters skParams = (MLDSAPrivateKeyParameters) mldsaKp.getPrivate();
    MLDSAPublicKeyParameters pkParams = (MLDSAPublicKeyParameters) mldsaKp.getPublic();

    Bytes rawSk = Bytes.wrap(skParams.getEncoded());
    Bytes rawPk = Bytes.wrap(pkParams.getEncoded());

    NodeKeyPair kp = NodeKeyPair.of(new GenericPrivateKey(rawSk), new GenericPublicKey(rawPk));

    return kp;
  }

  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    MLDSAPrivateKeyParameters skParams = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44,
        privateKey.getEncoded());
    MLDSASigner signerAndVerifier = new MLDSASigner();
    signerAndVerifier.init(true, skParams);
    signerAndVerifier.update(data, 0, data.length);

    try {
      return signerAndVerifier.generateSignature();
    } catch (DataLengthException | CryptoException e) {
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

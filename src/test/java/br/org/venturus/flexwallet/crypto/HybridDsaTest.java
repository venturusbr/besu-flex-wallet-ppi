package br.org.venturus.flexwallet.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.junit.jupiter.api.Test;

import br.org.venturus.flexwallet.crypto.key.types.CompositePrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.CompositePublicKey;
import br.org.venturus.flexwallet.crypto.key.types.GenericPrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;

class HybridDsaTest {
  private static final int SECP256K1_SIGNATURE_LENGTH = 65;

  @Test
  void parsesCliNamesCaseInsensitively() {
    assertEquals(HybridDsa.SECP256K1_FALCON512, HybridDsa.fromCliName("secp256k1-falcon512"));
    assertEquals(HybridDsa.SECP256K1_MLDSA44, HybridDsa.fromCliName("SECP256K1-MLDSA44"));
    assertThrows(IllegalArgumentException.class, () -> HybridDsa.fromCliName("FALCON512"));
  }

  @Test
  void falconHybridSignatureVerifiesAsBesuDoes() {
    DigitalSignatureAlgorithm hybrid = HybridDsa.SECP256K1_FALCON512.createAlgorithm();
    NodeKeyPair kp = hybrid.generateKeyPair();
    byte[] falconPk = ((CompositePublicKey) kp.getPublic()).getSecondKey().getEncoded();
    assertEquals(HybridDsa.SECP256K1_FALCON512.pqcPublicKeyLength(), falconPk.length);

    // Reload the private key from raw bytes, as App does with the key file.
    CompositePrivateKey stored = (CompositePrivateKey) kp.getPrivate();
    CompositePrivateKey reloaded = CompositePrivateKey.create(
        new GenericPrivateKey(org.apache.tuweni.bytes.Bytes.wrap(stored.getFirstKey().getEncoded())),
        new GenericPrivateKey(org.apache.tuweni.bytes.Bytes.wrap(stored.getSecondKey().getEncoded())));

    byte[] digest = new byte[32];
    new SecureRandom().nextBytes(digest);
    byte[] signature = hybrid.sign(digest, reloaded);

    // Besu: SECP256K1 signature is the fixed-length prefix, Falcon's is the remainder (<= 752).
    assertTrue(signature.length > SECP256K1_SIGNATURE_LENGTH);
    assertTrue(signature.length <= SECP256K1_SIGNATURE_LENGTH + 752);
    byte[] secpSig = Arrays.copyOfRange(signature, 0, SECP256K1_SIGNATURE_LENGTH);
    byte[] falconSig = Arrays.copyOfRange(signature, SECP256K1_SIGNATURE_LENGTH, signature.length);

    byte[] nested = new byte[digest.length + secpSig.length];
    System.arraycopy(digest, 0, nested, 0, digest.length);
    System.arraycopy(secpSig, 0, nested, digest.length, secpSig.length);

    FalconSigner verifier = new FalconSigner();
    verifier.init(false, new FalconPublicKeyParameters(FalconParameters.falcon_512, falconPk));
    assertTrue(verifier.verifySignature(nested, falconSig));
  }
}

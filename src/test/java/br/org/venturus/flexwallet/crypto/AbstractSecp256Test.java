package br.org.venturus.flexwallet.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Test;

import br.org.venturus.flexwallet.crypto.key.types.GenericPrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;

class AbstractSecp256Test {

  @Test
  void parsesCurveNamesCaseInsensitively() {
    assertEquals(EcCurve.SECP256R1, EcCurve.fromCliName("SECP256R1"));
    assertEquals(EcCurve.SECP256K1, EcCurve.fromCliName("secp256k1"));
    assertThrows(IllegalArgumentException.class, () -> EcCurve.fromCliName("secp384r1"));
  }

  @Test
  void derivesTheKnownSecp256k1AddressOfPrivateKeyOne() {
    byte[] one = new byte[32];
    one[31] = 1;
    byte[] pk = new Secp256k1().publicKeyOf(new GenericPrivateKey(Bytes.wrap(one)));
    assertEquals("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", AbstractSecp256.address(pk));
  }

  @Test
  void secp256r1KeysAreOnP256() {
    byte[] one = new byte[32];
    one[31] = 1;
    byte[] pk = new Secp256r1().publicKeyOf(new GenericPrivateKey(Bytes.wrap(one)));
    // The public key of d = 1 is the P-256 generator.
    assertEquals(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        Bytes.wrap(pk).toUnprefixedHexString());
  }

  /** What Besu does on the signature's curve: low-S check, then SEC 1 public-key recovery. */
  @ParameterizedTest
  @EnumSource(EcCurve.class)
  void signatureRecoversToTheSignerOnItsOwnCurve(EcCurve ecCurve) {
    AbstractSecp256 ecdsa = ecCurve.createAlgorithm();
    ECDomainParameters domain = domain(ecCurve.cliName());
    SecureRandom random = new SecureRandom();

    for (int i = 0; i < 20; i++) {
      NodeKeyPair kp = ecdsa.generateKeyPair();
      byte[] digest = new byte[32];
      random.nextBytes(digest);

      byte[] sig = ecdsa.sign(digest, kp.getPrivate());
      assertEquals(65, sig.length);
      BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
      BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
      int recId = sig[64];

      assertTrue(s.compareTo(domain.getN().shiftRight(1)) <= 0, "s must be low-S");
      assertTrue(recId == 0 || recId == 1);

      byte[] pk = kp.getPublic().getEncoded();
      assertArrayEquals(pk, ecdsa.publicKeyOf(kp.getPrivate()));
      assertArrayEquals(pk, recover(domain, recId, r, s, digest));

      ECDSASigner verifier = new ECDSASigner();
      verifier.init(false, new ECPublicKeyParameters(decode(domain, pk), domain));
      assertTrue(verifier.verifySignature(digest, r, s));
    }
  }

  @Test
  void secp256k1SignatureIsNotValidForTheSameKeyOnSecp256r1() {
    byte[] d = new byte[32];
    new SecureRandom().nextBytes(d);
    GenericPrivateKey sk = new GenericPrivateKey(Bytes.wrap(d));
    assertFalse(
        Arrays.equals(new Secp256k1().publicKeyOf(sk), new Secp256r1().publicKeyOf(sk)));
  }

  private static ECDomainParameters domain(String name) {
    X9ECParameters p = CustomNamedCurves.getByName(name);
    return new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
  }

  private static ECPoint decode(ECDomainParameters domain, byte[] xy) {
    byte[] encoded = new byte[65];
    encoded[0] = 0x04;
    System.arraycopy(xy, 0, encoded, 1, 64);
    return domain.getCurve().decodePoint(encoded);
  }

  /** Independent SEC 1 v2.0 §4.1.6 recovery for recId 0/1. */
  private static byte[] recover(
      ECDomainParameters domain, int recId, BigInteger r, BigInteger s, byte[] digest) {
    BigInteger n = domain.getN();
    byte[] compressed = new byte[33];
    compressed[0] = (byte) ((recId & 1) == 1 ? 0x03 : 0x02);
    byte[] x = r.toByteArray();
    int len = Math.min(x.length, 32);
    System.arraycopy(x, x.length - len, compressed, 33 - len, len);
    ECPoint bigR = domain.getCurve().decodePoint(compressed);

    BigInteger e = new BigInteger(1, digest);
    BigInteger rInv = r.modInverse(n);
    ECPoint q =
        ECAlgorithms.sumOfTwoMultiplies(
                domain.getG(), e.negate().mod(n).multiply(rInv).mod(n), bigR, s.multiply(rInv).mod(n))
            .normalize();
    byte[] uncompressed = q.getEncoded(false);
    return Arrays.copyOfRange(uncompressed, 1, 65);
  }
}

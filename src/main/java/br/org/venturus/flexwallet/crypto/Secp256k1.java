package br.org.venturus.flexwallet.crypto;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import br.org.venturus.flexwallet.crypto.key.types.GenericPrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.GenericPublicKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;

/**
 * secp256k1 ECDSA signer using the Bouncy Castle lightweight API, returning raw byte artifacts:
 *
 * <ul>
 *   <li>private key: 32 bytes (big-endian {@code D}).
 *   <li>public key: 64 bytes (uncompressed {@code X || Y} with the {@code 0x04} prefix stripped).
 *   <li>signature: 65 bytes ({@code r (32) || s (32) || recId (1)}). The recovery byte is the raw
 *       SEC 1 recovery id (0 or 1; theoretically 2/3, never observed in practice for secp256k1)
 *       and supports public-key recovery on the verifier side. Any Ethereum {@code v}-offsetting
 *       (legacy {@code +27}, EIP-155 {@code chainId * 2 + 35}) is the responsibility of the
 *       transaction encoder.
 * </ul>
 *
 * <p>Conventions match the modified Besu {@code SECP256K1} class (RFC 6979 deterministic {@code k}
 * with SHA-256 via {@link HMacDSAKCalculator}, low-S canonicalization per EIP-2, raw recovery id).
 */
public class Secp256k1 implements DigitalSignatureAlgorithm {

  /** secp256k1 domain parameters, loaded once. */
  private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

  private static final ECDomainParameters CURVE =
      new ECDomainParameters(
          CURVE_PARAMS.getCurve(),
          CURVE_PARAMS.getG(),
          CURVE_PARAMS.getN(),
          CURVE_PARAMS.getH());

  /** {@code n / 2}, the low-S threshold (EIP-2 / BIP-62). */
  private static final BigInteger HALF_CURVE_ORDER = CURVE.getN().shiftRight(1);

  /** Field characteristic of secp256k1 (prime {@code p}); used by the recovery routine. */
  private static final BigInteger CURVE_PRIME = SecP256K1Curve.q;

  private static final int PRIVATE_KEY_SIZE = 32;
  private static final int PUBLIC_KEY_SIZE = 64;
  private static final int SIGNATURE_SIZE = 65;

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Override
  public NodeKeyPair generateKeyPair() {
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    generator.init(new ECKeyGenerationParameters(CURVE, new SecureRandom()));
    AsymmetricCipherKeyPair kp = generator.generateKeyPair();

    ECPrivateKeyParameters skParams = (ECPrivateKeyParameters) kp.getPrivate();
    ECPublicKeyParameters pkParams = (ECPublicKeyParameters) kp.getPublic();

    Bytes rawSk = Bytes.wrap(toFixedLength(skParams.getD(), PRIVATE_KEY_SIZE));
    Bytes rawPk = Bytes.wrap(encodePublicKey(pkParams.getQ()));

    return NodeKeyPair.of(new GenericPrivateKey(rawSk), new GenericPublicKey(rawPk));
  }

  /**
   * Sign a 32-byte message digest (Keccak-256 of the RLP-encoded unsigned transaction in our
   * EIP-1559 flow) with the given raw 32-byte secp256k1 private key.
   *
   * @param data 32-byte message digest. Must already be hashed (matches Besu's {@code Bytes32
   *     dataHash} contract).
   * @param privateKey a {@link GenericPrivateKey} whose {@code getEncoded()} returns the raw
   *     32-byte scalar {@code d}.
   * @return 65 bytes: {@code r || s || recId}.
   */
  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    if (data == null || data.length != 32) {
      throw new IllegalArgumentException(
          "secp256k1 sign expects a 32-byte digest; got " + (data == null ? "null" : data.length));
    }
    byte[] skBytes = privateKey.getEncoded();
    if (skBytes == null || skBytes.length != PRIVATE_KEY_SIZE) {
      throw new IllegalArgumentException(
          "secp256k1 private key must be "
              + PRIVATE_KEY_SIZE
              + " raw bytes; got "
              + (skBytes == null ? "null" : skBytes.length));
    }

    BigInteger d = new BigInteger(1, skBytes);
    ECPrivateKeyParameters skParams = new ECPrivateKeyParameters(d, CURVE);

    // RFC 6979 deterministic k with SHA-256 — same as Besu's getKCalculator().
    ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    signer.init(true, skParams);

    BigInteger[] sig = signer.generateSignature(data);
    BigInteger r = sig[0];
    BigInteger s = sig[1];

    // Low-S canonicalization (EIP-2 / BIP-62). Required by all post-Homestead Ethereum verifiers.
    // When s is replaced by n - s, the recovery search below naturally finds the recId that
    // matches the canonicalized signature, so no manual flip is needed here.
    if (s.compareTo(HALF_CURVE_ORDER) > 0) {
      s = CURVE.getN().subtract(s);
    }

    // Compute recId by recovering each candidate Q and matching against the actual public key.
    ECPoint expectedQ = CURVE.getG().multiply(d).normalize();
    int recId = -1;
    for (int i = 0; i < 4; i++) {
      ECPoint candidate = recoverPoint(i, r, s, data);
      if (candidate != null && candidate.equals(expectedQ)) {
        recId = i;
        break;
      }
    }
    if (recId == -1) {
      throw new IllegalStateException("Unable to compute the secp256k1 signature recovery id");
    }

    byte[] out = new byte[SIGNATURE_SIZE];
    System.arraycopy(toFixedLength(r, 32), 0, out, 0, 32);
    System.arraycopy(toFixedLength(s, 32), 0, out, 32, 32);
    out[64] = (byte) recId;
    return out;
  }

  /**
   * Reconstruct a {@link PrivateKey} from its raw 32-byte encoding.
   *
   * @param encoded 32 raw bytes of {@code d}, big-endian.
   */
  @Override
  public PrivateKey getPrivateKeyFromEncoded(byte[] encoded) {
    if (encoded == null || encoded.length != PRIVATE_KEY_SIZE) {
      throw new IllegalArgumentException(
          "secp256k1 private key must be "
              + PRIVATE_KEY_SIZE
              + " raw bytes; got "
              + (encoded == null ? "null" : encoded.length));
    }
    return new GenericPrivateKey(Bytes.wrap(encoded));
  }

  /**
   * Reconstruct a {@link PublicKey} from its raw 64-byte encoding.
   *
   * @param encoded 64 raw bytes formed as {@code X || Y} (uncompressed point, no {@code 0x04}
   *     prefix).
   */
  @Override
  public PublicKey getPublicKeyFromEncoded(byte[] encoded) {
    if (encoded == null || encoded.length != PUBLIC_KEY_SIZE) {
      throw new IllegalArgumentException(
          "secp256k1 public key must be "
              + PUBLIC_KEY_SIZE
              + " raw bytes; got "
              + (encoded == null ? "null" : encoded.length));
    }
    return new GenericPublicKey(Bytes.wrap(encoded));
  }

  // ---------- helpers ----------

  /** Serialize an {@link ECPoint} as 64 bytes (X || Y), uncompressed with the 0x04 prefix removed. */
  private static byte[] encodePublicKey(ECPoint q) {
    byte[] uncompressed = q.normalize().getEncoded(false); // 0x04 || X || Y, 65 bytes
    return Arrays.copyOfRange(uncompressed, 1, uncompressed.length);
  }

  /** Big-endian byte array of the requested fixed length, left-padded with zeros if needed. */
  private static byte[] toFixedLength(BigInteger value, int length) {
    byte[] raw = value.toByteArray();
    if (raw.length == length) {
      return raw;
    }
    if (raw.length == length + 1 && raw[0] == 0) {
      // Strip the leading sign byte that BigInteger.toByteArray adds for positive values whose
      // high bit is set.
      return Arrays.copyOfRange(raw, 1, raw.length);
    }
    if (raw.length > length) {
      throw new IllegalArgumentException("Value too large to fit into " + length + " bytes");
    }
    byte[] padded = new byte[length];
    System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
    return padded;
  }

  /**
   * ECDSA public key recovery, per SEC 1 v2.0 §4.1.6. Returns the candidate Q for the given
   * {@code recId}, or {@code null} if the candidate is invalid.
   */
  private static ECPoint recoverPoint(int recId, BigInteger r, BigInteger s, byte[] messageHash) {
    BigInteger n = CURVE.getN();
    BigInteger i = BigInteger.valueOf((long) recId / 2);
    BigInteger x = r.add(i.multiply(n));

    if (x.compareTo(CURVE_PRIME) >= 0) {
      return null;
    }

    ECPoint R = decompressKey(x, (recId & 1) == 1);
    if (!R.multiply(n).isInfinity()) {
      return null;
    }

    BigInteger e = new BigInteger(1, messageHash);
    BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
    BigInteger rInv = r.modInverse(n);
    BigInteger srInv = rInv.multiply(s).mod(n);
    BigInteger eInvrInv = rInv.multiply(eInv).mod(n);

    ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);
    return q.normalize();
  }

  /** Reconstruct a curve point from its x-coordinate and the parity of its y-coordinate. */
  private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
    X9IntegerConverter x9 = new X9IntegerConverter();
    byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
    compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
    return CURVE.getCurve().decodePoint(compEnc);
  }
}

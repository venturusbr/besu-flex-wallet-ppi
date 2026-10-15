package br.org.venturus.flexwallet.crypto;

import java.util.function.Supplier;

/**
 * Elliptic curve used to sign plain {@code EIP1559} transactions. It must match the genesis
 * {@code ecCurve} of the target network: Besu recovers the sender on that curve, so a signature
 * made on another curve is either rejected or attributed to a meaningless sender address.
 */
public enum EcCurve {
  SECP256K1("secp256k1", Secp256k1::new),
  SECP256R1("secp256r1", Secp256r1::new);

  public static final EcCurve DEFAULT = SECP256K1;

  private final String cliName;
  private final Supplier<AbstractSecp256> algorithm;

  EcCurve(String cliName, Supplier<AbstractSecp256> algorithm) {
    this.cliName = cliName;
    this.algorithm = algorithm;
  }

  public String cliName() {
    return cliName;
  }

  public AbstractSecp256 createAlgorithm() {
    return algorithm.get();
  }

  /** Case-insensitive lookup by CLI name. */
  public static EcCurve fromCliName(String name) {
    for (EcCurve curve : values()) {
      if (curve.cliName.equalsIgnoreCase(name)) {
        return curve;
      }
    }
    throw new IllegalArgumentException(
        "Unsupported --ecCurve value: " + name + " (expected one of " + cliNames() + ")");
  }

  /** Comma-separated list of valid CLI names, for help and error messages. */
  public static String cliNames() {
    StringBuilder sb = new StringBuilder();
    for (EcCurve curve : values()) {
      if (sb.length() > 0) sb.append(", ");
      sb.append(curve.cliName);
    }
    return sb.toString();
  }
}

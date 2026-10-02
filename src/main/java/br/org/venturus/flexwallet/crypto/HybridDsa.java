package br.org.venturus.flexwallet.crypto;

import java.util.function.Supplier;

/**
 * Hybrid DSA combinations available for {@code FlexibleEIP1559} transactions. Each entry maps
 * the name used on the command line to the {@code dsaType} id expected by the modified Besu and
 * to the {@link NestedHybridDSA} that produces its signatures. Secp256k1 always comes first so
 * Besu can recover its public key; the transaction carries only the PQC public key.
 */
public enum HybridDsa {
  SECP256K1_MLDSA44("SECP256K1-MLDSA44", (short) 0x0060, 1312, MLDSA::new),
  SECP256K1_FALCON512("SECP256K1-FALCON512", (short) 0x0070, 896, Falcon::new);

  public static final HybridDsa DEFAULT = SECP256K1_MLDSA44;

  private final String cliName;
  private final short dsaType;
  private final int pqcPublicKeyLength;
  private final Supplier<DigitalSignatureAlgorithm> pqcAlgorithm;

  HybridDsa(
      String cliName,
      short dsaType,
      int pqcPublicKeyLength,
      Supplier<DigitalSignatureAlgorithm> pqcAlgorithm) {
    this.cliName = cliName;
    this.dsaType = dsaType;
    this.pqcPublicKeyLength = pqcPublicKeyLength;
    this.pqcAlgorithm = pqcAlgorithm;
  }

  public String cliName() {
    return cliName;
  }

  public short dsaType() {
    return dsaType;
  }

  /** Length of the PQC public key carried in the transaction. */
  public int pqcPublicKeyLength() {
    return pqcPublicKeyLength;
  }

  public DigitalSignatureAlgorithm createAlgorithm() {
    return new NestedHybridDSA(new Secp256k1(), pqcAlgorithm.get());
  }

  /** Case-insensitive lookup by CLI name. */
  public static HybridDsa fromCliName(String name) {
    for (HybridDsa dsa : values()) {
      if (dsa.cliName.equalsIgnoreCase(name)) {
        return dsa;
      }
    }
    throw new IllegalArgumentException(
        "Unsupported --hybridDsa value: " + name + " (expected one of " + cliNames() + ")");
  }

  /** Comma-separated list of valid CLI names, for help and error messages. */
  public static String cliNames() {
    StringBuilder sb = new StringBuilder();
    for (HybridDsa dsa : values()) {
      if (sb.length() > 0) sb.append(", ");
      sb.append(dsa.cliName);
    }
    return sb.toString();
  }
}

package br.org.venturus.flexwallet.crypto;

/**
 * ECDSA on secp256r1 (NIST P-256). Besu recovers the sender of a plain {@code EIP1559}
 * transaction on the genesis {@code ecCurve}, so networks with {@code "ecCurve": "secp256r1"}
 * (started with {@code --node-dsa SECP256R1}) need their transactions signed with this curve.
 */
public class Secp256r1 extends AbstractSecp256 {

  public Secp256r1() {
    super("secp256r1");
  }
}

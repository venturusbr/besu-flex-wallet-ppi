package br.org.venturus.flexwallet.crypto;

/** ECDSA on secp256k1, the curve of stock Ethereum and of Besu's default {@code ecCurve}. */
public class Secp256k1 extends AbstractSecp256 {

  public Secp256k1() {
    super("secp256k1");
  }
}

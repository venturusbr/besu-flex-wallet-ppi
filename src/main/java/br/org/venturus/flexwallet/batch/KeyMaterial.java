package br.org.venturus.flexwallet.batch;

import java.security.PrivateKey;

/** Holds the key material for a single sender: public key bytes embedded in the tx and private key used to sign it. */
public final class KeyMaterial {
  public final byte[] pubBytes;
  public final PrivateKey sk;

  public KeyMaterial(byte[] pubBytes, PrivateKey sk) {
    this.pubBytes = pubBytes;
    this.sk = sk;
  }
}

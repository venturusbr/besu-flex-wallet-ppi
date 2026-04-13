package br.org.venturus.flexwallet.crypto.key.types;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

public class CompositeKeyPair {
  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  public CompositeKeyPair(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = Objects.requireNonNull(privateKey);
    this.publicKey = Objects.requireNonNull(publicKey);
  }

  public PrivateKey getPrivate() {
    return privateKey;
  }

  public PublicKey getPublic() {
    return publicKey;
  }

  /**
   * Factory method for composite keys.
   */
  public static CompositeKeyPair of(PrivateKey privateKey, PublicKey publicKey) {
    return new CompositeKeyPair(privateKey, publicKey);
  }

  /**
   * Factory method for composite keys from two pairs.
   */
  public static CompositeKeyPair of(KeyPair first, KeyPair second) {
    return new CompositeKeyPair(
      CompositePrivateKey.create(first.getPrivate(), second.getPrivate()),
      CompositePublicKey.create(first.getPublic(), second.getPublic())
    );
  }

  public static CompositeKeyPair of(CompositeKeyPair first, CompositeKeyPair second) {
    return new CompositeKeyPair(
      CompositePrivateKey.create(first.getPrivate(), second.getPrivate()),
      CompositePublicKey.create(first.getPublic(), second.getPublic())
    );
  }
}

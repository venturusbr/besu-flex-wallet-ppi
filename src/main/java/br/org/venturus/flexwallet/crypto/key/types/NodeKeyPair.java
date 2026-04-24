package br.org.venturus.flexwallet.crypto.key.types;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

public class NodeKeyPair {
  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  public NodeKeyPair(PrivateKey privateKey, PublicKey publicKey) {
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
  public static NodeKeyPair of(PrivateKey privateKey, PublicKey publicKey) {
    return new NodeKeyPair(privateKey, publicKey);
  }

  /**
   * Factory method for composite keys from two pairs.
   */
  public static NodeKeyPair of(KeyPair first, KeyPair second) {
    return new NodeKeyPair(
      CompositePrivateKey.create(first.getPrivate(), second.getPrivate()),
      CompositePublicKey.create(first.getPublic(), second.getPublic())
    );
  }

  public static NodeKeyPair of(NodeKeyPair first, NodeKeyPair second) {
    return new NodeKeyPair(
      CompositePrivateKey.create(first.getPrivate(), second.getPrivate()),
      CompositePublicKey.create(first.getPublic(), second.getPublic())
    );
  }
}

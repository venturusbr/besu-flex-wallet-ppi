package br.org.venturus.flexwallet.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;

public interface DigitalSignatureAlgorithm {
  NodeKeyPair generateKeyPair();
  byte[] sign(byte[] data, PrivateKey privateKey);
  PrivateKey getPrivateKeyFromEncoded(byte[] encoded);
  PublicKey getPublicKeyFromEncoded(byte[] encoded);
}

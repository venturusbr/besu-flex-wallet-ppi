package br.org.venturus.flexwallet.crypto.key.types;

import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;

public class GenericPrivateKey implements PrivateKey {
  private final Bytes encoded;

  public GenericPrivateKey(final Bytes encoded){
    this.encoded = encoded;
  }

  @Override
  public String getAlgorithm() {
    // TODO Auto-generated method stub
    throw new UnsupportedOperationException("Unimplemented method 'getAlgorithm'");
  }

  @Override
  public byte[] getEncoded() {
    return encoded.toArrayUnsafe();
  }

  @Override
  public String getFormat() {
    // TODO Auto-generated method stub
    throw new UnsupportedOperationException("Unimplemented method 'getFormat'");
  }

}

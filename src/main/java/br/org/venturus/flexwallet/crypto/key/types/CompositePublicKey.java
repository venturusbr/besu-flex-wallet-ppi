package br.org.venturus.flexwallet.crypto.key.types;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;

public class CompositePublicKey implements PublicKey{
  private final PublicKey firstKey;
  private final PublicKey secondKey;

  public CompositePublicKey(final PublicKey firstKey, final PublicKey secondKey){
    this.firstKey = firstKey;
    this.secondKey = secondKey;
  }

  public PublicKey getFirstKey(){
    return firstKey;
  }

  public PublicKey getSecondKey(){
    return secondKey;
  }

  @Override
  public String getAlgorithm(){
    return firstKey.getAlgorithm() + "-" + secondKey.getAlgorithm();
  }

  @Override
  public String getFormat(){
    return "concatenated";
  }

  @Override
  public byte[] getEncoded(){
    return Bytes.concatenate(
      Bytes.wrap(firstKey.getEncoded()),
      Bytes.wrap(secondKey.getEncoded())
    ).toArrayUnsafe();
  }

  public static CompositePublicKey create(final PublicKey firstPk, final PublicKey secondPk){
    return new CompositePublicKey(firstPk, secondPk);
  }
}

package br.org.venturus.flexwallet.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.web3j.crypto.AccessListObject;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Numeric;

import org.apache.tuweni.bytes.Bytes;

public class Transaction {
  private long chainId;
  private BigInteger nonce;
  private BigInteger gasLimit;
  private Short dsaType;
  private String to;
  private BigInteger value;
  private String data;
  private BigInteger maxPriorityFeePerGas;
  private BigInteger maxFeePerGas;
  private List<AccessListObject> accessList = Collections.emptyList();
  private byte[] publicKey;
  private Optional<byte[]> signature;

  private Transaction(Builder builder) {
    this.dsaType = builder.dsaType;
    this.chainId = builder.chainId;
    this.nonce = builder.nonce;
    this.maxPriorityFeePerGas = builder.maxPriorityFeePerGas;
    this.maxFeePerGas = builder.maxFeePerGas;
    this.gasLimit = builder.gasLimit;
    this.to = builder.to;
    this.value = builder.value;
    this.data = Numeric.toHexString(builder.data.getBytes());
    this.publicKey = builder.publicKey;
    this.signature = Optional.empty();
    if (builder.accessList != null) {
      this.accessList = builder.accessList;
    }
  }

  public long getChainId()                    { return chainId; }
  public BigInteger getNonce()                { return nonce; }
  public BigInteger getMaxPriorityFeePerGas() { return maxPriorityFeePerGas; }
  public BigInteger getMaxFeePerGas()         { return maxFeePerGas; }
  public BigInteger getGasLimit()             { return gasLimit; }
  public String getTo()                       { return to; }
  public BigInteger getValue()                { return value; }
  public String getData()                     { return data; }

  public static class Builder {
    private Short dsaType;
    private long chainId;
    private BigInteger nonce;
    private String to;
    private BigInteger value;
    private String data = "";
    private BigInteger gasLimit;
    private BigInteger maxPriorityFeePerGas;
    private BigInteger maxFeePerGas;
    private List<AccessListObject> accessList = Collections.emptyList();
    private byte[] publicKey;

    public Builder dsaType(Short dsaType) {
      this.dsaType = dsaType;
      return this;
    }
    public Builder chainId(long chainId) {
      this.chainId = chainId;
      return this;
    }
    public Builder nonce(BigInteger nonce) {
      this.nonce = nonce;
      return this;
    }
    public Builder to(String to) {
      this.to = to;
      return this;
    }
    public Builder value(BigInteger value) {
      this.value = value;
      return this;
    }
    public Builder data(String data) {
      this.data = data;
      return this;
    }
    public Builder gasLimit(BigInteger gasLimit) {
      this.gasLimit = gasLimit;
      return this;
    }
    public Builder maxPriorityFeePerGas(BigInteger maxPriorityFeePerGas) {
      this.maxPriorityFeePerGas = maxPriorityFeePerGas;
      return this;
    }
    public Builder maxFeePerGas(BigInteger maxFeePerGas) {
      this.maxFeePerGas = maxFeePerGas;
      return this;
    }
    public Builder accessList(List<AccessListObject> accessList) {
      this.accessList = accessList;
      return this;
    }
    public Builder publicKey(byte[] publicKey) {
      this.publicKey = publicKey;
      return this;
    }
    public Transaction build() {
      return new Transaction(this);
    }
  }

  public void setSignature(Optional<byte[]> signature) {
    this.signature = signature;
  }

  public Optional<byte[]> getSignature() {
    return signature;
  }

  public byte[] toByteArray() throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(bos);
    oos.writeObject(dsaType);
    oos.writeObject(chainId);
    oos.writeObject(nonce);
    oos.writeObject(maxPriorityFeePerGas);
    oos.writeObject(maxFeePerGas);
    oos.writeObject(gasLimit);
    oos.writeObject(to);
    oos.writeObject(value);
    oos.writeObject(data);
    oos.writeObject(accessList);
    oos.writeObject(publicKey);
    oos.flush();
    return bos.toByteArray();
  }

  public String toHexString() {
    StringBuilder sb = new StringBuilder();
    sb.append(dsaType);
    sb.append(Numeric.toHexStringWithPrefix(BigInteger.valueOf(chainId)));
    sb.append(Numeric.toHexStringWithPrefix(nonce));
    sb.append(Numeric.toHexStringWithPrefix(maxPriorityFeePerGas));
    sb.append(Numeric.toHexStringWithPrefix(maxFeePerGas));
    sb.append(Numeric.toHexStringWithPrefix(gasLimit));
    sb.append(to);
    sb.append(Numeric.toHexStringWithPrefix(value));
    sb.append(data);
    if (signature.isPresent()) {
      sb.append(Numeric.toHexString(signature.get()));
    }
    return sb.toString();
  }

  public List<RlpType> asRlpValues(Optional<byte[]> signature) {
    List<RlpType> result = new ArrayList<>();
    result.add(RlpString.create(
        Bytes.ofUnsignedShort(dsaType).toArray()
    ));
    result.add(RlpString.create(chainId));
    result.add(RlpString.create(nonce));
    result.add(RlpString.create(maxPriorityFeePerGas));
    result.add(RlpString.create(maxFeePerGas));
    result.add(RlpString.create(gasLimit));
    if (to != null && to.length() > 0) {
      result.add(RlpString.create(Numeric.hexStringToByteArray(to)));
    } else {
      result.add(RlpString.create(""));
    }
    result.add(RlpString.create(value));
    byte[] payload = Numeric.hexStringToByteArray(data);
    result.add(RlpString.create(payload));
    result.add(new RlpList(rlpAccessList()));
    result.add(RlpString.create(publicKey));
    if (signature.isPresent()) {
      result.add(RlpString.create(signature.get()));
    }
    return result;
  }

  public List<RlpType> rlpAccessList() {
    List<RlpType> rlpAccessList = new ArrayList<>();
    accessList.forEach(
        entry -> {
          List<RlpType> rlpAccessListObject = new ArrayList<>();
          rlpAccessListObject.add(
              RlpString.create(Numeric.hexStringToByteArray(entry.getAddress())));
          List<RlpType> keyList = new ArrayList<>();
          entry.getStorageKeys()
              .forEach(
                  key -> {
                    keyList.add(
                        RlpString.create(
                            Numeric.hexStringToByteArray(key)));
                  });
          rlpAccessListObject.add(new RlpList(keyList));
          rlpAccessList.add(new RlpList(rlpAccessListObject));
        });
    return rlpAccessList;
  }
}

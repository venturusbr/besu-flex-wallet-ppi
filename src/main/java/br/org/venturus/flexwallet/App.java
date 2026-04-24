package br.org.venturus.flexwallet;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.web3j.utils.Convert;

import br.org.venturus.flexwallet.crypto.DigitalSignatureAlgorithm;
import br.org.venturus.flexwallet.crypto.NestedHybridDSA;
import br.org.venturus.flexwallet.crypto.Secp256k1;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;
import br.org.venturus.flexwallet.crypto.MLDSA;
import br.org.venturus.flexwallet.model.Transaction;
import br.org.venturus.flexwallet.model.encoder.EIP1559Encoder;
import br.org.venturus.flexwallet.request.EthSendRawTransaction;
import br.org.venturus.flexwallet.utils.FileUtils;

public class App {
  public static void main(String[] args) {
    try {
      // Register the PQC provider if it is not already registered
      if (Security.getProvider("BCPQC") == null) {
        Security.addProvider(new BouncyCastlePQCProvider());
      }

      boolean shouldGenerateKeys = false;

      // Checks if the --generateKeys flag is present
      for (String arg : args) {
        if (arg.equalsIgnoreCase("--generateKeys")) {
          shouldGenerateKeys = true;
          break;
        }
      }

      // Only write the keys once, if the file doesn't already exist
      FileUtils fileUtils = new FileUtils();
      Path keyFile = fileUtils.getFilePath();
      DigitalSignatureAlgorithm signatureAlgorithm = new NestedHybridDSA(new Secp256k1(), new MLDSA());

      // Generates the key only if the flag is present or the file does not exist
      if (shouldGenerateKeys || !Files.exists(keyFile)) {
        NodeKeyPair keyPair = signatureAlgorithm.generateKeyPair();
        fileUtils.writeKeys(keyPair);
        System.out.println("Generated new keys. File Path: " + keyFile);
      }

      // Read the keys back from the file (PEM → Base64)
      String[] keys = fileUtils.readKeys();
      byte[] pubBytes = Base64.getDecoder().decode(keys[0]);
      byte[] privBytes = Base64.getDecoder().decode(keys[1]);

      PrivateKey sk;

      if (signatureAlgorithm instanceof NestedHybridDSA) {
        if (keys.length != 4) {
          throw new UnsupportedOperationException(
              "When using a nested hybrid digital signature algorithm, 2 key pairs are expected.");
        }

        byte[] secondPubBytes = Base64.getDecoder().decode(keys[2]);
        byte[] secondPrivBytes = Base64.getDecoder().decode(keys[3]);

        // Caso SECP256K1/MLDSA: o primeiro algoritmo suporta PKR e o segundo não. Enviar PK do segundo.
        pubBytes = secondPubBytes;

        sk = ((NestedHybridDSA) signatureAlgorithm).getPrivateKeyFromEncoded(privBytes, secondPrivBytes);
      } else {
        sk = signatureAlgorithm.getPrivateKeyFromEncoded(privBytes);
      }

      // Build the unsigned transaction using the builder
      Transaction unsignedTransaction = new Transaction.Builder()
        .dsaType((short) 0x0060)
        .chainId(381660666L)
        .nonce(BigInteger.ZERO)
        .to("0xf17f52151EbEF6C7334FAD080c5704D77216b732")
        .value(Convert.toWei("0", Convert.Unit.ETHER).toBigInteger())
        .data("")
        .gasLimit(BigInteger.valueOf(1_000_000))
        .maxPriorityFeePerGas(BigInteger.ZERO)
        .maxFeePerGas(BigInteger.ZERO)
        .publicKey(pubBytes)
        .build();

      // Sign and send the transaction
      EIP1559Encoder encoder = new EIP1559Encoder(signatureAlgorithm);
      byte[] rawTransaction = encoder.createRawTransaction(unsignedTransaction, sk);
      String tx = "0x" + EIP1559Encoder.bytesToHex(rawTransaction);
      EthSendRawTransaction.send(tx);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

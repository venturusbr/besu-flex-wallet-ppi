package br.org.venturus.flexwallet;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.web3j.utils.Convert;

import br.org.venturus.flexwallet.batch.BatchRunner;
import br.org.venturus.flexwallet.batch.KeyMaterial;
import br.org.venturus.flexwallet.cli.CliArgs;
import br.org.venturus.flexwallet.cli.Usage;
import br.org.venturus.flexwallet.crypto.DigitalSignatureAlgorithm;
import br.org.venturus.flexwallet.crypto.MLDSA;
import br.org.venturus.flexwallet.crypto.NestedHybridDSA;
import br.org.venturus.flexwallet.crypto.Secp256k1;
import br.org.venturus.flexwallet.crypto.key.types.CompositePrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.CompositePublicKey;
import br.org.venturus.flexwallet.crypto.key.types.GenericPrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;
import br.org.venturus.flexwallet.model.Transaction;
import br.org.venturus.flexwallet.model.encoder.EIP1559Encoder;
import br.org.venturus.flexwallet.model.encoder.FlexibleEIP1559Encoder;
import br.org.venturus.flexwallet.request.EthSendRawTransaction;
import br.org.venturus.flexwallet.utils.FileUtils;

/**
 * Slim entry point. Resolves CLI arguments, sets up the BC providers, loads (or generates) the
 * key material, and dispatches to either the original single-tx path or the {@link BatchRunner}.
 */
public class App {
  // DSA mode constants — extend as needed
  private static final String MODE_HYBRID  = "FlexibleEIP1559"; // default
  private static final String MODE_LEGACY  = "EIP1559";           // standard secp256k1 only

  public static void main(String[] args) {
    // --help short-circuits all setup so that calling it on a misconfigured environment
    // (missing key file, no provider, etc.) still prints usage instead of crashing.
    if (CliArgs.hasHelpFlag(args)) {
      Usage.print();
      return;
    }

    try {
      CliArgs cli = CliArgs.parse(args);

      registerPqcProvider();

      boolean legacyMode = MODE_LEGACY.equalsIgnoreCase(cli.dsaMode()); // new CLI flag --dsa-mode

      if (legacyMode) {
        runLegacy(cli);
      } else {
        runHybrid(cli);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // -----------------------------------------------------------------------------------------
  // Provider + key setup
  // -----------------------------------------------------------------------------------------

  private static void registerPqcProvider() {
    if (Security.getProvider("BCPQC") == null) {
      Security.addProvider(new BouncyCastlePQCProvider());
    }
  }

  private static void runLegacy(CliArgs cli) throws Exception {
    Secp256k1 secp256k1 = new Secp256k1();
    EIP1559Encoder encoder = new EIP1559Encoder(!cli.batchMode());

    if (cli.batchMode()) {
      KeyMaterial[] keyMaterials = generateLegacyKeyMaterials(cli.txAmount(), secp256k1);
      new BatchRunner(cli, keyMaterials, encoder).run();
    } else {
      LoadedKeys keys = loadOrGenerateLegacyKeys(cli.generateKeys(), secp256k1);
      sendLegacyTransaction(encoder, keys, cli.singleEndpoint());
    }
  }
  private static LoadedKeys loadOrGenerateLegacyKeys(
      boolean forceRegenerate, Secp256k1 secp256k1) throws Exception {
    FileUtils fileUtils = new FileUtils();
    Path keyFile = fileUtils.getFilePath();
 
    if (forceRegenerate || !Files.exists(keyFile)) {
      NodeKeyPair keyPair = secp256k1.generateKeyPair();
      fileUtils.writeKeys(keyPair);
      System.out.println("Generated new secp256k1 keys. File Path: " + keyFile);
    }
 
    String[] keys = fileUtils.readKeys();
    byte[] pubBytes  = Base64.getDecoder().decode(keys[0]);
    byte[] privBytes = Base64.getDecoder().decode(keys[1]);
    PrivateKey sk = new GenericPrivateKey(Bytes.wrap(privBytes));
    return new LoadedKeys(pubBytes, sk);
  }
 
  private static void sendLegacyTransaction(
      EIP1559Encoder encoder, LoadedKeys keys, String endpoint) throws Exception {
    Transaction unsignedTransaction =
        new Transaction.Builder()
            .chainId(381660666L)
            .nonce(BigInteger.ZERO)
            .to("0xf17f52151EbEF6C7334FAD080c5704D77216b732")
            .value(Convert.toWei("0", Convert.Unit.ETHER).toBigInteger())
            .data("")
            .gasLimit(BigInteger.valueOf(1_000_000))
            .maxPriorityFeePerGas(BigInteger.ZERO)
            .maxFeePerGas(BigInteger.ZERO)
            // NOTE: dsaType and publicKey are intentionally omitted for legacy transactions
            .build();
 
    byte[] raw = encoder.createRawTransaction(unsignedTransaction, keys.sk);
    String tx = "0x" + FlexibleEIP1559Encoder.bytesToHex(raw);
    EthSendRawTransaction.send(tx, endpoint, true);
  }
 
  // -----------------------------------------------------------------------------------------
  // Hybrid SECP256K1-MLDSA44 (PQC, existing path)
  // -----------------------------------------------------------------------------------------
 
  private static void runHybrid(CliArgs cli) throws Exception {
    DigitalSignatureAlgorithm signatureAlgorithm =
        new NestedHybridDSA(new Secp256k1(), new MLDSA());

    FlexibleEIP1559Encoder encoder = new FlexibleEIP1559Encoder(signatureAlgorithm, !cli.batchMode());

    if (cli.batchMode()) {
      KeyMaterial[] keyMaterials = generateHybridKeyMaterials(cli.txAmount(), signatureAlgorithm);
      new BatchRunner(cli, keyMaterials, encoder).run();
    } else {
      LoadedKeys keys = loadOrGenerateHybridKeys(cli.generateKeys(), signatureAlgorithm);
      printKeyLengths(keys);
      sendHybridTransaction(encoder, keys, cli.singleEndpoint());
    }
  }

  private static KeyMaterial[] generateLegacyKeyMaterials(int n, Secp256k1 secp256k1) {
    System.out.println("Generating " + n + " secp256k1 key pairs in memory...");
    KeyMaterial[] materials = new KeyMaterial[n];
    for (int i = 0; i < n; i++) {
      NodeKeyPair kp = secp256k1.generateKeyPair();
      materials[i] = new KeyMaterial(kp.getPublic().getEncoded(), kp.getPrivate());
    }
    System.out.println("Key generation complete.");
    return materials;
  }

  private static KeyMaterial[] generateHybridKeyMaterials(int n, DigitalSignatureAlgorithm alg) {
    System.out.println("Generating " + n + " hybrid (secp256k1+ML-DSA) key pairs in memory...");
    KeyMaterial[] materials = new KeyMaterial[n];
    for (int i = 0; i < n; i++) {
      NodeKeyPair kp = alg.generateKeyPair();
      // Second key is ML-DSA; its encoded public bytes go in the tx field.
      // The composite private key (secp256k1 + ML-DSA) signs the transaction.
      byte[] pubBytes = ((CompositePublicKey) kp.getPublic()).getSecondKey().getEncoded();
      materials[i] = new KeyMaterial(pubBytes, kp.getPrivate());
      if ((i + 1) % 500 == 0) {
        System.out.println("  " + (i + 1) + "/" + n + " key pairs generated");
      }
    }
    System.out.println("Key generation complete.");
    return materials;
  }
 
  private static LoadedKeys loadOrGenerateHybridKeys(
      boolean forceRegenerate, DigitalSignatureAlgorithm signatureAlgorithm) throws Exception {
    FileUtils fileUtils = new FileUtils();
    Path keyFile = fileUtils.getFilePath();
 
    if (forceRegenerate || !Files.exists(keyFile)) {
      NodeKeyPair keyPair = signatureAlgorithm.generateKeyPair();
      fileUtils.writeKeys(keyPair);
      System.out.println("Generated new keys. File Path: " + keyFile);
    }
 
    String[] keys = fileUtils.readKeys();
    byte[] pubBytes  = Base64.getDecoder().decode(keys[0]);
    byte[] privBytes = Base64.getDecoder().decode(keys[1]);
    PrivateKey sk;
 
    if (keys.length != 4) {
      throw new UnsupportedOperationException(
          "When using a nested hybrid digital signature algorithm, 2 key pairs are expected.");
    }
    byte[] secondPubBytes  = Base64.getDecoder().decode(keys[2]);
    byte[] secondPrivBytes = Base64.getDecoder().decode(keys[3]);
 
    pubBytes = secondPubBytes;
    sk = CompositePrivateKey.create(
        new GenericPrivateKey(Bytes.wrap(privBytes)),
        new GenericPrivateKey(Bytes.wrap(secondPrivBytes)));
 
    return new LoadedKeys(pubBytes, sk);
  }
 
  private static void sendHybridTransaction(
      FlexibleEIP1559Encoder encoder, LoadedKeys keys, String endpoint) throws Exception {
    Transaction unsignedTransaction =
        new Transaction.Builder()
            .dsaType((short) 0x0060)
            .chainId(381660666L)
            .nonce(BigInteger.ZERO)
            .to("0xf17f52151EbEF6C7334FAD080c5704D77216b732")
            .value(Convert.toWei("0", Convert.Unit.ETHER).toBigInteger())
            .data("")
            .gasLimit(BigInteger.valueOf(1_000_000))
            .maxPriorityFeePerGas(BigInteger.ZERO)
            .maxFeePerGas(BigInteger.ZERO)
            .publicKey(keys.pubBytes)
            .build();
 
    byte[] raw = encoder.createRawTransaction(unsignedTransaction, keys.sk);
    String tx = "0x" + FlexibleEIP1559Encoder.bytesToHex(raw);
    EthSendRawTransaction.send(tx, endpoint, true);
  }

  /**
   * Load existing keys from disk or generate fresh ones. Mirrors the original main()'s behavior
   * verbatim — the NestedHybridDSA branch expects four base64-encoded entries (pub, priv, pub2,
   * priv2) and stitches the two private keys into a {@link CompositePrivateKey}.
   */
  private static LoadedKeys loadOrGenerateKeys(
      boolean forceRegenerate, DigitalSignatureAlgorithm signatureAlgorithm) throws Exception {
    FileUtils fileUtils = new FileUtils();
    Path keyFile = fileUtils.getFilePath();

    if (forceRegenerate || !Files.exists(keyFile)) {
      NodeKeyPair keyPair = signatureAlgorithm.generateKeyPair();
      fileUtils.writeKeys(keyPair);
      System.out.println("Generated new keys. File Path: " + keyFile);
    }

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

      // In SECP256K1/MLDSA: the first algorithm supports PKR, the second doesn't. Send the
      // public key of the second one downstream.
      pubBytes = secondPubBytes;

      sk =
          CompositePrivateKey.create(
              new GenericPrivateKey(Bytes.wrap(privBytes)),
              new GenericPrivateKey(Bytes.wrap(secondPrivBytes)));
    } else {
      sk = new GenericPrivateKey(Bytes.wrap(privBytes));
    }
    return new LoadedKeys(pubBytes, sk);
  }

  private static void printKeyLengths(LoadedKeys keys) {
    System.out.println("~~~~~~~~~~~~~~~~~~ Public key length ~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    System.out.println(keys.pubBytes.length);
    System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

    System.out.println("~~~~~~~~~~~~~~~~~~ Secret key length ~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    System.out.println(keys.sk.getEncoded().length);
    System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
  }

  // -----------------------------------------------------------------------------------------
  // Single-tx path
  // -----------------------------------------------------------------------------------------

  private static void sendSingleTransaction(FlexibleEIP1559Encoder encoder, LoadedKeys keys, String endpoint)
      throws Exception {
    Transaction unsignedTransaction =
        new Transaction.Builder()
            .dsaType((short) 0x0060)
            .chainId(381660666L)
            .nonce(BigInteger.ZERO)
            .to("0xf17f52151EbEF6C7334FAD080c5704D77216b732")
            .value(Convert.toWei("0", Convert.Unit.ETHER).toBigInteger())
            .data("")
            .gasLimit(BigInteger.valueOf(1_000_000))
            .maxPriorityFeePerGas(BigInteger.ZERO)
            .maxFeePerGas(BigInteger.ZERO)
            .publicKey(keys.pubBytes)
            .build();

    byte[] raw = encoder.createRawTransaction(unsignedTransaction, keys.sk);
    String tx = "0x" + FlexibleEIP1559Encoder.bytesToHex(raw);
    EthSendRawTransaction.send(tx, endpoint, true);
  }

  /** Trivial holder so we can return the loaded public bytes and secret key together. */
  private static final class LoadedKeys {
    final byte[] pubBytes;
    final PrivateKey sk;

    LoadedKeys(byte[] pubBytes, PrivateKey sk) {
      this.pubBytes = pubBytes;
      this.sk = sk;
    }
  }
}

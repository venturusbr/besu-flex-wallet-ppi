package br.org.venturus.flexwallet;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.web3j.utils.Convert;

import br.org.venturus.flexwallet.batch.BatchRunner;
import br.org.venturus.flexwallet.batch.KeyMaterial;
import br.org.venturus.flexwallet.cli.CliArgs;
import br.org.venturus.flexwallet.cli.Usage;
import br.org.venturus.flexwallet.crypto.AbstractSecp256;
import br.org.venturus.flexwallet.crypto.DigitalSignatureAlgorithm;
import br.org.venturus.flexwallet.crypto.HybridDsa;
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
  // Tx type constants — extend as needed
  private static final String TX_HYBRID = "FlexibleEIP1559";  // hybrid, see --hybridDsa
  private static final String TX_LEGACY = "EIP1559";          // plain ECDSA, see --ecCurve

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

      boolean isLegacyMode = TX_LEGACY.equalsIgnoreCase(cli.txType()); // CLI flag --txType EIP1559

      if (isLegacyMode) {
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
    AbstractSecp256 ecdsa = cli.ecCurve().createAlgorithm();
    System.out.println("EIP1559 signing curve: " + ecdsa.curveName());
    EIP1559Encoder encoder = new EIP1559Encoder(ecdsa, !cli.batchMode());

    if (cli.batchMode()) {
      KeyMaterial[] keyMaterials = generateLegacyKeyMaterials(cli.txAmount(), ecdsa);
      new BatchRunner(cli, keyMaterials, encoder).run();
    } else {
      LoadedKeys keys = loadOrGenerateLegacyKeys(cli.generateKeys(), ecdsa);
      System.out.println("Sender address: " + AbstractSecp256.address(keys.pubBytes));
      sendLegacyTransaction(encoder, keys, cli.singleEndpoint());
    }
  }
  private static LoadedKeys loadOrGenerateLegacyKeys(
      boolean forceRegenerate, AbstractSecp256 ecdsa) throws Exception {
    FileUtils fileUtils = new FileUtils();
    Path keyFile = fileUtils.getFilePath();

    if (forceRegenerate || !Files.exists(keyFile)) {
      NodeKeyPair keyPair = ecdsa.generateKeyPair();
      fileUtils.writeKeys(keyPair);
      System.out.println("Generated new " + ecdsa.curveName() + " keys. File Path: " + keyFile);
    }

    String[] keys = fileUtils.readKeys();
    byte[] pubBytes  = Base64.getDecoder().decode(keys[0]);
    byte[] privBytes = Base64.getDecoder().decode(keys[1]);
    PrivateKey sk = new GenericPrivateKey(Bytes.wrap(privBytes));

    // The same 32-byte scalar is a valid key on either curve, but with another public key and
    // address, so a key file generated for another curve (or a hybrid DSA) must not be reused.
    if (keys.length != 2 || !Arrays.equals(pubBytes, ecdsa.publicKeyOf(sk))) {
      throw new IllegalStateException(
          "Key file " + keyFile + " does not hold a " + ecdsa.curveName()
              + " key pair. It was likely generated for another --ecCurve or for"
              + " FlexibleEIP1559; rerun with --generateKeys.");
    }
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
  // Hybrid SECP256K1 + PQC (ML-DSA-44 or Falcon-512, chosen by --hybridDsa)
  // -----------------------------------------------------------------------------------------

  private static void runHybrid(CliArgs cli) throws Exception {
    HybridDsa hybridDsa = cli.hybridDsa();
    DigitalSignatureAlgorithm signatureAlgorithm = hybridDsa.createAlgorithm();
    System.out.println("Hybrid DSA: " + hybridDsa.cliName()
        + String.format(" (dsaType 0x%04x)", hybridDsa.dsaType()));

    FlexibleEIP1559Encoder encoder = new FlexibleEIP1559Encoder(signatureAlgorithm, !cli.batchMode());

    if (cli.batchMode()) {
      KeyMaterial[] keyMaterials = generateHybridKeyMaterials(cli.txAmount(), hybridDsa, signatureAlgorithm);
      new BatchRunner(cli, keyMaterials, encoder).run();
    } else {
      LoadedKeys keys = loadOrGenerateHybridKeys(cli.generateKeys(), hybridDsa, signatureAlgorithm);
      printKeyLengths(keys);
      sendHybridTransaction(encoder, hybridDsa, keys, cli.singleEndpoint());
    }
  }

  private static KeyMaterial[] generateLegacyKeyMaterials(int n, AbstractSecp256 ecdsa) {
    System.out.println("Generating " + n + " " + ecdsa.curveName() + " key pairs in memory...");
    KeyMaterial[] materials = new KeyMaterial[n];
    for (int i = 0; i < n; i++) {
      NodeKeyPair kp = ecdsa.generateKeyPair();
      materials[i] = new KeyMaterial(kp.getPublic().getEncoded(), kp.getPrivate());
    }
    System.out.println("Key generation complete.");
    return materials;
  }

  private static KeyMaterial[] generateHybridKeyMaterials(
      int n, HybridDsa hybridDsa, DigitalSignatureAlgorithm alg) {
    System.out.println(
        "Generating " + n + " hybrid (" + hybridDsa.cliName() + ") key pairs in memory...");
    KeyMaterial[] materials = new KeyMaterial[n];
    for (int i = 0; i < n; i++) {
      NodeKeyPair kp = alg.generateKeyPair();
      // Second key is the PQC one; its encoded public bytes go in the tx field.
      // The composite private key (secp256k1 + PQC) signs the transaction.
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
      boolean forceRegenerate, HybridDsa hybridDsa, DigitalSignatureAlgorithm signatureAlgorithm)
      throws Exception {
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

    if (secondPubBytes.length != hybridDsa.pqcPublicKeyLength()) {
      throw new IllegalStateException(
          "Key file " + keyFile + " holds a " + secondPubBytes.length + "-byte PQC public key, but "
              + hybridDsa.cliName() + " expects " + hybridDsa.pqcPublicKeyLength()
              + " bytes. It was likely generated for another --hybridDsa; rerun with --generateKeys.");
    }

    pubBytes = secondPubBytes;
    sk = CompositePrivateKey.create(
        new GenericPrivateKey(Bytes.wrap(privBytes)),
        new GenericPrivateKey(Bytes.wrap(secondPrivBytes)));

    return new LoadedKeys(pubBytes, sk);
  }

  private static void sendHybridTransaction(
      FlexibleEIP1559Encoder encoder, HybridDsa hybridDsa, LoadedKeys keys, String endpoint)
      throws Exception {
    Transaction unsignedTransaction =
        new Transaction.Builder()
            .dsaType(hybridDsa.dsaType())
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

  private static void printKeyLengths(LoadedKeys keys) {
    System.out.println("~~~~~~~~~~~~~~~~~~ Public key length ~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    System.out.println(keys.pubBytes.length);
    System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

    System.out.println("~~~~~~~~~~~~~~~~~~ Secret key length ~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    System.out.println(keys.sk.getEncoded().length);
    System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
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

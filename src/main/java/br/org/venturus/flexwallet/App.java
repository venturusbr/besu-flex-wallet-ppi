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
import br.org.venturus.flexwallet.cli.CliArgs;
import br.org.venturus.flexwallet.cli.Usage;
import br.org.venturus.flexwallet.crypto.DigitalSignatureAlgorithm;
import br.org.venturus.flexwallet.crypto.MLDSA;
import br.org.venturus.flexwallet.crypto.NestedHybridDSA;
import br.org.venturus.flexwallet.crypto.Secp256k1;
import br.org.venturus.flexwallet.crypto.key.types.CompositePrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.GenericPrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;
import br.org.venturus.flexwallet.model.Transaction;
import br.org.venturus.flexwallet.model.encoder.EIP1559Encoder;
import br.org.venturus.flexwallet.request.EthSendRawTransaction;
import br.org.venturus.flexwallet.utils.FileUtils;

/**
 * Slim entry point. Resolves CLI arguments, sets up the BC providers, loads (or generates) the
 * key material, and dispatches to either the original single-tx path or the {@link BatchRunner}.
 */
public class App {

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

      DigitalSignatureAlgorithm signatureAlgorithm =
          new NestedHybridDSA(new Secp256k1(), new MLDSA());
      // DigitalSignatureAlgorithm signatureAlgorithm = new Secp256k1();
      // DigitalSignatureAlgorithm signatureAlgorithm = new Falcon();
      // DigitalSignatureAlgorithm signatureAlgorithm = new MLDSA();

      LoadedKeys keys = loadOrGenerateKeys(cli.generateKeys(), signatureAlgorithm);

      if (!cli.batchMode()) {
        printKeyLengths(keys);
      }

      EIP1559Encoder encoder = new EIP1559Encoder(signatureAlgorithm, !cli.batchMode());

      if (cli.batchMode()) {
        new BatchRunner(cli, keys.pubBytes, keys.sk, encoder).run();
      } else {
        sendSingleTransaction(encoder, keys, cli.singleEndpoint());
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

  private static void sendSingleTransaction(EIP1559Encoder encoder, LoadedKeys keys, String endpoint)
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
    String tx = "0x" + EIP1559Encoder.bytesToHex(raw);
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

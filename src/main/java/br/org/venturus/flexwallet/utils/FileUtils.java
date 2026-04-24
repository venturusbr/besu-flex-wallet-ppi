package br.org.venturus.flexwallet.utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import br.org.venturus.flexwallet.crypto.key.types.NodeKeyPair;
import br.org.venturus.flexwallet.crypto.key.types.CompositePrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.CompositePublicKey;

import java.nio.charset.StandardCharsets;
import java.io.IOException;

public class FileUtils {
  private final String directory;
  private final String fileName;

  // Default values
  private static final String DEFAULT_DIRECTORY = System.getProperty("user.home") + "/.besu-flex-wallet";
  private static final String DEFAULT_FILE_NAME = "keys.txt";

  // Constructor with optional parameters
  public FileUtils(String directory, String fileName) {
    this.directory = (directory == null || directory.isEmpty()) ? DEFAULT_DIRECTORY : directory;
    this.fileName = (fileName == null || fileName.isEmpty()) ? DEFAULT_FILE_NAME : fileName;
  }

  // Default constructor uses defaults
  public FileUtils() {
    this(null, null);
  }

  public Path getFilePath() {
    return Paths.get(directory, fileName);
  }

  public void createDirectory() throws IOException {
    Path dirPath = Paths.get(directory);
    if (!Files.exists(dirPath)) {
      Files.createDirectories(dirPath);
    }
  }

  /**
   * Writes the keys to the file. Supports both single and composite key pairs.
   */
  public void writeKeys(NodeKeyPair keyPair) throws IOException {
    createDirectory();

    StringBuilder stringBuilder = new StringBuilder();

    PublicKey pub1 = keyPair.getPublic();
    PrivateKey priv1 = keyPair.getPrivate();

    // Check if composite
    if (pub1 instanceof CompositePublicKey && priv1 instanceof CompositePrivateKey) {
      CompositePublicKey cpk = (CompositePublicKey) pub1;
      CompositePrivateKey csk = (CompositePrivateKey) priv1;

      appendSection("PUBLIC KEY", cpk.getFirstKey().getEncoded(), stringBuilder);
      appendSection("PRIVATE KEY", csk.getFirstKey().getEncoded(), stringBuilder);
      appendSection("SECOND PUBLIC KEY", cpk.getSecondKey().getEncoded(), stringBuilder);
      appendSection("SECOND PRIVATE KEY", csk.getSecondKey().getEncoded(), stringBuilder);
    } else {
      appendSection("PUBLIC KEY", pub1.getEncoded(), stringBuilder);
      appendSection("PRIVATE KEY", priv1.getEncoded(), stringBuilder);
    }

    Files.write(getFilePath(), stringBuilder.toString().getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Reads the file containing the keys and extracts the public and private keys.
   * Returns a String array:
   *   - [0]: publicKey
   *   - [1]: privateKey
   *   - [2]: secondPublicKey (if present)
   *   - [3]: secondPrivateKey (if present)
   */
  public String[] readKeys() throws IOException {
    Path filePath = getFilePath();
    if (!Files.exists(filePath)) {
      return new String[0];
    }
    String content = new String(Files.readAllBytes(filePath), StandardCharsets.UTF_8);

    String publicKey = extractKey(content, "PUBLIC KEY");
    String privateKey = extractKey(content, "PRIVATE KEY");
    String secondPublicKey = extractKey(content, "SECOND PUBLIC KEY");
    String secondPrivateKey = extractKey(content, "SECOND PRIVATE KEY");

    // If second keys are present, return all four
    if (!secondPublicKey.isEmpty() && !secondPrivateKey.isEmpty()) {
      return new String[]{publicKey, privateKey, secondPublicKey, secondPrivateKey};
    } else {
      return new String[]{publicKey, privateKey};
    }
  }

  private static void appendSection(String title, byte[] keyBytes, StringBuilder builder) {
    builder.append("-----BEGIN ").append(title).append("-----\n")
           .append(Base64.getEncoder().encodeToString(keyBytes))
           .append("\n-----END ").append(title).append("-----\n\n");
  }

  private static String extractKey(String content, String keyType) {
    String begin = "-----BEGIN " + keyType + "-----";
    String end = "-----END " + keyType + "-----";
    int start = content.indexOf(begin);
    int finish = content.indexOf(end);
    if (start != -1 && finish != -1) {
      return content.substring(start + begin.length(), finish).trim();
    }
    return "";
  }
}

package br.org.venturus.flexwallet.utils;

import br.org.venturus.flexwallet.crypto.key.types.CompositeKeyPair;
import br.org.venturus.flexwallet.crypto.key.types.CompositePrivateKey;
import br.org.venturus.flexwallet.crypto.key.types.CompositePublicKey;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.*;
import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

class FileUtilsTest {

  // Simple dummy key implementations for testing
  static class DummyPublicKey implements PublicKey {
    private final String name;

    DummyPublicKey(String name) {
      this.name = name;
    }

    @Override
    public String getAlgorithm() {
      return "DUMMY";
    }

    @Override
    public String getFormat() {
      return "X.509";
    }

    @Override
    public byte[] getEncoded() {
      return (name + "-pub").getBytes();
    }
  }

  static class DummyPrivateKey implements PrivateKey {
    private final String name;

    DummyPrivateKey(String name) {
      this.name = name;
    }

    @Override
    public String getAlgorithm() {
      return "DUMMY";
    }

    @Override
    public String getFormat() {
      return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
      return (name + "-priv").getBytes();
    }
  }

  @TempDir
  Path tempDir;

  private Path tempFile;

  @BeforeEach
  void setUp() throws IOException {
    tempFile = tempDir.resolve("keys.txt");
  }

  @AfterEach
  void tearDown() throws IOException {
    Files.deleteIfExists(tempFile);
    Files.deleteIfExists(tempDir);
  }

  @Test
  void testWriteAndReadSingleKeyPair() throws IOException {
    PublicKey pub = new DummyPublicKey("A");
    PrivateKey priv = new DummyPrivateKey("A");
    CompositeKeyPair kp = new CompositeKeyPair(priv, pub);

    FileUtils fileUtils = new FileUtils(tempDir.toString(), tempFile.getFileName().toString());
    fileUtils.writeKeys(kp);

    String[] keys = fileUtils.readKeys();
    assertEquals(2, keys.length);
    assertTrue(new String(pub.getEncoded()).contains("A-pub"));
    assertTrue(new String(priv.getEncoded()).contains("A-priv"));
    assertTrue(new String(java.util.Base64.getDecoder().decode(keys[0])).contains("A-pub"));
    assertTrue(new String(java.util.Base64.getDecoder().decode(keys[1])).contains("A-priv"));
  }

  @Test
  void testWriteAndReadCompositeKeyPair() throws IOException {
    PublicKey pub1 = new DummyPublicKey("A");
    PrivateKey priv1 = new DummyPrivateKey("A");
    PublicKey pub2 = new DummyPublicKey("B");
    PrivateKey priv2 = new DummyPrivateKey("B");

    CompositePublicKey cpub = new CompositePublicKey(pub1, pub2);
    CompositePrivateKey cpriv = new CompositePrivateKey(priv1, priv2);
    CompositeKeyPair kp = new CompositeKeyPair(cpriv, cpub);

    FileUtils fileUtils = new FileUtils(tempDir.toString(), tempFile.getFileName().toString());
    fileUtils.writeKeys(kp);

    String[] keys = fileUtils.readKeys();
    assertEquals(4, keys.length);
    assertTrue(new String(java.util.Base64.getDecoder().decode(keys[0])).contains("A-pub"));
    assertTrue(new String(java.util.Base64.getDecoder().decode(keys[1])).contains("A-priv"));
    assertTrue(new String(java.util.Base64.getDecoder().decode(keys[2])).contains("B-pub"));
    assertTrue(new String(java.util.Base64.getDecoder().decode(keys[3])).contains("B-priv"));
  }
}

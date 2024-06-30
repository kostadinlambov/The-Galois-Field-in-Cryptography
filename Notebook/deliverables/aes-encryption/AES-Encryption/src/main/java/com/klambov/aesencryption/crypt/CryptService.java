package com.klambov.aesencryption.crypt;

import jakarta.annotation.PostConstruct;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Implements AES (Advanced Encryption Standard) with Galois/Counter Mode (GCM), which is a mode of
 * operation for symmetric key cryptographic block ciphers that has been widely adopted because of
 * its efficiency and performance.
 * <p>
 * Every encryption produces a new 12 byte random Initialization Vector (IV) (see
 * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) because the
 * security of GCM depends choosing a unique initialization vector for every encryption performed
 * with the same key.
 * <p>
 * The iv, encrypted content and auth tag will be encoded to the following format:
 * <p>
 * out = byte[] {x y y y y y y y y y y y y z z z ...}
 * <p>
 * x = IV length as byte y = IV bytes z = content bytes (encrypted content, auth tag)
 * <p>
 * The library accepts 128, 192 or 256 bit keys
 */
@Service
public class CryptService {

  public static final String CRYPT_PREFIX = "$[[aescrypt]]$";

  private static final String ALGORITHM = "AES/GCM/NoPadding";
  private static final int TAG_LENGTH_BIT = 128;
  private static final int IV_LENGTH_BYTE = 12;

  private final ThreadLocal<Cipher> cipherWrapper = new ThreadLocal<>();
  private final SecureRandom secureRandom = new SecureRandom();
  private SecretKey secretKey;

  public CryptService() {
  }

  @PostConstruct
  public void initializeSecretKey() throws Exception {
    String key = generate128BitRandomKey();

    if (key == null || key.isBlank()) {
      throw new Exception("Encryption Key is missing!");
    }

    byte[] encryptionKey;

    try {
      // Convert Base64-String to byte[]
      encryptionKey = Base64.getDecoder().decode(key);
    } catch (Exception e) {
      throw new Exception("Encryption Key must be a valid Base64-String");
    }

    if (encryptionKey.length != 16 && encryptionKey.length != 24 && encryptionKey.length != 32) {
      throw new Exception("Encryption Key length must be 16, 24 or 32 bytes");
    }

    secretKey = new SecretKeySpec(encryptionKey, "AES");
  }

  @Override
  public String encryptStringData(String dataToEncrypt) throws Exception {
    return encryptStringData(dataToEncrypt, null);
  }

  @Override
  public String encryptStringData(String dataToEncrypt, String associatedDataStr)
      throws Exception {

    if (dataToEncrypt == null || dataToEncrypt.isBlank()) {
      throw new Exception(
          "The received data to encrypt is invalid - the data is null or empty");
    }

    byte[] dataToEncryptBytes = dataToEncrypt.getBytes(StandardCharsets.UTF_8);
    byte[] associatedDataBytes =
        associatedDataStr != null ? associatedDataStr.getBytes(StandardCharsets.UTF_8) : null;

    return encryptBytesData(dataToEncryptBytes, associatedDataBytes);
  }

  private String encryptBytesData(byte[] dataToEncrypt, byte[] associatedData) throws Exception {

    if (dataToEncrypt == null || dataToEncrypt.length == 0) {
      throw new Exception(
          "The received data is invalid - the data to encrypt is null or empty");
    }

    byte[] iv = null;
    byte[] encrypted = null;

    try {
      //Create an Initialization Vector (IV)
      iv = new byte[IV_LENGTH_BYTE]; // Never reuse this IV with the same key

      // Populate the IV with random values
      secureRandom.nextBytes(iv);

      // Create new Cipher instance. We are using the AED-GCM mode
      final Cipher cipher = getCipher();

      // Constructs a GCMParameterSpec using the specified authentication tag bit-length and IV buffer
      GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

      // Initialize the cipher with a key and a set of algorithm parameters.
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

      // Add optional associatedData to the authentication tag (for instance meta data)
      if (associatedData != null) {
        cipher.updateAAD(associatedData);
      }

      // Encrypt the dataToEncrypt
      encrypted = cipher.doFinal(dataToEncrypt);

      ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encrypted.length);
      byteBuffer.put((byte) iv.length);
      byteBuffer.put(iv);
      byteBuffer.put(encrypted);
      byte[] cipherMessage = byteBuffer.array();

      // Encode the cipherMessage to Base64-String and prepend with the CRYPT_PREFIX
      return CRYPT_PREFIX + Base64.getEncoder().encodeToString(cipherMessage);

    } catch (Exception exc) {
      throw new Exception("Could not encrypt the data", exc);
    } finally {
      Arrays.fill(iv, (byte) 0);

      if (encrypted != null) {
        Arrays.fill(encrypted, (byte) 0);
      }
    }
  }

  @Override
  public String decryptBase64StringData(String dataToDecryptB64) throws Exception {
    return decryptBase64StringData(dataToDecryptB64, null);
  }

  @Override
  public String decryptBase64StringData(String dataToDecryptB64, String associatedDataStr)
      throws Exception {

    if (dataToDecryptB64 == null || dataToDecryptB64.isBlank()) {
      throw new Exception(
          "The received data to decrypt is invalid - the data is null or empty");
    }

    // If the input data (dataToDecryptB64) is not prefixed with the 'CRYPT_PREFIX', then the input data
    // will be returned without decryption
    if (!dataToDecryptB64.startsWith(CRYPT_PREFIX)) {
      return dataToDecryptB64;
    }

    String dataToDecryptWithoutPrefix = dataToDecryptB64.substring(CRYPT_PREFIX.length());

    // Convert Base64-String to byte[]
    byte[] cipherMessageByteArr = Base64.getDecoder().decode(dataToDecryptWithoutPrefix);
    byte[] associatedDataBytes =
        associatedDataStr != null ? associatedDataStr.getBytes(StandardCharsets.UTF_8) : null;

    return decryptBytesData(cipherMessageByteArr, associatedDataBytes);
  }

  private String decryptBytesData(byte[] dataToDecryptBytes, byte[] associatedData)
      throws Exception {

    if (dataToDecryptBytes == null || dataToDecryptBytes.length == 0) {
      throw new Exception(
          "The received data to decrypt is invalid - the data is null or empty");
    }

    try {
      int initialOffset = 1;
      int ivLength = dataToDecryptBytes[0];

      if (ivLength != 12) {
        throw new Exception("Unexpected Initialization Vector length");
      }

      final Cipher cipher = getCipher();

      AlgorithmParameterSpec gcmIv = new GCMParameterSpec(TAG_LENGTH_BIT, dataToDecryptBytes,
          initialOffset, ivLength);

      cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmIv);

      if (associatedData != null) {
        cipher.updateAAD(associatedData);
      }

      // Use everything from (initialOffset + ivLength) bytes on as ciphertext
      byte[] decryptedDataByteArr = cipher
          .doFinal(dataToDecryptBytes, initialOffset + ivLength,
              dataToDecryptBytes.length - (initialOffset + ivLength));

      return new String(decryptedDataByteArr, StandardCharsets.UTF_8);

    } catch (Exception exc) {
      throw new Exception("Could not decrypt the data", exc);
    }
  }

  @Override
  public String generate128BitRandomKey() {
    byte[] bytesArr = new byte[16];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(bytesArr);

    // Encode the randomKey to Base64-String
    return Base64.getEncoder().encodeToString(bytesArr);
  }

  private Cipher getCipher() throws Exception {
    Cipher cipher = cipherWrapper.get();
    if (cipher == null) {
      try {
        cipher = Cipher.getInstance(ALGORITHM);
      } catch (Exception e) {
        throw new Exception("Could not get cipher instance", e);
      }
      cipherWrapper.set(cipher);
      return cipherWrapper.get();
    } else {
      return cipher;
    }
  }
}

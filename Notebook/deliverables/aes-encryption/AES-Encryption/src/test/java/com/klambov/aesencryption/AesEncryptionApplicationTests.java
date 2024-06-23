package com.klambov.aesencryption;

import static org.assertj.core.api.Assertions.assertThat;

import com.klambov.aesencryption.crypt.LottaaCryptConfigProperties;
import com.klambov.aesencryption.crypt.LottaaCryptException;
import com.klambov.aesencryption.crypt.LottaaCryptService;
import com.klambov.aesencryption.crypt.LottaaCryptServiceImpl;
import java.util.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = LottaaCryptServiceImpl.class)
@EnableConfigurationProperties(value = {LottaaCryptConfigProperties.class})
@TestPropertySource("classpath:lottaa-application-test.properties")
class AesEncryptionApplicationTests {

  private static final String CRYPT_PREFIX = "$[[lottaaCrypt]]$";

  @Autowired
  private LottaaCryptService lottaaCryptService;

  @Test
  void testEncryptAndDecryptStringData_whenAssociatedDataIsTheSameForEncryptionAndDecryption_200()
      throws LottaaCryptException {
    String testData = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. "
        + "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an"
        + " unknown printer took a galley of type and scrambled it to make a type specimen book. "
        + "It has survived not only five centuries, but also the leap into electronic typesetting,"
        + " remaining essentially unchanged. It was popularised in the 1960s with the release of"
        + " Letraset sheets containing Lorem Ipsum passages, and more recently with desktop "
        + "publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

    String testAssociatedData = "Test-Metadata";

    // Encrypt data
    String encryptedData = lottaaCryptService.encryptStringData(testData, testAssociatedData);

    // Decrypt the encrypted data
    String decryptedData = lottaaCryptService
        .decryptBase64StringData(encryptedData, testAssociatedData);

    assertThat(testData).isEqualTo(decryptedData);
  }

  @Test
  void testEncryptAndDecryptStringData_whenAssociatedDataIsNull_200() throws LottaaCryptException {
    String testData = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. "
        + "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an"
        + " unknown printer took a galley of type and scrambled it to make a type specimen book. "
        + "It has survived not only five centuries, but also the leap into electronic typesetting,"
        + " remaining essentially unchanged. It was popularised in the 1960s with the release of"
        + " Letraset sheets containing Lorem Ipsum passages, and more recently with desktop "
        + "publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

    // Encrypt data
    String encryptedData = lottaaCryptService.encryptStringData(testData, null);

    // Decrypt the encrypted data
    String decryptedData = lottaaCryptService.decryptBase64StringData(encryptedData, null);

    assertThat(testData).isEqualTo(decryptedData);
  }

  @Test
  void testEncryptAndDecryptStringData_whenAssociatedDataIsNotTheSameForEncryptionAndDecryption_throwException()
      throws LottaaCryptException {
    String testData = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. "
        + "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an"
        + " unknown printer took a galley of type and scrambled it to make a type specimen book. "
        + "It has survived not only five centuries, but also the leap into electronic typesetting,"
        + " remaining essentially unchanged. It was popularised in the 1960s with the release of"
        + " Letraset sheets containing Lorem Ipsum passages, and more recently with desktop "
        + "publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

    String encryptionAssociatedData = "Test-Metadata";
    String decryptionAssociatedData = "Changed-Test-Metadata";

    // Encrypt data
    String encryptedData = lottaaCryptService.encryptStringData(testData, encryptionAssociatedData);

    // Decrypt the encrypted data
    Assertions.assertThrows(LottaaCryptException.class,
        () -> lottaaCryptService
            .decryptBase64StringData(encryptedData, decryptionAssociatedData),
        "Could not encrypt the data");
  }

  @Test
  void testEncryptStringData_whenDataToEncryptIsNull_throwException() {

    String encryptionAssociatedData = "Test-Metadata";

    // Encrypt data
    Assertions.assertThrows(LottaaCryptException.class,
        () -> lottaaCryptService.encryptStringData(null, encryptionAssociatedData),
        "The received data to encrypt is invalid - the data is null or empty");
  }

  @Test
  void testEncryptStringData_whenDataToEncryptIsEmptyString_throwException() {

    String encryptionAssociatedData = "Test-Metadata";

    // Encrypt data
    Assertions.assertThrows(LottaaCryptException.class,
        () -> lottaaCryptService.encryptStringData("", encryptionAssociatedData),
        "The received data to encrypt is invalid - the data is null or empty");
  }

  @Test
  void testDecryptBase64StringData_whenDataToDecryptIsNull_throwException() {
    String decryptionAssociatedData = "Test-Metadata";

    // Decrypt the encrypted data
    Assertions.assertThrows(LottaaCryptException.class,
        () -> lottaaCryptService
            .decryptBase64StringData(null, decryptionAssociatedData),
        "The received data to encrypt is invalid - the data is null or empty");
  }

  @Test
  void testDecryptBase64StringData_whenDataToDecryptIsEmptyString_throwException() {
    String decryptionAssociatedData = "Test-Metadata";

    // Decrypt the encrypted data
    Assertions.assertThrows(LottaaCryptException.class,
        () -> lottaaCryptService
            .decryptBase64StringData("", decryptionAssociatedData),
        "The received data to encrypt is invalid - the data is null or empty");
  }

  @Test
  void testDecryptBase64StringData_whenDataToDecryptIsEmptyStringAndAssociatedDataIsNull_throwException() {
    // Decrypt the encrypted data
    Assertions.assertThrows(LottaaCryptException.class,
        () -> lottaaCryptService
            .decryptBase64StringData("", null),
        "The received data to encrypt is invalid - the data is null or empty");
  }


  @Test
  void testDecryptStringData_whenDataIsNotPrefixed_returnTheInputData()
      throws LottaaCryptException {
    String notPrefixedTestDataToDecrypt =
        "Lorem Ipsum is simply dummy text of the printing and typesetting industry. "
            + "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an"
            + " unknown printer took a galley of type and scrambled it to make a type specimen book. "
            + "It has survived not only five centuries, but also the leap into electronic typesetting,"
            + " remaining essentially unchanged. It was popularised in the 1960s with the release of"
            + " Letraset sheets containing Lorem Ipsum passages, and more recently with desktop "
            + "publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

    // Decrypt the encrypted data
    String decryptedData = lottaaCryptService.decryptBase64StringData(notPrefixedTestDataToDecrypt);

    assertThat(notPrefixedTestDataToDecrypt).isEqualTo(decryptedData);
  }


//  @Disabled("Requires a 256 bit Encryption Key")
  @Test
  void testDecryptStringData_whenDataIsPrefixedAnd256BitEncryptionKey_200() throws LottaaCryptException {
    String prefixedTestBase64DataToDecrypt = CRYPT_PREFIX + "DAzPVaUKcd+MZncnrjen7WoWp3vq/9meVKJUL3OVk6+vaHLPPvDMooU8lxqYdT4b2DzrSYb6+0qgJ8tqAKtTv3Jj0ufwCpRpHRKL3UvAdmei1BgntChf5hUIhoWLocOE62pfUcn3LaY7ABWa9ye1Xyb+r5AQ6U8sd7LuXmr2dt8/bqNIPN+c8XFMT1i8D0oXaZ+YLx/nEfmF1AeoHa5K3GTbL4QSyIPHol+61b3TkEsRoUATq3UPURDkxnkQ1v+vJMqbnfql0AyGKyQlZw1lBMNdT8RqxvG5VOLMiGzUv0ULWZHOJNnXGs5KsxdjV7RVqwW5Y4A8gnIDaR1NZZw6YlFNUV0AY+bvntEZ7vXdohy8OA1kh1k9N+fgfNavBmgZvwtFCICd/Fspo1hlWDww47fs9FIftWowpl7ENZ77f0AVvoXKrk3UJoib2L6UXsFwUenm6u/KMUZcZRYUcAVU+3K6BlJ/fP2qtN+HamqS5FG+sUfoikt1XJHkWtf0A+jI18IpoBdivet2Hmj4BjnVtglvFE60R0gf7uFBFlNKXO4Zf8DOaPG6xNjt+Tp+TZFxJff/dHF+STCsoerwV9fyJ240JTwQ8qJ702XZMHEdR6yVWMnLU0b8eSYqcYz7QE8g1UuuoxaIMhRiIjNA9xPphu6wv65+pZZCVo3+5wYfufXY7W+X2MHyvOGUZU4IHaLWDrDFc1C/ZukegbHyxmoXYF+Cf8Lrss74gKyrpu6hYkgY4d5U0Ny/dUbbxKlLnNG/XMXcPBO3hJREDBX5kZMZobuTYW5uIdS1p2xk";
    String testDecryptedData = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. "
        + "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an"
        + " unknown printer took a galley of type and scrambled it to make a type specimen book. "
        + "It has survived not only five centuries, but also the leap into electronic typesetting,"
        + " remaining essentially unchanged. It was popularised in the 1960s with the release of"
        + " Letraset sheets containing Lorem Ipsum passages, and more recently with desktop "
        + "publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

    // Decrypt the encrypted data
    String decryptedData = lottaaCryptService.decryptBase64StringData(prefixedTestBase64DataToDecrypt);

    assertThat(testDecryptedData).isEqualTo(decryptedData);
  }

  @Test
  void testGenerate128BitRandomKey() {
    String generatedRandomKey = lottaaCryptService.generate128BitRandomKey();

    assertThat(generatedRandomKey).isNotNull();
    assertThat(Base64.getDecoder().decode(generatedRandomKey).length).isEqualTo(16);
  }
}
/*
 * File created on Mar 8, 2019
 *
 * Copyright (c) 2019 Carl Harris, Jr
 * and others as noted
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.soulwing.jwt.api.jose4j;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Optional;
import javax.json.Json;
import javax.json.JsonObject;

import org.jmock.Expectations;
import org.jmock.auto.Mock;
import org.jmock.integration.junit4.JUnitRuleMockery;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.KeyProvider;
import org.soulwing.jwt.api.KeyUtil;
import org.soulwing.jwt.api.SingletonKeyProvider;
import org.soulwing.jwt.api.exceptions.DecryptionKeyNotFoundException;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;

/**
 * Unit tests for {@link Jose4jEncryptionOperator}.
 *
 * @author Carl Harris
 */
public class Jose4jEncryptionOperatorTest {

  private static final String KEY_ID = "keyId";
  private static final String PAYLOAD = "This is just a plain old string";
  private static final String OTHER = "OTHER";

  private static final JWE.KeyManagementAlgorithm KEY_MANAGEMENT_ALGORITHM =
      JWE.KeyManagementAlgorithm.A256KW;

  private static final JWE.ContentEncryptionAlgorithm CONTENT_ENCRYPTION_ALGORITHM =
      JWE.ContentEncryptionAlgorithm.A256CBC_HS512;
  private static final JWE.CompressionAlgorithm COMPRESSION_ALGORITHM = JWE.CompressionAlgorithm.DEFLATE;

  @Rule
  public final JUnitRuleMockery context = new JUnitRuleMockery();

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Mock
  private KeyProvider keyProvider;

  private Key key, otherKey;

  @Before
  public void setUp() throws Exception {
    key = KeyUtil.newAesKey(256);
    otherKey = KeyUtil.newAesKey(256);
  }

  @Test(expected = JWTConfigurationException.class)
  public void testBuildWhenNothingConfigured() throws Exception {
    Jose4jEncryptionOperator.builder().build();
  }

  @Test
  public void testBuildWhenNoKeyProvider() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("keyProvider");
    Jose4jEncryptionOperator.builder()
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .contentType(JWE.JWT)
        .build();
  }

  @Test
  public void testBuildWhenNoKeyManagementAlgorithm() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("keyManagementAlgorithm");
    Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .contentType(JWE.JWT)
        .build();
  }

  @Test
  public void testBuildWhenNoContentEncryptionAlgorithm() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("contentEncryptionAlgorithm");
    Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .contentType(JWE.JWT)
        .build();
  }

  @Test
  public void testBuildWhenNoCompressionAlgorithm() throws Exception {
    Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .contentType(JWE.JWT)
        .build();
  }

  @Test
  public void testBuildWhenNoContentType() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("contentType");
    Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .build();
  }

  @Test
  public void testEncryptAndDecrypt() throws Exception {
    final JWE operator = Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KEY_ID, key))
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .contentType(OTHER)
        .build();

    final String encoded = operator.encrypt(PAYLOAD);
    final String header = new String(Base64.getUrlDecoder().decode(
        encoded.substring(0, encoded.indexOf('.'))), StandardCharsets.UTF_8);

    final JsonObject fields = Json.createReader(
        new StringReader(header)).readObject();

    assertThat(fields.getString("kid"),
        is(equalTo(KEY_ID)));
    assertThat(fields.getString("alg"),
        is(equalTo(KEY_MANAGEMENT_ALGORITHM.toToken())));
    assertThat(fields.getString("enc"),
        is(equalTo(CONTENT_ENCRYPTION_ALGORITHM.toToken())));
    assertThat(fields.getString("zip"),
        is(equalTo(COMPRESSION_ALGORITHM.toToken())));
    assertThat(fields.getString("cty"),
        is(equalTo(OTHER)));

    assertThat(operator.decrypt(encoded), is(equalTo(PAYLOAD)));
  }

  @Test(expected = JWTEncryptionException.class)
  public void testDecryptWithDifferentKeyThanEncrypt() throws Exception {
    final JWE encrypt = Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KEY_ID, key))
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .contentType(OTHER)
        .build();

    final String encoded = encrypt.encrypt(PAYLOAD);

    final JWE decrypt = Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KEY_ID, otherKey))
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .contentType(OTHER)
        .build();

    decrypt.decrypt(encoded);
  }


  @Test(expected = JWTEncryptionException.class)
  public void testEncryptWithInadequateKey() throws Exception {
    final JWE operator = Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(128)))
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .contentType(OTHER)
        .build();

    operator.encrypt("DON'T CARE");
  }

  @Test(expected = JWTEncryptionException.class)
  public void testDecryptWithInadequateKey() throws Exception {
    final JWE operator = Jose4jEncryptionOperator.builder()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(128)))
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .contentType(OTHER)
        .build();

    operator.decrypt("DON'T CARE");
  }

  @Test(expected = DecryptionKeyNotFoundException.class)
  public void testDecryptWhenKeyNotFound() throws Exception {
    final JWE operator = Jose4jEncryptionOperator.builder()
        .keyProvider(keyProvider)
        .keyManagementAlgorithm(KEY_MANAGEMENT_ALGORITHM)
        .contentEncryptionAlgorithm(CONTENT_ENCRYPTION_ALGORITHM)
        .compressionAlgorithm(COMPRESSION_ALGORITHM)
        .contentType(OTHER)
        .build();

    context.checking(new Expectations() {
      {
        oneOf(keyProvider).currentKey();
        will(returnValue(SingletonKeyProvider.with(KEY_ID, key).currentKey()));
        oneOf(keyProvider).retrieveKey(KEY_ID);
        will(returnValue(Optional.empty()));
      }
    });

    operator.decrypt(operator.encrypt(PAYLOAD));
  }

}

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
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.jose4j.jwx.Headers;
import org.junit.Test;
import org.soulwing.jwt.api.Assertions;
import org.soulwing.jwt.api.Claims;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.JWTGenerator;
import org.soulwing.jwt.api.JWTValidator;
import org.soulwing.jwt.api.JoseHeader;
import org.soulwing.jwt.api.KeyUtil;
import org.soulwing.jwt.api.SingletonKeyProvider;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;
import org.soulwing.jwt.api.exceptions.JWTValidationException;

/**
 * Unit tests for {@link Jose4jProvider}.
 *
 * @author Carl Harris
 */
public class Jose4jProviderTest {

  private static final String ID = "id";
  private static final String ISSUER = "issuer";

  private static final Instant EXPIRES_AT =
      Instant.ofEpochSecond(Instant.now().getEpochSecond());

  private final Jose4jProvider provider = new Jose4jProvider();

  @Test
  public void testClaims() throws Exception {
    final Claims claims = createClaims();

    // there are other tests for more comprehensive testing of the claims
    // implementation, so just a few basics here
    assertThat(claims.id().orElse(null), is(equalTo(ID)));
    assertThat(claims.issuer().orElse(null), is(equalTo(ISSUER)));
    assertThat(claims.expiresAt().orElse(null), is(equalTo(EXPIRES_AT)));
    assertThat(claims.toJson(), is(not(nullValue())));
  }

  @Test
  public void testParse() throws Exception {
    final Claims claims = createClaims();

    final Claims actual = provider.parse(claims.toJson());

    assertThat(actual.id().orElse(null), is(equalTo(ID)));
    assertThat(actual.issuer().orElse(null), is(equalTo(ISSUER)));
    assertThat(actual.expiresAt().orElse(null), is(equalTo(EXPIRES_AT)));
  }

  @Test
  public void testHeader() throws Exception {
    final Headers headers = new Headers();
    headers.setFullHeaderAsJsonString("{\"typ\":\"TYPE\"}");
    final JoseHeader header = provider.header(headers.getEncodedHeader());
    assertThat(header.getType(), is(equalTo("TYPE")));
  }

  @Test
  public void testAssertions() throws Exception {
    final Claims claims = createClaims();

    // there are other tests for more comprehensive testing of the assertions
    // implementation, so just a few basics here

    // EXPIRES_AT was set to `now` at the start of the test, so
    // allow plenty of tolerance here for elapsed time
    final Duration tolerance = Duration.ofMinutes(15);

    provider.assertions()
        .requireNotExpired(tolerance)
        .requireIssuer(ISSUER)
        .build()
        .assertSatisfied(claims,
            new Jose4jAssertionContext(Clock.systemUTC(), null));
  }

  @Test
  public void testSignatureOperator() throws Exception {

    // there are other tests for more comprehensive testing of the signature
    // implementation, so just a few basics here

    final JWS operator = provider.signatureOperator()
        .algorithm(JWS.Algorithm.HS256)
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
        .build();

    final Claims claims = createClaims();
    final String encoded = operator.sign(claims.toJson());
    final JWS.Result result = operator.verify(encoded);
    final Claims actual = provider.parse(result.getPayload());

    assertThat(actual.id().orElse(null), is(equalTo(ID)));
    assertThat(actual.issuer().orElse(null), is(equalTo(ISSUER)));
    assertThat(actual.expiresAt().orElse(null), is(equalTo(EXPIRES_AT)));
  }

  @Test
  public void testEncryptionOperator() throws Exception {

    // there are other tests for more comprehensive testing of the encryption
    // implementation, so just a few basics here

    final JWE operator = provider.encryptionOperator()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
        .keyManagementAlgorithm(JWE.KeyManagementAlgorithm.A256KW)
        .contentEncryptionAlgorithm(JWE.ContentEncryptionAlgorithm.A256CBC_HS512)
        .compressionAlgorithm(JWE.CompressionAlgorithm.DEFLATE)
        .contentType("OTHER")
        .build();

    final Claims claims = createClaims();
    final String encoded = operator.encrypt(claims.toJson());
    final String decoded = operator.decrypt(encoded);
    final Claims actual = provider.parse(decoded);

    assertThat(actual.id().orElse(null), is(equalTo(ID)));
    assertThat(actual.issuer().orElse(null), is(equalTo(ISSUER)));
    assertThat(actual.expiresAt().orElse(null), is(equalTo(EXPIRES_AT)));
  }

  @Test
  public void testGenerateAndValidateSuccess() throws Exception {

    final JWE encryptionOperator = encryptionOperator();
    final JWS signatureOperator = signatureOperator();

    final JWTGenerator generator = provider.generator()
        .encryption(encryptionOperator)
        .signature(signatureOperator)
        .build();

    // EXPIRES_AT was set to `now` at the start of the test, so
    // allow plenty of tolerance here for elapsed time
    final Duration tolerance = Duration.ofMinutes(15);

    final Assertions assertions = provider.assertions()
        .requireNotExpired(tolerance)
        .requireIssuer(ISSUER)
        .build();

    final JWTValidator validator = provider.validator()
        .encryptionOperator(encryptionOperator)
        .signatureOperator(signatureOperator)
        .claimsAssertions(assertions)
        .build();

    validator.validate(generator.generate(createClaims()));
  }

  @Test(expected = JWTEncryptionException.class)
  public void testGenerateAndValidateWhenDecryptionFails() throws Exception {

    final JWE encryptionOperator = encryptionOperator();
    final JWE decryptionOperator = encryptionOperator();  // different key
    final JWS signatureOperator = signatureOperator();

    final JWTGenerator generator = provider.generator()
        .encryption(encryptionOperator)
        .signature(signatureOperator)
        .build();

    final Assertions assertions = provider.assertions()
        .requireNotExpired(Duration.ZERO)
        .requireIssuer(ISSUER)
        .build();

    final JWTValidator validator = provider.validator()
        .encryptionOperator(decryptionOperator)                  // different operator
        .signatureOperator(signatureOperator)
        .claimsAssertions(assertions)
        .build();

    validator.validate(generator.generate(createClaims()));
  }

  @Test(expected = JWTSignatureException.class)
  public void testGenerateAndValidateWhenSignatureValidationFails()
      throws Exception {

    final JWE encryptionOperator = encryptionOperator();
    final JWS signatureOperator = signatureOperator();
    final JWS verifyOperator = signatureOperator();       // different key

    final JWTGenerator generator = provider.generator()
        .encryption(encryptionOperator)
        .signature(signatureOperator)
        .build();

    final Assertions assertions = provider.assertions()
        .requireNotExpired(Duration.ZERO)
        .requireIssuer(ISSUER)
        .build();

    final JWTValidator validator = provider.validator()
        .encryptionOperator(encryptionOperator)
        .signatureOperator(verifyOperator)              // different operator
        .claimsAssertions(assertions)
        .build();

    validator.validate(generator.generate(createClaims()));
  }

  @Test(expected = JWTValidationException.class)
  public void testGenerateAndValidateWhenAssertionFails() throws Exception {

    final JWE encryptionOperator = encryptionOperator();
    final JWS signatureOperator = signatureOperator();

    final JWTGenerator generator = provider.generator()
        .encryption(encryptionOperator)
        .signature(signatureOperator)
        .build();

    // EXPIRES_AT was set to now at the start of the test.
    // i.e. it is already expired so will fail with a tolerance of zero
    final Duration tolerance = Duration.ZERO;
    final Assertions assertions = provider.assertions()
        .requireNotExpired(tolerance)
        .requireIssuer(ISSUER)
        .build();

    final JWTValidator validator = provider.validator()
        .encryptionOperator(encryptionOperator)
        .signatureOperator(signatureOperator)
        .claimsAssertions(assertions)
        .build();

    validator.validate(generator.generate(createClaims()));
  }

  private JWS signatureOperator() throws JWTConfigurationException {
    return provider.signatureOperator()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
        .algorithm(JWS.Algorithm.HS256)
        .build();
  }

  private JWE encryptionOperator() throws JWTConfigurationException {
    return provider.encryptionOperator()
        .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
        .keyManagementAlgorithm(JWE.KeyManagementAlgorithm.A256KW)
        .contentEncryptionAlgorithm(JWE.ContentEncryptionAlgorithm.A256CBC_HS512)
        .compressionAlgorithm(JWE.CompressionAlgorithm.DEFLATE)
        .contentType(JWE.JWT)
        .build();
  }

  private Claims createClaims() {
    return provider.claims()
        .id(ID)
        .issuer(ISSUER)
        .expiresAt(EXPIRES_AT)
        .build();
  }


}
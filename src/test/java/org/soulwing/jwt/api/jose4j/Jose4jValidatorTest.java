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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import org.hamcrest.Matchers;
import org.jmock.Expectations;
import org.jmock.auto.Mock;
import org.jmock.integration.junit4.JUnitRuleMockery;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.Assertions;
import org.soulwing.jwt.api.Claims;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.JWTProvider;
import org.soulwing.jwt.api.JWTValidator;
import org.soulwing.jwt.api.MockClock;
import org.soulwing.jwt.api.exceptions.JWTAssertionFailedException;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;
import org.soulwing.jwt.api.exceptions.JWTValidationException;

/**
 * Unit tests for {@link Jose4jValidator}.
 *
 * @author Carl Harris
 */
public class Jose4jValidatorTest {

  private static final String ENCODED = "encoded";
  private static final String DECRYPTED = "decrypted";
  private static final String PAYLOAD = "payload";

  @Rule
  public final JUnitRuleMockery context = new JUnitRuleMockery();

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Mock
  private JWE encryptionOperator;

  @Mock
  private JWE.Factory encryptionOperatorFactory;

  @Mock
  private JWS signatureOperator;

  @Mock
  private JWS.Factory signatureOperatorFactory;

  @Mock
  private Assertions assertions;

  @Mock
  private JWTProvider provider;

  @Mock
  private JWE.Header jweHeader;

  @Mock
  private JWS.Header jwsHeader;

  @Mock
  private Claims payload;

  private MockClock clock = new MockClock();

  @Test(expected = JWTConfigurationException.class)
  public void testBuildWhenNothingConfigured() throws Exception {
    Jose4jValidator.builder(provider).build();
  }

  @Test
  public void testBuildWhenNoSignatureOperator() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("signature");
    Jose4jValidator.builder(provider)
        .encryptionOperator(encryptionOperator)
        .claimsAssertions(assertions)
        .clock(clock)
        .build();
  }

  @Test
  public void testBuildWhenNoAssertions() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("assertions");
    Jose4jValidator.builder(provider)
        .encryptionOperator(encryptionOperator)
        .signatureOperator(signatureOperator)
        .clock(clock)
        .build();
  }

  @Test
  public void testBuildWhenEncryptionOperatorAndFactory() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("encryption operator or operator factory");
    Jose4jValidator.builder(provider)
        .encryptionOperator(encryptionOperator)
        .encryptionOperatorFactory(encryptionOperatorFactory)
        .signatureOperator(signatureOperator)
        .claimsAssertions(assertions)
        .clock(clock)
        .build();
  }

  @Test
  public void testBuildWhenSignatureOperatorAndFactory() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("signature operator or operator factory");
    Jose4jValidator.builder(provider)
        .encryptionOperator(encryptionOperator)
        .signatureOperator(signatureOperator)
        .signatureOperatorFactory(signatureOperatorFactory)
        .claimsAssertions(assertions)
        .clock(clock)
        .build();
  }

  @Test
  public void testUseDefaultClock() throws Exception {
    Jose4jValidator.builder(provider)
        .encryptionOperator(encryptionOperator)
        .signatureOperator(signatureOperator)
        .claimsAssertions(assertions)
        .clock(null)
        .build();
  }

  @Test
  public void testUseDefaultEncryptionOperator() throws Exception {
    Jose4jValidator.builder(provider)
        .signatureOperator(signatureOperator)
        .claimsAssertions(assertions)
        .clock(clock)
        .build();
  }

  @Test
  public void testValidateSuccess() throws Exception {
    context.checking(decryptExpectations(null));
    context.checking(verifySignatureExpectations(null));
    context.checking(payloadAssertionExpectations(null));
    assertThat(newValidator().validate(ENCODED), is(sameInstance(payload)));
  }

  @Test
  public void testValidateWhenAssertionFails() throws Exception {
    final JWTAssertionFailedException ex =
        new JWTAssertionFailedException("validation error");
    context.checking(decryptExpectations(null));
    context.checking(verifySignatureExpectations(null));
    context.checking(payloadAssertionExpectations(ex));
    expectedException.expect(JWTValidationException.class);
    expectedException.expectCause(is(sameInstance(ex)));
    newValidator().validate(ENCODED);
  }

  @Test
  public void testValidateWhenSignatureValidationFails() throws Exception {
    context.checking(decryptExpectations(null));
    final JWTSignatureException ex = new JWTSignatureException("error");
    context.checking(verifySignatureExpectations(ex));
    expectedException.expect(is(sameInstance(ex)));
    newValidator().validate(ENCODED);
  }

  @Test
  public void testValidateWhenDecryptionFails() throws Exception {
    final JWTEncryptionException ex = new JWTEncryptionException("error");
    context.checking(decryptExpectations(ex));
    expectedException.expect(is(sameInstance(ex)));
    newValidator().validate(ENCODED);
  }

  private Expectations decryptExpectations(JWTEncryptionException ex)
      throws Exception {
    return new Expectations() {
      {
        oneOf(provider).header(ENCODED);
        will(returnValue(jweHeader));
        oneOf(encryptionOperatorFactory).getOperator(jweHeader);
        will(returnValue(encryptionOperator));
        oneOf(encryptionOperator).decrypt(ENCODED);
        will(ex != null ? throwException(ex) : returnValue(DECRYPTED));
      }
    };
  }

  private Expectations verifySignatureExpectations(JWTSignatureException ex)
      throws Exception {
    return new Expectations() {
      {
        oneOf(provider).header(DECRYPTED);
        will(returnValue(jwsHeader));
        oneOf(signatureOperatorFactory).getOperator(jwsHeader);
        will(returnValue(signatureOperator));
        oneOf(signatureOperator).verify(DECRYPTED);
        will(ex != null ? throwException(ex)
            : returnValue(new Jose4jVerificationResult(PAYLOAD, null)));
      }
    };
  }

  private Expectations payloadAssertionExpectations(
      JWTAssertionFailedException ex) throws Exception {
    return new Expectations() {
      {
        oneOf(provider).parse(PAYLOAD);
        will(returnValue(payload));
        oneOf(assertions).assertSatisfied(with(payload),
            with(Matchers.<Assertions.Context>hasProperty("clock",
                is(sameInstance(clock)))));
        will(ex == null ? returnValue(null) : throwException(ex));
      }
    };
  }

  private JWTValidator newValidator() throws JWTConfigurationException {
    return Jose4jValidator.builder(provider)
          .encryptionOperatorFactory(encryptionOperatorFactory)
          .signatureOperatorFactory(signatureOperatorFactory)
          .claimsAssertions(assertions)
          .clock(clock)
          .build();
  }

}
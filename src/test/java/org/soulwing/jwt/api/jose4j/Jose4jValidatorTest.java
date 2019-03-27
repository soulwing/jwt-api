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

import java.io.StringWriter;
import javax.json.Json;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matchers;
import org.jmock.Expectations;
import org.jmock.Sequence;
import org.jmock.auto.Mock;
import org.jmock.integration.junit4.JUnitRuleMockery;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.Assertions;
import org.soulwing.jwt.api.Claims;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.JWTValidator;
import org.soulwing.jwt.api.MockClock;
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
  private static final String ID = "id";

  private static final String PAYLOAD;

  static {
    final StringWriter writer = new StringWriter();
    Json.createWriter(writer).writeObject(Json.createObjectBuilder()
        .add(Claims.JTI, ID).build());
    PAYLOAD = writer.toString();
  }

  @Rule
  public final JUnitRuleMockery context = new JUnitRuleMockery();

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Mock
  private JWE encryptionOperator;

  @Mock
  private JWS signatureOperator;

  @Mock
  private Assertions assertions;

  private MockClock clock = new MockClock();

  @Test(expected = JWTConfigurationException.class)
  public void testBuildWhenNothingConfigured() throws Exception {
    Jose4jValidator.builder().build();
  }

  @Test
  public void testBuildWhenNoSignatureOperator() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("signature");
    Jose4jValidator.builder()
        .decryption(encryptionOperator)
        .claimsAssertions(assertions)
        .clock(clock)
        .build();
  }

  @Test
  public void testBuildWhenNoAssertions() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("assertions");
    Jose4jValidator.builder()
        .decryption(encryptionOperator)
        .signatureValidation(signatureOperator)
        .clock(clock)
        .build();
  }

  @Test
  public void testUseDefaultClock() throws Exception {
    Jose4jValidator.builder()
        .decryption(encryptionOperator)
        .signatureValidation(signatureOperator)
        .claimsAssertions(assertions)
        .clock(null)
        .build();
  }

  @Test
  public void testUseDefaultEncryptionOperator() throws Exception {
    Jose4jValidator.builder()
        .decryption(null)
        .signatureValidation(signatureOperator)
        .claimsAssertions(assertions)
        .clock(clock)
        .build();
  }

  @Test
  public void testValidateSuccess() throws Exception {
    final Sequence sequence = context.sequence("validateSequence");
    context.checking(new Expectations() {
      {
        oneOf(encryptionOperator).decrypt(ENCODED);
        inSequence(sequence);
        will(returnValue(DECRYPTED));
        oneOf(signatureOperator).verify(DECRYPTED);
        inSequence(sequence);
        will(returnValue(new Jose4jVerificationResult(PAYLOAD, null)));
        oneOf(assertions).test(with(claimsWithJti(ID)),
            with(Matchers.<Assertions.Context>hasProperty("clock",
                Matchers.is(Matchers.sameInstance(clock)))));
        inSequence(sequence);
        will(returnValue(true));
      }
    });

    newValidator().validate(ENCODED);
  }

  @Test
  public void testValidateWhenAssertionFails() throws Exception {
    final Sequence sequence = context.sequence("validateSequence");
    context.checking(new Expectations() {
      {
        oneOf(encryptionOperator).decrypt(ENCODED);
        inSequence(sequence);
        will(returnValue(DECRYPTED));
        oneOf(signatureOperator).verify(DECRYPTED);
        inSequence(sequence);
        will(returnValue(new Jose4jVerificationResult(PAYLOAD, null)));
        oneOf(assertions).test(with(claimsWithJti(ID)),
            with(Matchers.<Assertions.Context>hasProperty("clock",
                Matchers.is(Matchers.sameInstance(clock)))));
        inSequence(sequence);
        will(returnValue(false));
      }
    });

    expectedException.expect(JWTValidationException.class);
    expectedException.expectMessage("assertions");
    newValidator().validate(ENCODED);
  }

  @Test(expected = JWTSignatureException.class)
  public void testValidateWhenSignatureValidationFails() throws Exception {
    final Sequence sequence = context.sequence("validateSequence");
    context.checking(new Expectations() {
      {
        oneOf(encryptionOperator).decrypt(ENCODED);
        inSequence(sequence);
        will(returnValue(DECRYPTED));
        oneOf(signatureOperator).verify(DECRYPTED);
        inSequence(sequence);
        will(throwException(new JWTSignatureException("invalid signature")));
      }
    });

    newValidator().validate(ENCODED);
  }

  @Test(expected = JWTEncryptionException.class)
  public void testValidateWhenDecryptionFails() throws Exception {
    final Sequence sequence = context.sequence("validateSequence");
    context.checking(new Expectations() {
      {
        oneOf(encryptionOperator).decrypt(ENCODED);
        inSequence(sequence);
        will(throwException(new JWTEncryptionException("invalid decryption")));
      }
    });

    newValidator().validate(ENCODED);
  }

  private JWTValidator newValidator() throws JWTConfigurationException {
    return Jose4jValidator.builder()
          .decryption(encryptionOperator)
          .signatureValidation(signatureOperator)
          .claimsAssertions(assertions)
          .clock(clock)
          .build();
  }

  private static ClaimsJTIMatcher claimsWithJti(String expected) {
    return new ClaimsJTIMatcher(expected);
  }

  private static class ClaimsJTIMatcher extends BaseMatcher<Claims> {

    private final String expected;

    public ClaimsJTIMatcher(String expected) {
      this.expected = expected;
    }

    @Override
    public boolean matches(Object o) {
      return expected.equals(((Claims) o).id().orElse(null));
    }

    @Override
    public void describeTo(Description description) {
      description.appendText("claims with jti=`")
          .appendText(expected)
          .appendText("`");
    }
  }
}
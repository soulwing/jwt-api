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

import org.jmock.Expectations;
import org.jmock.Sequence;
import org.jmock.auto.Mock;
import org.jmock.integration.junit4.JUnitRuleMockery;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.Claims;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.JWTGenerator;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;

/**
 * Unit tests for {@link Jose4jGenerator}.
 *
 * @author Carl Harris
 */
public class Jose4jGeneratorTest {

  private static final String PAYLOAD = "payload";
  private static final String SIGNED_PAYLOAD = "signedPayload";
  private static final String ENCRYPTED_PAYLOAD = "encryptedPayload";
  @Rule
  public final JUnitRuleMockery context = new JUnitRuleMockery();

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Mock
  private JWE encryptionOperator;

  @Mock
  private JWS signatureOperator;

  @Mock
  private Claims claims;


  @Test(expected = JWTConfigurationException.class)
  public void testBuildWithNoConfiguration() throws Exception {
    Jose4jGenerator.builder().build();
  }

  @Test
  public void testBuildWithNoSignatureOperator() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("signature");
    Jose4jGenerator.builder()
        .encryption(encryptionOperator)
        .build();
  }

  @Test
  public void testBuildWithNullEncryptionOperator() throws Exception {
    Jose4jGenerator.builder()
        .encryption(null)
        .signature(signatureOperator)
        .build();
  }

  @Test
  public void testGenerate() throws Exception {
    final Sequence sequence = context.sequence("generatorSequence");
    context.checking(new Expectations() {
      {
        oneOf(claims).toJson();
        inSequence(sequence);
        will(returnValue(PAYLOAD));
        oneOf(signatureOperator).sign(PAYLOAD);
        inSequence(sequence);
        will(returnValue(SIGNED_PAYLOAD));
        oneOf(encryptionOperator).encrypt(SIGNED_PAYLOAD);
        inSequence(sequence);
        will(returnValue(ENCRYPTED_PAYLOAD));
      }
    });

    final JWTGenerator generator = Jose4jGenerator.builder()
        .encryption(encryptionOperator)
        .signature(signatureOperator)
        .build();

    assertThat(generator.generate(claims), is(equalTo(ENCRYPTED_PAYLOAD)));
  }

  @Test
  public void testGenerateSignatureOnly() throws Exception {
    final Sequence sequence = context.sequence("generatorSequence");
    context.checking(new Expectations() {
      {
        oneOf(claims).toJson();
        inSequence(sequence);
        will(returnValue(PAYLOAD));
        oneOf(signatureOperator).sign(PAYLOAD);
        inSequence(sequence);
        will(returnValue(SIGNED_PAYLOAD));
      }
    });

    final JWTGenerator generator = Jose4jGenerator.builder()
        .signature(signatureOperator)
        .build();

    assertThat(generator.generate(claims), is(equalTo(SIGNED_PAYLOAD)));
  }

}
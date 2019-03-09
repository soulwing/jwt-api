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
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.KeyProvider;
import org.soulwing.jwt.api.KeyUtil;
import org.soulwing.jwt.api.SingletonKeyProvider;
import org.soulwing.jwt.api.exceptions.InvalidSignatureException;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;
import org.soulwing.jwt.api.exceptions.SignatureKeyNotFoundException;

/**
 * Unit tests for {@link Jose4jSignatureOperator}.
 *
 * @author Carl Harris
 */
public class Jose4JSignatureOperatorTest {

  private static final String KEY_ID = "keyId";
  private static final JWS.Algorithm ALGORITHM  = JWS.Algorithm.HS256;
  private static final String PAYLOAD = "This is just a plain old string";

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
    Jose4jSignatureOperator.builder().build();
  }

  @Test
  public void testBuildWhenNoKeyProvider() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("keyProvider");
    Jose4jSignatureOperator.builder()
        .algorithm(JWS.Algorithm.HS256)
        .build();
  }

  @Test
  public void testBuildWhenNoKeyProviderAndAlgorithmNone() throws Exception {
    Jose4jSignatureOperator.builder()
        .algorithm(JWS.Algorithm.none)
        .build();
  }

  @Test
  public void testBuildWhenNoAlgorithm() throws Exception {
    expectedException.expect(JWTConfigurationException.class);
    expectedException.expectMessage("algorithm");
    Jose4jSignatureOperator.builder()
        .keyProvider(SingletonKeyProvider.with(key))
        .build();
  }

  @Test
  public void testWithAlgorithmNone() throws Exception {
    expectedException.expect(JWTSignatureException.class);
    expectedException.expectMessage("blacklisted");
    final JWS operation =
        Jose4jSignatureOperator.builder()
            .algorithm(JWS.Algorithm.none)
            .build();

    operation.sign(PAYLOAD);
  }

  @Test
  public void testSignAndVerify() throws Exception {
    final JWS operator =
        Jose4jSignatureOperator.builder()
            .algorithm(JWS.Algorithm.HS256)
            .keyProvider(SingletonKeyProvider.with(KEY_ID, key))
            .build();

    final String encoded = operator.sign(PAYLOAD);
    final String header = new String(Base64.getUrlDecoder().decode(
        encoded.substring(0, encoded.indexOf('.'))), StandardCharsets.UTF_8);

    final JsonObject fields = Json.createReader(
        new StringReader(header)).readObject();

    assertThat(fields.getString("kid"), is(equalTo(KEY_ID)));
    assertThat(fields.getString("alg"), is(equalTo(ALGORITHM.toToken())));

    assertThat(operator.verify(encoded), is(equalTo(PAYLOAD)));
  }

  @Test
  public void testVerifyWithDifferentKeyThanSign() throws Exception {
    final JWS sign =
        Jose4jSignatureOperator.builder()
            .algorithm(JWS.Algorithm.HS256)
            .keyProvider(SingletonKeyProvider.with(key))
            .build();

    final JWS verify =
        Jose4jSignatureOperator.builder()
            .algorithm(JWS.Algorithm.HS256)
            .keyProvider(SingletonKeyProvider.with(otherKey))
            .build();

    expectedException.expect(InvalidSignatureException.class);
    verify.verify(sign.sign(PAYLOAD));
  }

  @Test(expected = JWTSignatureException.class)
  public void testSignWithInadequateKey() throws Exception {
    final JWS operator =
        Jose4jSignatureOperator.builder()
            .algorithm(JWS.Algorithm.HS384)
            .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
            .build();

    operator.sign("DON'T CARE");
  }

  @Test(expected = JWTSignatureException.class)
  public void testVerifyWithInadequateKey() throws Exception {
    final JWS operator =
        Jose4jSignatureOperator.builder()
            .algorithm(JWS.Algorithm.HS384)
            .keyProvider(SingletonKeyProvider.with(KeyUtil.newAesKey(256)))
            .build();

    operator.verify("DON'T CARE");
  }

  @Test(expected = SignatureKeyNotFoundException.class)
  public void testVerifyWhenKeyNotFound() throws Exception {


    final JWS operator =
        Jose4jSignatureOperator.builder()
            .algorithm(JWS.Algorithm.HS256)
            .keyProvider(keyProvider)
            .build();

    context.checking(new Expectations() {
      {
        oneOf(keyProvider).currentKey();
        will(returnValue(SingletonKeyProvider.with(KEY_ID, key).currentKey()));
        oneOf(keyProvider).retrieveKey(KEY_ID);
        will(returnValue(Optional.empty()));
      }
    });

    operator.verify(operator.sign(PAYLOAD));
  }

}
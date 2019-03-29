/*
 * File created on Mar 19, 2019
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
package org.soulwing.jwt.api.locator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.EnumSet;

import org.jmock.Expectations;
import org.jmock.auto.Mock;
import org.jmock.integration.junit4.JUnitRuleMockery;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.CertUtil;
import org.soulwing.jwt.api.KeyUtil;
import org.soulwing.jwt.api.PublicKeyInfo;
import org.soulwing.jwt.api.PublicKeyLocator;
import org.soulwing.jwt.api.X509CertificateValidator;

/**
 * Unit tests for {@link JcaPublicKeyLocator}.
 *
 * @author Carl Harris
 */
public class JcaPublicKeyLocatorTest {

  private static KeyPair keyPair;

  private static X509Certificate certificate;

  @Rule
  public final JUnitRuleMockery context = new JUnitRuleMockery();

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Mock
  private X509CertificateValidator validator;

  @Mock
  private X509CertificateValidator.Factory validatorFactory;


  @Mock
  private CertificateChainLoader chainLoader;

  @Mock
  private PublicKeyLocator.Criteria criteria;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    keyPair = KeyUtil.newRsaKeyPair();
    certificate = CertUtil.createSelfSignedCert("subjectName",
        keyPair, Duration.ZERO, false);
  }

  @Test
  public void testValidBuild() throws Exception {
    JcaPublicKeyLocator.builder()
        .certificateValidator(validator)
        .strategies(EnumSet.allOf(PublicKeyLocator.StrategyType.class))
        .build();
  }

  @Test
  public void testBuildWhenNoValidatorOrValidatorFactory() throws Exception {
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("certificate validator");
    JcaPublicKeyLocator.builder()
        .strategies(EnumSet.allOf(PublicKeyLocator.StrategyType.class))
        .build();
  }

  @Test
  public void testBuildWhenBothValidatorAndValidatorFactory() throws Exception {
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("either a certificate validator");
    JcaPublicKeyLocator.builder()
        .certificateValidator(validator)
        .certificateValidatorFactory(validatorFactory)
        .strategies(EnumSet.allOf(PublicKeyLocator.StrategyType.class))
        .build();
  }


  @Test
  public void testBuildWhenNoStrategies() throws Exception {
    JcaPublicKeyLocator.builder()
        .certificateValidator(validator)
        .build();
  }

  @Test
  public void testLocateViaCertificateChain() throws Exception {
    context.checking(new Expectations() {
      {
        oneOf(criteria).getCertificateChain();
        will(returnValue(Collections.singletonList(certificate)));
        oneOf(validatorFactory).getValidator(criteria,
            Collections.singletonList(certificate));
        will(returnValue(validator));
        oneOf(validator).validate(Collections.singletonList(certificate));
      }
    });

    final PublicKeyInfo actual = JcaPublicKeyLocator.builder()
        .certificateValidatorFactory(validatorFactory)
        .strategies(EnumSet.of(PublicKeyLocator.StrategyType.CERT_CHAIN))
        .build()
        .locate(criteria);

    assertThat(actual.getPublicKey(), is(equalTo(keyPair.getPublic())));
    assertThat(actual.getCertificates(), is(not(empty())));
  }

  @Test
  public void testLocateViaCertificateUrl() throws Exception {
    final URI url = URI.create("https://localhost/test");
    context.checking(new Expectations() {
      {
        oneOf(criteria).getCertificateChainUrl();
        will(returnValue(url));
        oneOf(chainLoader).load(url);
        will(returnValue(Collections.singletonList(certificate)));
        oneOf(validator).validate(Collections.singletonList(certificate));
      }
    });

    final PublicKeyInfo actual = JcaPublicKeyLocator.builder()
        .chainLoader(chainLoader)
        .certificateValidator(validator)
        .strategies(EnumSet.of(PublicKeyLocator.StrategyType.CERT_CHAIN_URL))
        .build()
        .locate(criteria);

    assertThat(actual.getPublicKey(), is(equalTo(keyPair.getPublic())));
    assertThat(actual.getCertificates(), is(not(empty())));
  }

}
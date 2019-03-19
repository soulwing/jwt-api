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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;
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
  private X509CertificateValidator certificateValidator;

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
        .certificateValidator(certificateValidator)
        .strategies(EnumSet.allOf(PublicKeyLocator.StrategyType.class))
        .build();
  }

  @Test
  public void testBuildWhenNoCertificateValidator() throws Exception {
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("certificate validator");
    JcaPublicKeyLocator.builder()
        .strategies(EnumSet.allOf(PublicKeyLocator.StrategyType.class))
        .build();
  }

  @Test
  public void testBuildWhenNoStrategies() throws Exception {
    JcaPublicKeyLocator.builder()
        .certificateValidator(certificateValidator)
        .build();
  }

  @Test
  public void testLocateViaCertificateChain() throws Exception {
    context.checking(new Expectations() {
      {
        oneOf(criteria).getCertificateChain();
        will(returnValue(Collections.singletonList(certificate)));
        oneOf(certificateValidator).validate(Collections.singletonList(certificate));
      }
    });

    final PublicKey actual = JcaPublicKeyLocator.builder()
        .certificateValidator(certificateValidator)
        .strategies(EnumSet.of(PublicKeyLocator.StrategyType.CERT_CHAIN))
        .build()
        .locate(criteria);

    assertThat(actual, is(equalTo(keyPair.getPublic())));
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
        oneOf(certificateValidator).validate(Collections.singletonList(certificate));
      }
    });

    final PublicKey actual = JcaPublicKeyLocator.builder()
        .chainLoader(chainLoader)
        .certificateValidator(certificateValidator)
        .strategies(EnumSet.of(PublicKeyLocator.StrategyType.CERT_CHAIN_URL))
        .build()
        .locate(criteria);

    assertThat(actual, is(equalTo(keyPair.getPublic())));
  }

}
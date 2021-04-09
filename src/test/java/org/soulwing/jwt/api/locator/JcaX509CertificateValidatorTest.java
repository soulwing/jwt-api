/*
 * File created on Mar 18, 2019
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

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

import java.security.KeyStore;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.jmock.integration.junit4.JUnitRuleMockery;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.CertUtil;
import org.soulwing.jwt.api.X509CertificateValidator;
import org.soulwing.jwt.api.exceptions.CertificateValidationException;

/**
 * Unit tests for {@link JcaX509CertificateValidator}.
 * @author Carl Harris
 */
public class JcaX509CertificateValidatorTest {

  @Rule
  public final JUnitRuleMockery context = new JUnitRuleMockery();

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Test
  public void testBuildWithNoClock() throws Exception {
    final X509Certificate trustedCert =
        CertUtil.createChain(1, Duration.ZERO).get(0);
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("clock");
    JcaX509CertificateValidator.builder()
        .trustStore(newTrustStore(trustedCert))
        .clock(null)
        .build();
  }

  @Test
  public void testBuildWithNoTrustStore() throws Exception {
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("trust");
    JcaX509CertificateValidator.builder()
        .build();
  }

  @Test
  public void testValidateWithGoodChain() throws Exception {
    final List<X509Certificate> chain = CertUtil.createChain(5,
        Duration.ofDays(1));
    newValidator(chain.get(chain.size() - 1)).validate(chain);
  }

  @Test
  public void testValidateWithNoTrustedRoot() throws Exception {
    final List<X509Certificate> chain = CertUtil.createChain(3,
        Duration.ofDays(1));
    expectedException.expect(CertificateValidationException.class);
    expectedException.expectCause(is(instanceOf(CertPathBuilderException.class)));
    expectedException.expectMessage("certification path");
    final X509Certificate trustedCert =
    CertUtil.createSelfSignedCert("root", Duration.ofDays(1), true);
    newValidator(trustedCert).validate(chain);
  }

  @Test
  public void testValidateWithExpiredSubjectCertificate() throws Exception {
    final List<X509Certificate> chain = CertUtil.createChain(3,
        Duration.ZERO, Duration.ofDays(1));
    expectedException.expect(CertificateValidationException.class);
    expectedException.expectCause(is(instanceOf(CertificateExpiredException.class)));
    expectedException.expectMessage(startsWith("certificate expired"));
    newValidator(chain.get(chain.size() - 1)).validate(chain);
  }

  @Test
  public void testValidateWithExpiredSubjectCertificateWithExpirationCheckDisabled() throws Exception {
    final List<X509Certificate> chain = CertUtil.createChain(3,
        Duration.ZERO, Duration.ofDays(1));
//    expectedException.expect(CertificateValidationException.class);
//    expectedException.expectCause(is(instanceOf(CertificateExpiredException.class)));
//    expectedException.expectMessage(startsWith("certificate expired"));
    newValidator(chain.get(chain.size() - 1), false).validate(chain);
  }

  @Test
  public void testValidateWithExpiredIssuerCertificate() throws Exception {
    final List<X509Certificate> chain = CertUtil.createChain(3,
        Duration.ofDays(1), Duration.ZERO, Duration.ofDays(1));
    expectedException.expect(CertificateValidationException.class);
    expectedException.expectCause(is(instanceOf(CertificateExpiredException.class)));
    expectedException.expectMessage(startsWith("issuer certificate expired"));
    newValidator(chain.get(chain.size() - 1)).validate(chain);
  }

  @Test
  public void testValidateWithExpiredRootCertificate() throws Exception {
    final List<X509Certificate> chain = CertUtil.createChain(3,
        Duration.ofDays(1), Duration.ofDays(1), Duration.ZERO);
    expectedException.expect(CertificateValidationException.class);
    expectedException.expectCause(is(instanceOf(CertificateExpiredException.class)));
    expectedException.expectMessage(startsWith("root certificate expired"));
    newValidator(chain.get(chain.size() - 1)).validate(chain);
  }

  @Test
  public void testValidateWithRevocationWhenNoRevocationStatus() throws Exception {
    final List<X509Certificate> chain = CertUtil.createChain(3,
        Duration.ofDays(1), Duration.ofDays(1), Duration.ofDays(1));
    expectedException.expect(CertificateValidationException.class);
    expectedException.expectMessage("certification path");
    JcaX509CertificateValidator.builder()
        .checkExpiration(true)
        .checkRevocation(true)
        .checkSubjectOnly(true)
        .trustStore(newTrustStore(chain.get(chain.size() - 1)))
        .build()
        .validate(chain);
  }

  private X509CertificateValidator newValidator(X509Certificate trustedCert)
      throws Exception {
    return newValidator(trustedCert, true);
  }


  private X509CertificateValidator newValidator(X509Certificate trustedCert,
      boolean checkExpiration)
      throws Exception {
    return JcaX509CertificateValidator.builder()
        .checkExpiration(checkExpiration)
        .checkRevocation(false)
        .checkSubjectOnly(false)
        .trustStore(newTrustStore(trustedCert))
        .build();
  }


  private KeyStore newTrustStore(X509Certificate trustedCert) throws Exception {
    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setEntry("root",
        new KeyStore.TrustedCertificateEntry(trustedCert),
        new KeyStore.PasswordProtection(null));
    return keyStore;
  }

}
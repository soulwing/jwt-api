/*
 * File created on Mar 27, 2019
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
package org.soulwing.jwt.api;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for {@link CertificateNameMatcher}.
 *
 * @author Carl Harris
 */
public class CertificateNameMatcherTest {

  private static final String SUBJECT_NAME = "subjectName";
  private static final String ALT_NAME = "altName";

  private static KeyPair keyPair;
  private static X509Certificate certificate;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    keyPair = KeyUtil.newRsaKeyPair();
    final X509Certificate cert = CertUtil.createSelfSignedCert(
        SUBJECT_NAME, ALT_NAME, keyPair, Duration.ZERO, false);

    // the JDK implementation of getSubjectAlternativeNames fails for
    // cert created by Bouncy Castle; so we encode and decode to get an
    // different implementation class
    certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
  }

  @Test
  public void testMatchWhenSubjectNameMatches() throws Exception {
    assertThat(
        CertificateNameMatcher.hasSubjectName(SUBJECT_NAME, certificate),
        is(true));
  }

  @Test
  public void testMatchWhenAltNameMatches() throws Exception {
    assertThat(
        CertificateNameMatcher.hasSubjectName(ALT_NAME, certificate),
        is(true));
  }

  @Test
  public void testMatchWhenNoMatch() throws Exception {
    assertThat(
        CertificateNameMatcher.hasSubjectName("other", certificate),
        is(false));
  }


}
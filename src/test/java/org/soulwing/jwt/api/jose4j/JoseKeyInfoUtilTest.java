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
package org.soulwing.jwt.api.jose4j;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

import java.net.URI;
import java.security.Key;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.junit.BeforeClass;
import org.junit.Test;
import org.soulwing.jwt.api.CertUtil;
import org.soulwing.jwt.api.KeyInfo;
import org.soulwing.jwt.api.KeyUtil;

/**
 * Unit tests for {@link JoseKeyInfoUtil}.
 *
 * @author Carl Harris
 */
public class JoseKeyInfoUtilTest {

  private static final String ID = "id";
  private static final URI CERTIFICATE_URL = URI.create("certificateUrl");
  private static Key key = KeyUtil.newAesKey(128);
  private static List<X509Certificate> certificates;

  private final JsonWebStructure jws = new JsonWebSignature();

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    certificates = CertUtil.createChain(2, Duration.ZERO);
  }

  @Test
  public void testWhenNoCertificates() throws Exception {
    JoseKeyInfoUtil.configureKeyInfo(jws, KeyInfo.builder()
        .id(ID)
        .key(key)
        .build());

    assertThat(jws.getKey(), is(sameInstance(key)));
    assertThat(jws.getKeyIdHeaderValue(), is(equalTo(ID)));
    assertThat(jws.getCertificateChainHeaderValue(),
        is(nullValue()));
    assertThat(jws.getX509CertSha1ThumbprintHeaderValue(),
        is(nullValue()));
    assertThat(jws.getX509CertSha256ThumbprintHeaderValue(),
        is(nullValue()));
    assertThat(jws.getHeader(HeaderParameterNames.X509_URL),
        is(nullValue()));
  }

  @Test
  public void testWhenCertificates() throws Exception {
    JoseKeyInfoUtil.configureKeyInfo(jws, KeyInfo.builder()
        .id(ID)
        .key(key)
        .certificates(certificates)
        .build());

    assertThat(jws.getKey(), is(sameInstance(key)));
    assertThat(jws.getKeyIdHeaderValue(), is(equalTo(ID)));
    assertThat(jws.getCertificateChainHeaderValue(),
        is(equalTo(certificates)));
    assertThat(jws.getX509CertSha1ThumbprintHeaderValue(),
        is(not(nullValue())));
    assertThat(jws.getX509CertSha256ThumbprintHeaderValue(),
        is(not(nullValue())));
    assertThat(jws.getHeader(HeaderParameterNames.X509_URL),
        is(nullValue()));
  }

  @Test
  public void testWhenCertificateUrl() throws Exception {
    JoseKeyInfoUtil.configureKeyInfo(jws, KeyInfo.builder()
        .id(ID)
        .key(key)
        .certificates(certificates)
        .certificateUrl(CERTIFICATE_URL)
        .build());

    assertThat(jws.getKey(), is(sameInstance(key)));
    assertThat(jws.getKeyIdHeaderValue(), is(equalTo(ID)));
    assertThat(jws.getCertificateChainHeaderValue(),
        is(nullValue()));
    assertThat(jws.getX509CertSha1ThumbprintHeaderValue(),
        is(not(nullValue())));
    assertThat(jws.getX509CertSha256ThumbprintHeaderValue(),
        is(not(nullValue())));
    assertThat(jws.getHeader(HeaderParameterNames.X509_URL),
        is(equalTo(CERTIFICATE_URL.toString())));
  }


}
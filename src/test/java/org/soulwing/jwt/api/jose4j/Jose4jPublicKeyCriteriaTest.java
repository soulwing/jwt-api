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
package org.soulwing.jwt.api.jose4j;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.net.URI;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.junit.BeforeClass;
import org.junit.Test;
import org.soulwing.jwt.api.CertUtil;

/**
 * Unit tests for {@link Jose4jPublicKeyCriteria}.
 *
 * @author Carl Harris
 */
public class Jose4jPublicKeyCriteriaTest {

  private JsonWebSignature signature = new JsonWebSignature();

  private Jose4jPublicKeyCriteria criteria =
      new Jose4jPublicKeyCriteria(signature);

  private static List<X509Certificate> chain;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    chain = CertUtil.createChain(2, Duration.ZERO);
  }

  @Test
  public void testGetKeyId() throws Exception {
    assertThat(criteria.getKeyId(), is(nullValue()));
    signature.setKeyIdHeaderValue("id");
    assertThat(criteria.getKeyId(), is(equalTo("id")));
  }

  @Test
  public void testGetCertificateChain() throws Exception {
    assertThat(criteria.getCertificateChain(), is(nullValue()));
    signature.setCertificateChainHeaderValue(
        chain.toArray(new X509Certificate[0]));
    assertThat(criteria.getCertificateChain(), is(equalTo(chain)));
  }

  @Test
  public void testGetCertificateChainUrl() throws Exception {
    assertThat(criteria.getCertificateChainUrl(), is(nullValue()));
    final URI uri = URI.create("https://localhost/certs");
    signature.setHeader(Jose4jPublicKeyCriteria.X5U, uri.toString());
    assertThat(criteria.getCertificateChainUrl(), is(equalTo(uri)));
  }

  @Test
  public void testGetCertificateThumbprintWhenSha1() throws Exception {
    assertThat(criteria.getCertificateThumbprint(), is(nullValue()));
    signature.setX509CertSha1ThumbprintHeaderValue(chain.get(0));
    assertThat(criteria.getCertificateThumbprint(), is(not(nullValue())));
  }

  @Test
  public void testGetCertificateThumbprintWhenSha256() throws Exception {
    assertThat(criteria.getCertificateThumbprint(), is(nullValue()));
    signature.setX509CertSha256ThumbprintHeaderValue(chain.get(0));
    assertThat(criteria.getCertificateThumbprint(), is(not(nullValue())));
  }

  @Test
  public void testGetWebKey() throws Exception {
    final PublicKey publicKey = chain.get(0).getPublicKey();
    JsonWebKey jwk = JsonWebKey.Factory.newJwk(publicKey);
    assertThat(criteria.getWebKey(), is(nullValue()));
    signature.getHeaders().setJwkHeaderValue(Jose4jPublicKeyCriteria.JWK, jwk);
    assertThat(criteria.getWebKey().getKey(), is(equalTo(publicKey)));
  }

  @Test
  public void testGetWebKeyUrl() throws Exception {
    assertThat(criteria.getWebKeyUrl(), is(nullValue()));
    final URI uri = URI.create("https://localhost/certs");
    signature.setHeader(Jose4jPublicKeyCriteria.JKU, uri.toString());
    assertThat(criteria.getWebKeyUrl(), is(equalTo(uri)));
  }


}
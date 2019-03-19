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
import static org.hamcrest.Matchers.is;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.jose4j.jws.JsonWebSignature;
import org.junit.Test;
import org.soulwing.jwt.api.CertUtil;

/**
 * Unit tests for {@link Jose4jPublicKeyThumbprint}.
 * @author Carl Harris
 */
public class Jose4jPublicKeyThumbprintTest {

  private JsonWebSignature signature = new JsonWebSignature();

  private Jose4jPublicKeyThumbprint thumbprint =
      new Jose4jPublicKeyThumbprint(signature);

  @Test
  public void testWithSha1Thumbprint() throws Exception {
    final X509Certificate certificate = CertUtil.createChain(1,
        Duration.ZERO).get(0);
    signature.setX509CertSha1ThumbprintHeaderValue(certificate);


    assertThat(thumbprint.matcher().test(certificate), is(true));
  }

  @Test
  public void testWithSha256Thumbprint() throws Exception {
    final X509Certificate certificate = CertUtil.createChain(1,
        Duration.ZERO).get(0);
    signature.setX509CertSha256ThumbprintHeaderValue(certificate);

    assertThat(thumbprint.matcher().test(certificate), is(true));
  }

  @Test
  public void testWhenCertificateMismatch() throws Exception {
    final List<X509Certificate> chain = CertUtil.createChain(2,
        Duration.ZERO);
    final X509Certificate certificate = chain.get(0);
    signature.setX509CertSha256ThumbprintHeaderValue(certificate);
    signature.setX509CertSha1ThumbprintHeaderValue(certificate);

    assertThat(thumbprint.matcher().test(chain.get(1)), is(false));
  }


}
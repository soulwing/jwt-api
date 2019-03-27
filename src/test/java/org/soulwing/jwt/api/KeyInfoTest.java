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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Unit tests for {@link KeyInfo}.
 * @author Carl Harris
 */
public class KeyInfoTest {

  private static final URI CERTIFICATE_URI = URI.create("certificateUri");
  private static final String ID = "id";

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Test
  public void testBuildWithNoKey() throws Exception {
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("key");
    KeyInfo.builder().build();
  }

  @Test
  public void testBuild() throws Exception {
    final Key key = KeyUtil.newAesKey(128);
    final List<X509Certificate> certs = CertUtil.createChain(2, Duration.ZERO);
    final KeyInfo keyInfo = KeyInfo.builder()
        .id(ID)
        .key(key)
        .certificates(certs)
        .certificateUrl(CERTIFICATE_URI)
        .build();

    assertThat(keyInfo.getId(), is(equalTo(ID)));
    assertThat(keyInfo.getKey(), is(sameInstance(key)));
    assertThat(keyInfo.getCertificates(), is(equalTo(certs)));
    assertThat(keyInfo.getCertificateUrl(), is(equalTo(CERTIFICATE_URI)));
  }

}
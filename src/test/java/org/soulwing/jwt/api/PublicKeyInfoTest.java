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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Unit tests for {@link PublicKeyInfo}.
 *
 * @author Carl Harris
 */
public class PublicKeyInfoTest {

  private static KeyPair keyPair;
  private static List<X509Certificate> certificates;

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    keyPair = KeyUtil.newRsaKeyPair();
    certificates = CertUtil.createChain(2, Duration.ZERO);
  }

  @Test
  public void testBuildWithNoPublicKey() throws Exception {
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("public key");
    PublicKeyInfo.builder().build();
  }

  @Test
  public void testBuildSuccess() throws Exception {
    final PublicKeyInfo info = PublicKeyInfo.builder()
        .publicKey(keyPair.getPublic())
        .certificates(certificates)
        .build();

    assertThat(info.getPublicKey(), is(sameInstance(keyPair.getPublic())));
    assertThat(info.getCertificates(), is(equalTo(certificates)));
  }

}
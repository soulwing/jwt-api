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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import java.security.KeyPair;
import java.time.Clock;

import org.junit.Test;
import org.soulwing.jwt.api.KeyUtil;
import org.soulwing.jwt.api.MockClock;
import org.soulwing.jwt.api.PublicKeyInfo;

/**
 * Unit tests for {@link Jose4jVerificationResult}.
 * @author Carl Harris
 */
public class Jose4jVerificationResultTest {

  private static final String PAYLOAD = "payload";

  private static KeyPair keyPair = KeyUtil.newRsaKeyPair();

  @Test
  public void test() throws Exception {
    final PublicKeyInfo publicKeyInfo = PublicKeyInfo.builder()
        .publicKey(keyPair.getPublic())
        .build();

    final Jose4jVerificationResult result =
        new Jose4jVerificationResult(PAYLOAD, publicKeyInfo);
    assertThat(result.getPayload(), is(sameInstance(PAYLOAD)));
    assertThat(result.getPublicKeyInfo(), is(sameInstance(publicKeyInfo)));
  }

}
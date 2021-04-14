/*
 * File created on Apr 14, 2021
 *
 * Copyright (c) 2021 Carl Harris, Jr
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
package org.soulwing.jwt.api.jca;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonArray;
import javax.json.JsonObject;

import org.junit.Test;
import org.soulwing.jwt.api.JWKS;

/**
 * Unit tests for {@link JcaJsonWebKeySet}.
 *
 * @author Carl Harris
 */
public class JcaJsonWebKeySetTest {

  private static final byte[] KEY = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };

  private static final String ENCODED_KEY =
      Base64.getUrlEncoder().withoutPadding().encodeToString(KEY);

  @Test
  public void testBuildOne() throws Exception {
    JWKS jwks = JcaJsonWebKeySet.builder()
        .add(JcaJsonWebKey.builder().key(new SecretKeySpec(KEY, "AES")).build())
        .build();

    JsonObject actual = jwks.toJson();
    assertThat(actual.getJsonArray("keys"), is(not(nullValue())));
    JsonArray keys = actual.getJsonArray("keys");
    assertThat(keys.size(), is(equalTo(1)));
    JsonObject key = keys.getJsonObject(0);
    assertThat(key.getString("kty"), is("oct"));
    assertThat(key.getString("k"), is(equalTo(ENCODED_KEY)));
  }

  @Test
  public void testBuildTwo() throws Exception {
    JWKS jwks = JcaJsonWebKeySet.builder()
        .add(JcaJsonWebKey.builder().id("0").key(new SecretKeySpec(KEY, "AES")))
        .add(JcaJsonWebKey.builder().id("1").key(new SecretKeySpec(KEY, "AES")))
        .build();

    JsonObject actual = jwks.toJson();
    assertThat(actual.getJsonArray("keys"), is(not(nullValue())));
    JsonArray keys = actual.getJsonArray("keys");
    assertThat(keys.size(), is(equalTo(2)));
    assertThat(keys.getJsonObject(0).getString("kid"), is(equalTo("0")));
    assertThat(keys.getJsonObject(1).getString("kid"), is(equalTo("1")));
  }


}

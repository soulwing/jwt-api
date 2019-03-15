/*
 * File created on Mar 8, 2019
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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.soulwing.jwt.api.Claims;

/**
 * Unit tests for {@link Jose4jClaimsBuilder}.
 *
 * @author Carl Harris
 */
public class Jose4jClaimsBuilderTest {

  private static final String ID = "id";
  private static final String ISSUER = "issuer";
  private static final String SUBJECT = "subject";
  private static final String AUDIENCE = "audience";
  private static final String OTHER_AUDIENCE = "otherAudience";

  private static final String CLAIM_NAME = "claimName";
  private static final String STRING_VALUE = "stringValue";
  private static final Number NUMBER_VALUE = 42;
  private static final Boolean BOOLEAN_VALUE = true;

  private static final Instant ISSUED_AT = Instant.ofEpochSecond(
      Instant.now().getEpochSecond());

  private static final Instant EXPIRES_AT = ISSUED_AT.plusSeconds(30);

  private Jose4jClaimsBuilder builder = new Jose4jClaimsBuilder();

  @Test
  public void testBuildWithId() throws Exception {
    assertThat(builder.id(ID).build().id().orElse(null),
        is(equalTo(ID)));
  }

  @Test
  public void testBuildWithIssuer() throws Exception {
    assertThat(builder.issuer(ISSUER).build().issuer().orElse(null),
        is(equalTo(ISSUER)));
  }

  @Test
  public void testBuildWithSubject() throws Exception {
    assertThat(builder.subject(SUBJECT).build().subject().orElse(null),
        is(equalTo(SUBJECT)));
  }

  @Test
  public void testBuildWithOneAudience() throws Exception {
    assertThat(builder.audience(AUDIENCE).build().getAudience().contains(AUDIENCE),
        is(true));
  }

  @Test
  public void testBuildWithMultipleAudiences() throws Exception {
    final Claims claims = builder.audience(AUDIENCE, OTHER_AUDIENCE).build();
    assertThat(claims.getAudience().contains(AUDIENCE), is(true));
    assertThat(claims.getAudience().contains(OTHER_AUDIENCE), is(true));
  }

  @Test
  public void testBuildWithIssuedAt() throws Exception {
    assertThat(builder.issuedAt(ISSUED_AT).build().issuedAt().orElse(null),
        is(equalTo(ISSUED_AT)));
  }

  @Test
  public void testBuildWithExpiresAt() throws Exception {
    assertThat(builder.expiresAt(EXPIRES_AT).build().expiresAt().orElse(null),
        is(equalTo(EXPIRES_AT)));
  }

  @Test
  public void testBuildWithStringClaim() throws Exception {
    assertThat(builder.set(CLAIM_NAME, STRING_VALUE).build()
        .claim(CLAIM_NAME, String.class).orElse(null), is(equalTo(STRING_VALUE)));
  }

  @Test
  public void testBuildWithNumberClaim() throws Exception {
    assertThat(builder.set(CLAIM_NAME, NUMBER_VALUE).build()
        .claim(CLAIM_NAME, Integer.class).orElse(null),
            is(equalTo(NUMBER_VALUE.intValue())));
  }

  @Test
  public void testBuildWithBooleanClaim() throws Exception {
    assertThat(builder.set(CLAIM_NAME, BOOLEAN_VALUE).build()
        .claim(CLAIM_NAME, Boolean.class).orElse(null),
            is(equalTo(BOOLEAN_VALUE)));
  }

  @Test
  public void testBuildWithVarArgsClaim() throws Exception {
    assertThat(builder.set(CLAIM_NAME, STRING_VALUE, NUMBER_VALUE).build()
        .claim(CLAIM_NAME, Object[].class).orElse(null),
            is(equalTo(new Object[] { STRING_VALUE, NUMBER_VALUE })));
  }

  @Test
  public void testBuildWithArrayClaim() throws Exception {
    final String[] values = {STRING_VALUE};
    assertThat(builder.set(CLAIM_NAME, values).build()
        .claim(CLAIM_NAME, String[].class).orElse(null), is(equalTo(values)));
  }

  @Test
  public void testBuildWithListClaim() throws Exception {
    final List values = Collections.singletonList(STRING_VALUE);
    assertThat(builder.set(CLAIM_NAME, values).build()
        .claim(CLAIM_NAME, List.class).orElse(null), is(equalTo(values)));
  }

  @Test
  public void testBuildWithSetClaim() throws Exception {
    final Set values = Collections.singleton(STRING_VALUE);
    assertThat(builder.set(CLAIM_NAME, values).build()
        .claim(CLAIM_NAME, Set.class).orElse(null), is(equalTo(values)));
  }

  @Test
  public void testBuildWithSingleObjectValue() throws Exception {
    final Object value = new Object();
    assertThat(builder.set(CLAIM_NAME, value).build()
        .claim(CLAIM_NAME, Object.class).orElse(null), is(sameInstance(value)));
  }

  @Test
  public void testBuildWithMultipleObjectValue() throws Exception {
    final Object value = new Object();
    final Object otherValue = new Object();
    final Claims claims = builder.set(CLAIM_NAME, value, otherValue).build();
    assertThat(claims.claim(CLAIM_NAME, Object.class).orElse(null),
        is(instanceOf(List.class)));
    final List<?> actual = (List<?>)
        claims.claim(CLAIM_NAME, List.class).orElse(null);
    assertThat(actual, contains(value, otherValue));
  }

}
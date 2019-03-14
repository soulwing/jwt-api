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
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.io.StringReader;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.json.Json;
import javax.json.JsonObject;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.Claims;

/**
 * Unit tests for {@link Jose4jClaims}.
 *
 * @author Carl Harris
 */
public class Jose4jClaimsTest {

  private static final String CLAIM_NAME = "claimName";
  private static final String STRING_VALUE = "stringValue";
  private static final Number NUMBER_VALUE = 42;
  private static final Boolean BOOLEAN_VALUE = true;

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  private JwtClaims delegate = new JwtClaims();
  private Jose4jClaims claims = new Jose4jClaims(delegate);

  @Test
  public void testGetId() throws Exception {
    delegate.setJwtId(STRING_VALUE);
    assertThat(claims.getId(), is(equalTo(STRING_VALUE)));
  }

  @Test
  public void testGetIdWhenNotPresent() throws Exception {
    expectedException.expect(NullPointerException.class);
    expectedException.expectMessage(Claims.JTI);
    claims.getId();
  }

  @Test
  public void testGetIssuer() throws Exception {
    delegate.setIssuer(STRING_VALUE);
    assertThat(claims.getIssuer(), is(equalTo(STRING_VALUE)));
  }

  @Test
  public void testGetIssuerWhenNotPresent() throws Exception {
    expectedException.expect(NullPointerException.class);
    expectedException.expectMessage(Claims.ISS);
    claims.getIssuer();
  }

  @Test
  public void testGetAudience() throws Exception {
    delegate.setAudience(STRING_VALUE);
    assertThat(claims.getAudience(),
        is(equalTo(Collections.singletonList(STRING_VALUE))));
  }

  @Test
  public void testGetAudienceWhenNotPresent() throws Exception {
    expectedException.expect(NullPointerException.class);
    expectedException.expectMessage(Claims.AUD);
    claims.getAudience();
  }

  @Test
  public void testGetSubject() throws Exception {
    delegate.setSubject(STRING_VALUE);
    assertThat(claims.getSubject(), is(equalTo(STRING_VALUE)));
  }

  @Test
  public void testGetSubjectWhenNotPresent() throws Exception {
    expectedException.expect(NullPointerException.class);
    expectedException.expectMessage(Claims.SUB);
    claims.getSubject();
  }

  @Test
  public void testGetIssuedAt() throws Exception {
    delegate.setIssuedAt(NumericDate.fromSeconds(NUMBER_VALUE.longValue()));
    assertThat(claims.getIssuedAt(), 
        is(equalTo(Instant.ofEpochSecond(NUMBER_VALUE.longValue()))));
  }

  @Test
  public void testGetIssuedAtWhenNotPresent() throws Exception {
    expectedException.expect(NullPointerException.class);
    expectedException.expectMessage(Claims.IAT);
    claims.getIssuedAt();
  }

  @Test
  public void testGetExpiresAt() throws Exception {
    delegate.setExpirationTime(NumericDate.fromSeconds(NUMBER_VALUE.longValue()));
    assertThat(claims.getExpiresAt(),
        is(equalTo(Instant.ofEpochSecond(NUMBER_VALUE.longValue()))));
  }

  @Test
  public void testGetExpiresAtWhenNotPresent() throws Exception {
    expectedException.expect(NullPointerException.class);
    expectedException.expectMessage(Claims.EXP);
    claims.getExpiresAt();
  }

  @Test
  public void testGetIdOptional() throws Exception {
    delegate.setJwtId(STRING_VALUE);
    assertThat(claims.id().orElse(null), is(equalTo(STRING_VALUE)));
  }

  @Test
  public void testGetIssuerOptional() throws Exception {
    delegate.setIssuer(STRING_VALUE);
    assertThat(claims.issuer().orElse(null), is(equalTo(STRING_VALUE)));
  }

  @Test
  public void testGetAudiencesOptionalWhenString() throws Exception {
    delegate.setAudience(STRING_VALUE);
    assertThat(claims.audiences().orElse(null),
        is(equalTo(Collections.singletonList(STRING_VALUE))));
  }

  @Test
  public void testGetAudiencesOptionalWhenList() throws Exception {
    final List<String> audiences =
        Arrays.asList(STRING_VALUE, "other" + STRING_VALUE);
    delegate.setAudience(audiences);
    final Optional<List> actual = claims.audiences();
    assertThat(actual.isPresent(), is(true));
    assertThat(actual.get().contains(STRING_VALUE), is(true));
  }

  @Test
  public void testGetAudiencesOptionalWhenOtherType() throws Exception {
    delegate.setClaim(Claims.AUD, NUMBER_VALUE);
    assertThat(claims.audiences().orElse(null),
        is(equalTo(Collections.singletonList(NUMBER_VALUE))));
  }

  @Test
  public void testGetAudiencesOptionalWhenNoAudience() throws Exception {
    assertThat(claims.audiences().isPresent(), is(false));
  }

  @Test
  public void testGetIssuedAtOptional() throws Exception {
    delegate.setIssuedAt(NumericDate.fromSeconds(NUMBER_VALUE.longValue()));
    assertThat(claims.issuedAt().orElse(null),
        is(equalTo(Instant.ofEpochSecond(NUMBER_VALUE.longValue()))));
  }

  @Test
  public void testGetExpiresAtOptional() throws Exception {
    delegate.setExpirationTime(NumericDate.fromSeconds(NUMBER_VALUE.longValue()));
    assertThat(claims.expiresAt().orElse(null),
        is(equalTo(Instant.ofEpochSecond(NUMBER_VALUE.longValue()))));
  }

  @Test
  public void testGetSubjectOptional() throws Exception {
    delegate.setSubject(STRING_VALUE);
    assertThat(claims.subject().orElse(null), is(equalTo(STRING_VALUE)));
  }

  @Test
  public void testGetStringOptional() throws Exception {
    delegate.setClaim(CLAIM_NAME, STRING_VALUE);
    assertThat(claims.claim(CLAIM_NAME, String.class).orElse(null),
        is(equalTo(STRING_VALUE)));
  }

  @Test
  public void testGetStringOptionalWhenNotFound() throws Exception {
    assertThat(claims.claim(CLAIM_NAME, String.class).isPresent(), is(false));
  }

  @Test(expected = ClassCastException.class)
  public void testGetStringOptionalWhenWrongType() throws Exception {
    delegate.setClaim(CLAIM_NAME, STRING_VALUE);
    claims.claim(CLAIM_NAME, Boolean.class);
  }

  @Test
  public void testGetBooleanOptional() throws Exception {
    delegate.setClaim(CLAIM_NAME, BOOLEAN_VALUE);
    assertThat(claims.claim(CLAIM_NAME, Boolean.class).orElse(null),
        is(equalTo(BOOLEAN_VALUE)));
  }

  @Test
  public void testGetBooleanOptionalWhenNotFound() throws Exception {
    assertThat(claims.claim(CLAIM_NAME, Boolean.class).isPresent(), is(false));
  }

  @Test(expected = ClassCastException.class)
  public void testGetBooleanOptionalWhenWrongType() throws Exception {
    delegate.setClaim(CLAIM_NAME, BOOLEAN_VALUE);
    claims.claim(CLAIM_NAME, String.class);
  }

  @Test
  public void testGetNumberOptionalAsLong() throws Exception {
    delegate.setClaim(CLAIM_NAME, NUMBER_VALUE);
    assertThat(claims.claim(CLAIM_NAME, Long.class).orElse(null),
        is(equalTo(NUMBER_VALUE.longValue())));
  }

  @Test
  public void testGetNumberOptionalAsInteger() throws Exception {
    delegate.setClaim(CLAIM_NAME, NUMBER_VALUE);
    assertThat(claims.claim(CLAIM_NAME, Integer.class).orElse(null),
        is(equalTo(NUMBER_VALUE.intValue())));
  }

  @Test
  public void testGetNumberOptionalAsDouble() throws Exception {
    delegate.setClaim(CLAIM_NAME, NUMBER_VALUE);
    assertThat(claims.claim(CLAIM_NAME, Double.class).orElse(null),
        is(equalTo(NUMBER_VALUE.doubleValue())));
  }

  @Test
  public void testGetNumberOptionalWhenNotFound() throws Exception {
    assertThat(claims.claim(CLAIM_NAME, Number.class).isPresent(), is(false));
  }

  @Test(expected = ClassCastException.class)
  public void testGetNumberOptionalWhenWrongType() throws Exception {
    delegate.setClaim(CLAIM_NAME, STRING_VALUE);
    claims.claim(CLAIM_NAME, Number.class);
  }

  @Test
  public void testGetArrayOptionalAsList() throws Exception {
    delegate.setClaim(CLAIM_NAME, Collections.singletonList(STRING_VALUE));
    final Optional<List> actual = claims.claim(CLAIM_NAME, List.class);
    assertThat(actual.isPresent(), is(true));
    assertThat(actual.get().contains(STRING_VALUE), is(true));
  }

  @Test
  public void testGetArrayOptionalAsSet() throws Exception {
    delegate.setClaim(CLAIM_NAME, Collections.singletonList(STRING_VALUE));
    final Optional<Set> actual = claims.claim(CLAIM_NAME, Set.class);
    assertThat(actual.isPresent(), is(true));
    assertThat(actual.get().contains(STRING_VALUE), is(true));
  }

  @Test
  public void testGetArrayOptionalAsArray() throws Exception {
    delegate.setClaim(CLAIM_NAME, Collections.singletonList(STRING_VALUE));
    final Optional<String[]> actual = claims.claim(CLAIM_NAME, String[].class);
    assertThat(actual.isPresent(), is(true));
    assertThat(actual.get(), is(instanceOf(String[].class)));
    assertThat(Arrays.asList(actual.get()).contains(STRING_VALUE), is(true));
  }

  @Test
  public void testNames() throws Exception {
    delegate.setClaim(CLAIM_NAME, STRING_VALUE);
    assertThat(claims.names(), contains(CLAIM_NAME));
  }

  @Test
  public void testToJson() throws Exception {
    delegate.setSubject(STRING_VALUE);
    String json = claims.toJson();
    assertThat(json, is(not(nullValue())));
    final JsonObject obj =
        Json.createReader(new StringReader(json)).readObject();
    assertThat(obj.getString(Claims.SUB), is(equalTo(STRING_VALUE)));
  }

}
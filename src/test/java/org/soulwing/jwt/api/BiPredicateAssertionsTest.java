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
package org.soulwing.jwt.api;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.time.Duration;
import java.time.Instant;

import org.junit.Test;

/**
 * Units tests for {@link BiPredicateAssertions}.
 *
 * @author Carl Harris
 */
public class BiPredicateAssertionsTest {

  private static final String ISSUER = "issuer";
  private static final String SUBJECT = "subject";
  private static final String AUDIENCE = "audience";
  private static final String CLAIM_NAME = "claimName";
  private static final String STRING_VALUE = "stringValue";
  private static final Number NUMBER_VALUE = 42;

  private static final Duration TOLERANCE = Duration.ofSeconds(10);
  private static final Duration LIFETIME = Duration.ofSeconds(100);
  private static final Instant ISSUED_AT = Instant.ofEpochSecond(0);
  private static final Instant EXPIRES_AT = ISSUED_AT.plus(LIFETIME);
  private static final String ID = "id";

  private MockClock clock = new MockClock();
  private MockClaims claims = new MockClaims();

  @Test
  public void testRequireIdWhenNonEmptyString() throws Exception {
    claims.put(Claims.JTI, ID);
    assertThat(BiPredicateAssertions.builder()
        .requireId()
        .build().test(claims, clock), is(true));
  }

  @Test
  public void testRequireIdWhenEmptyString() throws Exception {
    claims.put(Claims.JTI, "");
    assertThat(BiPredicateAssertions.builder()
        .requireId()
        .build().test(claims, clock), is(false));
  }

  @Test
  public void testRequireIdWhenNull() throws Exception {
    claims.put(Claims.JTI, null);
    assertThat(BiPredicateAssertions.builder()
        .requireId()
        .build().test(claims, clock), is(false));
  }

  @Test
  public void testRequireIdWhenNotString() throws Exception {
    claims.put(Claims.JTI, 42);
    assertThat(BiPredicateAssertions.builder()
        .requireId()
        .build().test(claims, clock), is(false));
  }

  @Test
  public void testRequireIdWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireId()
        .build().test(claims, clock), is(false));
  }

  @Test
  public void testRequireIdSatisfies() throws Exception {
    claims.put(Claims.JTI, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireIdSatisfies((v) -> v.equals(STRING_VALUE))
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireLifetimeNotExceededWhenClockEqualsLifetimeMinusOne() throws Exception {
    claims.put(Claims.IAT, ISSUED_AT.getEpochSecond());
    assertThat(BiPredicateAssertions.builder()
        .requireLifetimeNotExceeded(LIFETIME)
        .build()
        .test(claims, new MockClock(ISSUED_AT.plus(LIFETIME).minusSeconds(1))), is(true));
  }

  @Test
  public void testRequireLifetimeNotExceededWhenClockEqualsLifetime() throws Exception {
    claims.put(Claims.IAT, ISSUED_AT.getEpochSecond());
    assertThat(BiPredicateAssertions.builder()
        .requireLifetimeNotExceeded(LIFETIME)
        .build()
        .test(claims, new MockClock(ISSUED_AT.plus(LIFETIME))), is(false));
  }

  @Test
  public void testRequireLifetimeNotExceededWhenTypeMismatch() throws Exception {
    claims.put(Claims.IAT, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireLifetimeNotExceeded(LIFETIME)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireLifetimeNotExceededWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireLifetimeNotExceeded(LIFETIME)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireIssuedAtSatisfies() throws Exception {
    claims.put(Claims.IAT, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireIssuedAtSatisfies((t, clock) ->
            t.equals(Instant.ofEpochSecond(NUMBER_VALUE.longValue())))
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireNotExpiredWhenClockEqualsExpiresMinusOne() throws Exception {
    claims.put(Claims.EXP, EXPIRES_AT.getEpochSecond());
    assertThat(BiPredicateAssertions.builder()
        .requireNotExpired(Duration.ZERO)
        .build()
        .test(claims, new MockClock(EXPIRES_AT.minusSeconds(1))), is(true));
  }

  @Test
  public void testRequireNotExpiredWhenClockEqualsExpires() throws Exception {
    claims.put(Claims.EXP, EXPIRES_AT.getEpochSecond());
    assertThat(BiPredicateAssertions.builder()
        .requireNotExpired(Duration.ZERO)
        .build()
        .test(claims, new MockClock(EXPIRES_AT)), is(false));
  }

  @Test
  public void testRequireNotExpiredWithToleranceWhenClockEqualsExpires()
       throws Exception {
    claims.put(Claims.EXP, EXPIRES_AT.getEpochSecond());
    assertThat(BiPredicateAssertions.builder()
        .requireNotExpired(TOLERANCE)
        .build()
        .test(claims, new MockClock(EXPIRES_AT)), is(true));
  }

  @Test
  public void testRequireNotExpiredWithToleranceWhenClockEqualsExpiresPlusTolerance()
      throws Exception {
    claims.put(Claims.EXP, EXPIRES_AT.getEpochSecond());
    assertThat(BiPredicateAssertions.builder()
        .requireNotExpired(TOLERANCE)
        .build()
        .test(claims, new MockClock(EXPIRES_AT.plus(TOLERANCE))), is(false));
  }

  @Test
  public void testRequireNotExpiredWhenTypeMismatch() throws Exception {
    claims.put(Claims.EXP, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireNotExpired(TOLERANCE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireNotExpiredWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireNotExpired(TOLERANCE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireExpirationSatisfies() throws Exception {
    claims.put(Claims.EXP, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireExpirationSatisfies((t, clock) ->
            t.equals(Instant.ofEpochSecond(NUMBER_VALUE.longValue())))
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireIssuerMatches() throws Exception {
    claims.put(Claims.ISS, ISSUER);
    assertThat(BiPredicateAssertions.builder()
        .requireIssuer(ISSUER)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireIssuerMatchesOneOf() throws Exception {
    claims.put(Claims.ISS, ISSUER);
    assertThat(BiPredicateAssertions.builder()
        .requireIssuer("other" + ISSUER, ISSUER)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireIssuerWhenNoMatch() throws Exception {
    claims.put(Claims.ISS, ISSUER);
    assertThat(BiPredicateAssertions.builder()
        .requireIssuer("other1" + ISSUER, "other2" + ISSUER)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireIssuerWhenNotString() throws Exception {
    claims.put(Claims.ISS, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireIssuer(ISSUER)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireIssuerWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireIssuer(ISSUER)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireIssuerSatisfies() throws Exception {
    claims.put(Claims.ISS, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireIssuerSatisfies((v) -> v.equals(STRING_VALUE))
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireSubjectMatches() throws Exception {
    claims.put(Claims.SUB, SUBJECT);
    assertThat(BiPredicateAssertions.builder()
        .requireSubject(SUBJECT)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireSubjectMatchesOneOf() throws Exception {
    claims.put(Claims.SUB, SUBJECT);
    assertThat(BiPredicateAssertions.builder()
        .requireSubject("other" + SUBJECT, SUBJECT)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireSubjectWhenNoMatch() throws Exception {
    claims.put(Claims.SUB, SUBJECT);
    assertThat(BiPredicateAssertions.builder()
        .requireSubject("other1" + SUBJECT, "other2" + SUBJECT)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireSubjectWhenNotString() throws Exception {
    claims.put(Claims.SUB, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireSubject(SUBJECT)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireSubjectWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireSubject(SUBJECT)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireSubjectSatisfies() throws Exception {
    claims.put(Claims.SUB, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireSubjectSatisfies((v) -> v.equals(STRING_VALUE))
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireAudienceMatches() throws Exception {
    claims.put(Claims.AUD, AUDIENCE);
    assertThat(BiPredicateAssertions.builder()
        .requireAudience(AUDIENCE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireAudienceMatchesOneOf() throws Exception {
    claims.put(Claims.AUD, AUDIENCE);
    assertThat(BiPredicateAssertions.builder()
        .requireAudience("other" + AUDIENCE, AUDIENCE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireAudienceWhenNoMatch() throws Exception {
    claims.put(Claims.AUD, AUDIENCE);
    assertThat(BiPredicateAssertions.builder()
        .requireAudience("other1" + AUDIENCE, "other2" + AUDIENCE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireAudienceWhenNotString() throws Exception {
    claims.put(Claims.AUD, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireAudience(AUDIENCE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireAudienceWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireAudience(AUDIENCE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireAudienceSatisfies() throws Exception {
    claims.put(Claims.AUD, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireAudienceSatisfies((l) -> l.contains(STRING_VALUE))
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireEqualsMatchesStringValue() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, STRING_VALUE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireEqualsMatchesNumberValue() throws Exception {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, NUMBER_VALUE)
        .build()
        .test(claims, clock), is(true));
  }


  @Test
  public void testRequireEqualsMatchesOneOfStringValue() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, NUMBER_VALUE, STRING_VALUE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireEqualsMatchesOneOfNumberValue() throws Exception {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, STRING_VALUE, NUMBER_VALUE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireEqualsWhenNoMatch() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, NUMBER_VALUE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireEqualsWhenTypeMismatch() throws Exception {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, STRING_VALUE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireEqualsWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, STRING_VALUE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireContainsMatchesString() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, STRING_VALUE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireContainsMatchesNumber() throws Exception {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, NUMBER_VALUE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireContainsMatchesList() throws Exception {
    claims.put(CLAIM_NAME, NUMBER_VALUE, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, STRING_VALUE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireContainsMatchesOneOfValue() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, NUMBER_VALUE, STRING_VALUE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireContainsMatchesOneOfList() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, "other" + STRING_VALUE, STRING_VALUE)
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireContainsWhenNoMatchForValue() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, NUMBER_VALUE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireContainsWhenNoMatchForList() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, "other" + STRING_VALUE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireContainsWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, STRING_VALUE)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireSatisfiesWhenSatisfied() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireSatisfies(CLAIM_NAME, String.class,
            (v) -> v.equals(STRING_VALUE))
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireSatisfiesWhenNotSatisfied() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireSatisfies(CLAIM_NAME, String.class,
            (v) -> v.equals("other" + STRING_VALUE))
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireSatisfiesWhenTypeMismatch() throws Exception {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireSatisfies(CLAIM_NAME, String.class,
            (v) -> v.equals(STRING_VALUE))
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireSatisfiesWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireSatisfies(CLAIM_NAME, String.class,
            (v) -> v.equals(STRING_VALUE))
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireInstantSatisfiesWhenSatisfied() throws Exception {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireInstantSatisfies(CLAIM_NAME, (v, clock) ->
            v.equals(Instant.ofEpochSecond(NUMBER_VALUE.longValue())))
        .build()
        .test(claims, clock), is(true));
  }

  @Test
  public void testRequireInstantSatisfiesWhenNotSatisfied() throws Exception {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireInstantSatisfies(CLAIM_NAME,
            (v, clock) -> v.equals(Instant.EPOCH))
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireInstantSatisfiesWhenTypeMismatch() throws Exception {
    claims.put(CLAIM_NAME, STRING_VALUE);
    assertThat(BiPredicateAssertions.builder()
        .requireInstantSatisfies(CLAIM_NAME, (v, clock) -> true)
        .build()
        .test(claims, clock), is(false));
  }

  @Test
  public void testRequireInstantSatisfiesWhenNotPresent() throws Exception {
    assertThat(BiPredicateAssertions.builder()
        .requireInstantSatisfies(CLAIM_NAME, (v, clock) -> true)
        .build()
        .test(claims, clock), is(false));
  }


}
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

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.exceptions.CertificateSubjectNameAssertionException;
import org.soulwing.jwt.api.exceptions.ContainsAssertionException;
import org.soulwing.jwt.api.exceptions.EqualsAssertionException;
import org.soulwing.jwt.api.exceptions.ExpirationAssertionException;
import org.soulwing.jwt.api.exceptions.IdAssertionException;
import org.soulwing.jwt.api.exceptions.InstantAssertionException;
import org.soulwing.jwt.api.exceptions.JWTAssertionFailedException;
import org.soulwing.jwt.api.exceptions.LifetimeAssertionException;
import org.soulwing.jwt.api.exceptions.TypeMismatchAssertionException;
import org.soulwing.jwt.api.exceptions.UndefinedValueAssertionException;

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

  private static KeyPair keyPair = KeyUtil.newRsaKeyPair();

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  private MockClock clock = new MockClock();
  private MockClaims claims = new MockClaims();
  private MockContext context = new MockContext(clock, null);

  @Test
  public void testRequireIdWhenNonEmptyString() {
    claims.put(Claims.JTI, ID);
    BiPredicateAssertions.builder()
        .requireId()
        .build().assertSatisfied(claims, context);
  }

  @Test
  public void testRequireIdWhenEmptyString() {
    claims.put(Claims.JTI, "");
    expectedException.expect(IdAssertionException.class);
    expectedException.expectMessage(Claims.JTI);
    expectedException.expectMessage("required, but not present");
    BiPredicateAssertions.builder()
        .requireId()
        .build().assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireIdWhenNull() {
    claims.put(Claims.JTI, null);
    BiPredicateAssertions.builder()
        .requireId()
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = TypeMismatchAssertionException.class)
  public void testRequireIdWhenNotString() {
    claims.put(Claims.JTI, 42);
    BiPredicateAssertions.builder()
        .requireId()
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireIdWhenNotPresent() {
   BiPredicateAssertions.builder()
        .requireId()
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireIdSatisfies() {
    claims.put(Claims.JTI, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireIdSatisfies(v -> v.equals(STRING_VALUE),
            v -> new EqualsAssertionException(Claims.JTI, STRING_VALUE, STRING_VALUE))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireIdSatisfiesWhenNotSatisfied() {
    claims.put(Claims.JTI, "other" + STRING_VALUE);
    final EqualsAssertionException ex =
        new EqualsAssertionException(Claims.JTI, STRING_VALUE, STRING_VALUE);

    expectedException.expect(is(sameInstance(ex)));
    BiPredicateAssertions.builder()
        .requireIdSatisfies(v -> v.equals(STRING_VALUE), v -> ex)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireLifetimeNotExceededWhenClockEqualsLifetimeMinusOne() {
    claims.put(Claims.IAT, ISSUED_AT.getEpochSecond());
    final MockContext ctx = new MockContext(
        new MockClock(ISSUED_AT.plus(LIFETIME).minusSeconds(1)), null);

    BiPredicateAssertions.builder()
        .requireLifetimeNotExceeded(LIFETIME)
        .build()
        .assertSatisfied(claims, ctx);
  }

  @Test
  public void testRequireLifetimeNotExceededWhenClockEqualsLifetime() {
    claims.put(Claims.IAT, ISSUED_AT.getEpochSecond());
    final MockContext ctx = new MockContext(
        new MockClock(ISSUED_AT.plus(LIFETIME)), null);

    expectedException.expect(LifetimeAssertionException.class);
    expectedException.expectMessage("is before current time");
    BiPredicateAssertions.builder()
        .requireLifetimeNotExceeded(LIFETIME)
        .build()
        .assertSatisfied(claims, ctx);
  }

  @Test(expected = TypeMismatchAssertionException.class)
  public void testRequireLifetimeNotExceededWhenTypeMismatch() {
    claims.put(Claims.IAT, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireLifetimeNotExceeded(LIFETIME)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireLifetimeNotExceededWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireLifetimeNotExceeded(LIFETIME)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireIssuedAtSatisfies() {
    claims.put(Claims.IAT, NUMBER_VALUE);
    final Instant other = Instant.ofEpochSecond(NUMBER_VALUE.longValue());
    BiPredicateAssertions.builder()
        .requireIssuedAtSatisfies(
            (t, clock) -> t.equals(other),
            (t, clock) -> new InstantAssertionException(clock.instant(), t,
                (now, then) -> "error message"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireNotExpiredWhenClockEqualsExpiresMinusOne() {
    claims.put(Claims.EXP, EXPIRES_AT.getEpochSecond());
    BiPredicateAssertions.builder()
        .requireNotExpired(Duration.ZERO)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireNotExpiredWhenClockEqualsExpires() {
    claims.put(Claims.EXP, EXPIRES_AT.getEpochSecond());
    final MockContext ctx = new MockContext(new MockClock(EXPIRES_AT), null);
    expectedException.expect(ExpirationAssertionException.class);
    expectedException.expectMessage("before current time");
    BiPredicateAssertions.builder()
        .requireNotExpired(Duration.ZERO)
        .build()
        .assertSatisfied(claims, ctx);
  }

  @Test
  public void testRequireNotExpiredWithToleranceWhenClockEqualsExpires() {
    claims.put(Claims.EXP, EXPIRES_AT.getEpochSecond());
    final MockContext ctx = new MockContext(new MockClock(EXPIRES_AT), null);
    BiPredicateAssertions.builder()
        .requireNotExpired(TOLERANCE)
        .build()
        .assertSatisfied(claims, ctx);
  }

  @Test
  public void testRequireNotExpiredWithToleranceWhenClockEqualsExpiresPlusTolerance() {
    claims.put(Claims.EXP, EXPIRES_AT.getEpochSecond());
    final MockContext ctx = new MockContext(
        new MockClock(EXPIRES_AT.plus(TOLERANCE)), null);
    expectedException.expect(ExpirationAssertionException.class);
    expectedException.expectMessage("before current time");
    BiPredicateAssertions.builder()
        .requireNotExpired(TOLERANCE)
        .build()
        .assertSatisfied(claims, ctx);
  }

  @Test(expected = TypeMismatchAssertionException.class)
  public void testRequireNotExpiredWhenTypeMismatch() {
    claims.put(Claims.EXP, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireNotExpired(TOLERANCE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireNotExpiredWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireNotExpired(TOLERANCE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireExpirationSatisfies() {
    claims.put(Claims.EXP, NUMBER_VALUE);
    final Instant expiresAt = Instant.ofEpochSecond(NUMBER_VALUE.longValue());
    BiPredicateAssertions.builder()
        .requireExpirationSatisfies(
            (t, clock) -> t.equals(expiresAt),
            (t, clock) -> new ExpirationAssertionException(
                clock.instant(), expiresAt, Duration.ZERO))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireExpirationSatisfiesWhenNotSatisfied() {
    claims.put(Claims.EXP, NUMBER_VALUE);
    final Instant expiresAt = Instant.ofEpochSecond(NUMBER_VALUE.longValue());
    final ExpirationAssertionException ex =
        new ExpirationAssertionException(clock.instant(), expiresAt, Duration.ZERO);

    expectedException.expect(is(sameInstance(ex)));
    BiPredicateAssertions.builder()
        .requireExpirationSatisfies(
            (t, clock) -> !t.equals(expiresAt),
            (t, clock) -> ex)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireIssuerMatches() {
    claims.put(Claims.ISS, ISSUER);
    BiPredicateAssertions.builder()
        .requireIssuer(ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireIssuerMatchesOneOf() {
    claims.put(Claims.ISS, ISSUER);
    BiPredicateAssertions.builder()
        .requireIssuer("other" + ISSUER, ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = EqualsAssertionException.class)
  public void testRequireIssuerWhenNoMatch() {
    claims.put(Claims.ISS, ISSUER);
    BiPredicateAssertions.builder()
        .requireIssuer("other1" + ISSUER, "other2" + ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = EqualsAssertionException.class)
  public void testRequireIssuerWhenNotString() {
    claims.put(Claims.ISS, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireIssuer(ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireIssuerWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireIssuer(ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireIssuerSatisfies() {
    claims.put(Claims.ISS, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireIssuerSatisfies(v -> v.equals(STRING_VALUE),
            v -> new EqualsAssertionException(Claims.ISS, STRING_VALUE, STRING_VALUE))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireIssuerSatisfiesWhenNotSatisfied() {
    claims.put(Claims.ISS, STRING_VALUE);
    final EqualsAssertionException ex =
        new EqualsAssertionException(Claims.ISS, STRING_VALUE, STRING_VALUE);
    expectedException.expect(is(sameInstance(ex)));
    BiPredicateAssertions.builder()
        .requireIssuerSatisfies(v -> !v.equals(STRING_VALUE), v -> ex)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSubjectMatches() {
    claims.put(Claims.SUB, SUBJECT);
    BiPredicateAssertions.builder()
        .requireSubject(SUBJECT)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSubjectMatchesOneOf() {
    claims.put(Claims.SUB, SUBJECT);
    BiPredicateAssertions.builder()
        .requireSubject("other" + SUBJECT, SUBJECT)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = EqualsAssertionException.class)
  public void testRequireSubjectWhenNoMatch() {
    claims.put(Claims.SUB, SUBJECT);
    BiPredicateAssertions.builder()
        .requireSubject("other1" + SUBJECT, "other2" + SUBJECT)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = EqualsAssertionException.class)
  public void testRequireSubjectWhenNotString() {
    claims.put(Claims.SUB, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireSubject(SUBJECT)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireSubjectWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireSubject(SUBJECT)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSubjectSatisfies() {
    claims.put(Claims.SUB, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireSubjectSatisfies(v -> v.equals(STRING_VALUE),
            v -> new EqualsAssertionException(Claims.SUB, STRING_VALUE, STRING_VALUE))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSubjectSatisfiesWhenNotSatisfied() {
    claims.put(Claims.SUB, STRING_VALUE);
    final EqualsAssertionException ex =
        new EqualsAssertionException(Claims.SUB, STRING_VALUE, STRING_VALUE);
    expectedException.expect(is(sameInstance(ex)));
    BiPredicateAssertions.builder()
        .requireSubjectSatisfies(v -> !v.equals(STRING_VALUE), v -> ex)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireAudienceMatches() {
    claims.put(Claims.AUD, AUDIENCE);
    BiPredicateAssertions.builder()
        .requireAudience(AUDIENCE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireAudienceMatchesOneOf() {
    claims.put(Claims.AUD, AUDIENCE);
    BiPredicateAssertions.builder()
        .requireAudience("other" + AUDIENCE, AUDIENCE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = ContainsAssertionException.class)
  public void testRequireAudienceWhenNoMatch() {
    claims.put(Claims.AUD, AUDIENCE);
    BiPredicateAssertions.builder()
        .requireAudience("other1" + AUDIENCE, "other2" + AUDIENCE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = ContainsAssertionException.class)
  public void testRequireAudienceWhenNotString() {
    claims.put(Claims.AUD, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireAudience(AUDIENCE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireAudienceWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireAudience(AUDIENCE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireAudienceSatisfies() {
    claims.put(Claims.AUD, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireAudienceSatisfies((l) -> l.contains(STRING_VALUE),
            l -> new ContainsAssertionException(Claims.AUD, l, STRING_VALUE))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireEqualsMatchesStringValue() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireEqualsMatchesNumberValue() {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, NUMBER_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }


  @Test
  public void testRequireEqualsMatchesOneOfStringValue() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, NUMBER_VALUE, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireEqualsMatchesOneOfNumberValue() {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, STRING_VALUE, NUMBER_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = EqualsAssertionException.class)
  public void testRequireEqualsWhenNoMatch() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, NUMBER_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = EqualsAssertionException.class)
  public void testRequireEqualsWhenTypeMismatch() {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireEqualsWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireEquals(CLAIM_NAME, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireContainsMatchesString() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireContainsMatchesNumber() {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, NUMBER_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireContainsMatchesList() {
    claims.put(CLAIM_NAME, NUMBER_VALUE, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireContainsMatchesOneOfValue() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, NUMBER_VALUE, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireContainsMatchesOneOfList() {
    claims.put(CLAIM_NAME, STRING_VALUE, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, "other" + STRING_VALUE, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = ContainsAssertionException.class)
  public void testRequireContainsWhenNoMatchForValue() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, NUMBER_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = ContainsAssertionException.class)
  public void testRequireContainsWhenNoMatchForList() {
    claims.put(CLAIM_NAME, STRING_VALUE, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, "other" + STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireContainsWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireContains(CLAIM_NAME, STRING_VALUE)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSatisfiesWhenSatisfied() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireSatisfies(CLAIM_NAME, String.class,
            v -> v.equals(STRING_VALUE),
            v -> new JWTAssertionFailedException("not satisfied"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSatisfiesWhenNotSatisfied() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    final JWTAssertionFailedException ex =
        new JWTAssertionFailedException("not satisfied");
    expectedException.expect(is(sameInstance(ex)));
    BiPredicateAssertions.builder()
        .requireSatisfies(CLAIM_NAME, String.class,
            v -> v.equals("other" + STRING_VALUE), v -> ex)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = TypeMismatchAssertionException.class)
  public void testRequireSatisfiesWhenTypeMismatch() {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireSatisfies(CLAIM_NAME, String.class,
            v -> v.equals(STRING_VALUE),
            v -> new JWTAssertionFailedException("type mismatch"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireSatisfiesWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireSatisfies(CLAIM_NAME, String.class,
            v -> v.equals(STRING_VALUE),
            v -> new JWTAssertionFailedException("not present"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireInstantSatisfiesWhenSatisfied() {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    final Instant instant = Instant.ofEpochSecond(NUMBER_VALUE.longValue());
    BiPredicateAssertions.builder()
        .requireInstantSatisfies(CLAIM_NAME,
            (t, clock) -> t.equals(instant),
            (t, clock) -> new InstantAssertionException(
                clock.instant(), t, (now, other) -> "now is not equal to other"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = InstantAssertionException.class)
  public void testRequireInstantSatisfiesWhenNotSatisfied() {
    claims.put(CLAIM_NAME, NUMBER_VALUE);
    BiPredicateAssertions.builder()
        .requireInstantSatisfies(CLAIM_NAME,
            (t, clock) -> t.equals(Instant.EPOCH),
            (t, clock) -> new InstantAssertionException(
                Instant.EPOCH, t, (now, other) -> "now is not other"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = TypeMismatchAssertionException.class)
  public void testRequireInstantSatisfiesWhenTypeMismatch() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requireInstantSatisfies(CLAIM_NAME,
            (t, clock) -> true,
            (t, clock) -> new InstantAssertionException(
                Instant.EPOCH, t, (now, other) -> "now is not other"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = UndefinedValueAssertionException.class)
  public void testRequireInstantSatisfiesWhenNotPresent() {
    BiPredicateAssertions.builder()
        .requireInstantSatisfies(CLAIM_NAME,
            (t, clock) -> true,
            (t, clock) -> new InstantAssertionException(
                Instant.EPOCH, t, (now, other) -> "now is not other"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSubjectNameMatchesIssuerWhenSubjectNameMatches()
      throws Exception {

    final X509Certificate certificate =
        CertUtil.createSelfSignedCert(ISSUER, keyPair, Duration.ZERO, false);

    final PublicKeyInfo publicKeyInfo = PublicKeyInfo.builder()
        .publicKey(keyPair.getPublic())
        .certificates(Collections.singletonList(certificate))
        .build();

    final MockContext context = new MockContext(clock, publicKeyInfo);
    claims.put(Claims.ISS, ISSUER);

    BiPredicateAssertions.builder()
        .requireCertificateSubjectMatchesIssuer()
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSubjectNameMatchesIssuerWhenAltSubjectNameMatches()
      throws Exception {

    final X509Certificate bcCert =
        CertUtil.createSelfSignedCert("other-" + ISSUER, ISSUER, keyPair,
            Duration.ZERO, false);

    final X509Certificate certificate = (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(bcCert.getEncoded()));

    final PublicKeyInfo publicKeyInfo = PublicKeyInfo.builder()
        .publicKey(keyPair.getPublic())
        .certificates(Collections.singletonList(certificate))
        .build();

    final MockContext context = new MockContext(clock, publicKeyInfo);
    claims.put(Claims.ISS, ISSUER);

    BiPredicateAssertions.builder()
        .requireCertificateSubjectMatchesIssuer()
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = CertificateSubjectNameAssertionException.class)
  public void testRequireSubjectNameMatchesIssuerWhenSubjectNameDoesNotMatch()
      throws Exception {

    final X509Certificate certificate =
        CertUtil.createSelfSignedCert("other" + ISSUER, keyPair,
            Duration.ZERO, false);

    final PublicKeyInfo publicKeyInfo = PublicKeyInfo.builder()
        .publicKey(keyPair.getPublic())
        .certificates(Collections.singletonList(certificate))
        .build();

    final MockContext context = new MockContext(clock, publicKeyInfo);
    BiPredicateAssertions.builder()
        .requireCertificateSubjectMatches(ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSubjectNameMatchesWhenSubjectNameMatches()
      throws Exception {

    final X509Certificate certificate =
        CertUtil.createSelfSignedCert(ISSUER, keyPair, Duration.ZERO, false);

    final PublicKeyInfo publicKeyInfo = PublicKeyInfo.builder()
        .publicKey(keyPair.getPublic())
        .certificates(Collections.singletonList(certificate))
        .build();

    final MockContext context = new MockContext(clock, publicKeyInfo);
    BiPredicateAssertions.builder()
        .requireCertificateSubjectMatches(ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireSubjectNameMatchesWhenAltSubjectNameMatches()
      throws Exception {

    final X509Certificate bcCert =
        CertUtil.createSelfSignedCert("other-" + ISSUER, ISSUER, keyPair,
            Duration.ZERO, false);

    final X509Certificate certificate = (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(bcCert.getEncoded()));

    final PublicKeyInfo publicKeyInfo = PublicKeyInfo.builder()
        .publicKey(keyPair.getPublic())
        .certificates(Collections.singletonList(certificate))
        .build();

    final MockContext context = new MockContext(clock, publicKeyInfo);
    BiPredicateAssertions.builder()
        .requireCertificateSubjectMatches(ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = CertificateSubjectNameAssertionException.class)
  public void testRequireSubjectNameMatchesWhenSubjectNameDoesNotMatch()
      throws Exception {

    final X509Certificate certificate =
        CertUtil.createSelfSignedCert("other" + ISSUER, keyPair,
            Duration.ZERO, false);

    final PublicKeyInfo publicKeyInfo = PublicKeyInfo.builder()
        .publicKey(keyPair.getPublic())
        .certificates(Collections.singletonList(certificate))
        .build();

    final MockContext context = new MockContext(clock, publicKeyInfo);
    BiPredicateAssertions.builder()
        .requireCertificateSubjectMatches(ISSUER)
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequireClaimAndPublicKeyInfoSatisfiesWhenSatisfied() {
    claims.put(CLAIM_NAME, STRING_VALUE);
   BiPredicateAssertions.builder()
        .requirePublicKeyInfoSatisfies(CLAIM_NAME, (v, publicKeyInfo) -> true,
            (v, publicKeyInfo) -> new JWTAssertionFailedException("not satisfied"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = JWTAssertionFailedException.class)
  public void testRequireClaimAndPublicKeyInfoSatisfiesWhenNotSatisfied() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requirePublicKeyInfoSatisfies(publicKeyInfo -> false,
            publicKeyInfo -> new JWTAssertionFailedException("not satisfied"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test
  public void testRequirePublicKeyInfoSatisfiesWhenSatisfied() {
    BiPredicateAssertions.builder()
        .requirePublicKeyInfoSatisfies(publicKeyInfo -> true,
            publicKeyInfo -> new JWTAssertionFailedException("not satisfied"))
        .build()
        .assertSatisfied(claims, context);
  }

  @Test(expected = JWTAssertionFailedException.class)
  public void testRequirePublicKeyInfoSatisfiesWhenNotSatisfied() {
    claims.put(CLAIM_NAME, STRING_VALUE);
    BiPredicateAssertions.builder()
        .requirePublicKeyInfoSatisfies(CLAIM_NAME,
            (v, publicKeyInfo) -> false,
            (v, publicKeyInfo) -> new JWTAssertionFailedException("not satisfied"))
        .build()
        .assertSatisfied(claims, context);
  }

  private static class MockContext implements Assertions.Context {

    private final Clock clock;
    private final PublicKeyInfo publicKeyInfo;

    MockContext(Clock clock, PublicKeyInfo publicKeyInfo) {
      this.clock = clock;
      this.publicKeyInfo = publicKeyInfo;
    }

    @Override
    public Clock getClock() {
      return clock;
    }

    @Override
    public PublicKeyInfo getPublicKeyInfo() {
      return publicKeyInfo;
    }
  }

}
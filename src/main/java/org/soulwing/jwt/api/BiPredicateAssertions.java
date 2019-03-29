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

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Predicate;

import org.soulwing.jwt.api.exceptions.CertificateSubjectNameAssertionException;
import org.soulwing.jwt.api.exceptions.ContainsAssertionException;
import org.soulwing.jwt.api.exceptions.EqualsAssertionException;
import org.soulwing.jwt.api.exceptions.ExpirationAssertionException;
import org.soulwing.jwt.api.exceptions.IdAssertionException;
import org.soulwing.jwt.api.exceptions.JWTAssertionFailedException;
import org.soulwing.jwt.api.exceptions.LifetimeAssertionException;
import org.soulwing.jwt.api.exceptions.TypeMismatchAssertionException;
import org.soulwing.jwt.api.exceptions.UndefinedValueAssertionException;

/**
 * An {@link Assertions} implementation that evaluates a list of
 * {@link BiPredicate} lambdas.
 *
 * @author Carl Harris
 */
public final class BiPredicateAssertions implements Assertions {

  private class Assertion {
    private final BiPredicate<Claims, Context> condition;
    private final BiFunction<Claims, Context, JWTAssertionFailedException> errorSupplier;

    Assertion(BiPredicate<Claims, Context> condition,
        BiFunction<Claims, Context, JWTAssertionFailedException> errorSupplier) {
      this.condition = condition;
      this.errorSupplier = errorSupplier;
    }

  }

  private final List<Assertion> assertions = new ArrayList<>();

  private <T> void addClaimAssertion(
      Function<Claims, T> accessor,
      Predicate<T> condition,
      Function<T, JWTAssertionFailedException> description) {

    assertions.add(new Assertion(
        (claims, context) -> condition.test(accessor.apply(claims)),
        (claims, context) -> description.apply(accessor.apply(claims))));
  }

  private <T> void addClaimAssertion(
      Function<Claims, T> accessor,
      BiPredicate<T, Context> condition,
      BiFunction<T, Context, JWTAssertionFailedException> description) {
    assertions.add(new Assertion(
        (claims, context) -> condition.test(accessor.apply(claims), context),
        (claims, context) -> description.apply(accessor.apply(claims), context)));
  }

  private void addClaimAssertion(Predicate<Context> condition,
      Function<Context, JWTAssertionFailedException> description) {
    assertions.add(new Assertion(
        (claims, context) -> condition.test(context),
        (claims, context) -> description.apply(context)));
  }

  public static final class Builder implements Assertions.Builder {

    private final BiPredicateAssertions assertions;

    Builder(BiPredicateAssertions assertions) {
      this.assertions = assertions;
    }

    @Override
    public Assertions.Builder requireId() {
      return requireIdSatisfies(v -> v != null && !v.trim().isEmpty(),
          v -> new IdAssertionException());
    }

    @Override
    public Assertions.Builder requireIdSatisfies(Predicate<String> condition,
        Function<String, JWTAssertionFailedException> errorSupplier) {
      return requireSatisfies(Claims.JTI, String.class, condition, errorSupplier);
    }

    @Override
    public Assertions.Builder requireLifetimeNotExceeded(Duration lifetime) {
      return requireIssuedAtSatisfies(
          (t, clock) -> clock.instant().minus(lifetime).isBefore(t),
          (t, clock) -> new LifetimeAssertionException(clock.instant(),
              t, lifetime));
    }

    @Override
    public Assertions.Builder requireIssuedAtSatisfies(
        BiPredicate<Instant, Clock> condition,
        BiFunction<Instant, Clock, JWTAssertionFailedException> errorSupplier) {
      return requireInstantSatisfies(Claims.IAT, condition, errorSupplier);
    }

    @Override
    public Assertions.Builder requireNotExpired(Duration tolerance) {
      return requireExpirationSatisfies(
          (t, clock) -> clock.instant().minus(tolerance).isBefore(t),
          (t, clock) -> new ExpirationAssertionException(
              clock.instant(), t, tolerance));
    }

    @Override
    public Assertions.Builder requireExpirationSatisfies(
        BiPredicate<Instant, Clock> condition,
        BiFunction<Instant, Clock, JWTAssertionFailedException> description) {
      return requireInstantSatisfies(Claims.EXP, condition, description);
    }

    @Override
    public Assertions.Builder requireIssuer(String issuer, String... otherIssuers) {
      return requireEquals(Claims.ISS, issuer, (Object[]) otherIssuers);
    }

    @Override
    public Assertions.Builder requireIssuerSatisfies(Predicate<String> condition,
        Function<String, JWTAssertionFailedException> description) {
      return requireSatisfies(Claims.ISS, String.class, condition, description);
    }

    @Override
    public Assertions.Builder requireCertificateSubjectMatchesIssuer() {
      return requirePublicKeyInfoSatisfies(Claims.ISS,
          (issuer, publicKeyInfo) -> {
            final List<X509Certificate> certificates =
                publicKeyInfo.getCertificates();
            return certificates.isEmpty()
                || CertificateNameMatcher.hasSubjectName(issuer,
                        certificates.get(0));
          },
          (issuer, publicKeyInfo) ->
              new CertificateSubjectNameAssertionException(issuer)
      );
    }

    @Override
    public Assertions.Builder requireCertificateSubjectMatches(String subjectName) {
      return requirePublicKeyInfoSatisfies(
          (publicKeyInfo) -> {
            final List<X509Certificate> certificates =
                publicKeyInfo.getCertificates();
            return certificates.isEmpty()
                || CertificateNameMatcher.hasSubjectName(subjectName,
                certificates.get(0));
          },
          (publicKeyInfo) -> new CertificateSubjectNameAssertionException(subjectName));
    }

    @Override
    public Assertions.Builder requireAudience(String audience,
        String... otherAudiences) {
      return requireContains(Claims.AUD, audience, (Object[]) otherAudiences);
    }

    @Override
    public Assertions.Builder requireAudienceSatisfies(Predicate<List> condition,
        Function<List, JWTAssertionFailedException> description) {
      assertions.addClaimAssertion(listAccessor(Claims.AUD), condition,
          description);
      return this;
    }

    @Override
    public Assertions.Builder requireSubject(String subject, String... otherSubjects) {
      return requireEquals(Claims.SUB, subject, (Object[]) otherSubjects);
    }

    @Override
    public Assertions.Builder requireSubjectSatisfies(Predicate<String> condition,
        Function<String, JWTAssertionFailedException> errorSupplier) {
      return requireSatisfies(Claims.SUB, String.class, condition, errorSupplier);
    }

    @Override
    public Assertions.Builder requireEquals(String name,
        Object value, Object... otherValues) {
      return requireSatisfies(name, Object.class,
          v -> v.equals(value) || Arrays.asList(otherValues).contains(v),
          v -> new EqualsAssertionException(name, v, value, otherValues));
    }

    @Override
    public Assertions.Builder requireContains(String name,
        Object value, Object... otherValues) {
      assertions.addClaimAssertion(listAccessor(name),
          l -> l != null && (l.contains(value)
                || Arrays.stream(otherValues).anyMatch(l::contains)),
          l -> new ContainsAssertionException(name, l, value, otherValues));
      return this;
    }

    @Override
    public final <T> Assertions.Builder requireSatisfies(
        String name, Class<? extends T> type, Predicate<T> condition,
        Function<T, JWTAssertionFailedException> errorSupplier) {
      assertions.addClaimAssertion(
          valueAccessor(name, type),
          (v) -> type.isInstance(v) && condition.test(v),
          errorSupplier);
      return this;
    }

    @Override
    public final Assertions.Builder requireInstantSatisfies(
        String name, BiPredicate<Instant, Clock> condition,
        BiFunction<Instant, Clock, JWTAssertionFailedException> errorSupplier) {
      assertions.addClaimAssertion(valueAccessor(name, Number.class),
          (v, context) -> condition.test(
              Instant.ofEpochSecond(v.longValue()), context.getClock()),
          (v, context) -> errorSupplier.apply(
              Instant.ofEpochSecond(v.longValue()), context.getClock()));
      return this;
    }

    @Override
    public Assertions.Builder requirePublicKeyInfoSatisfies(
        String name, BiPredicate<String, PublicKeyInfo> condition,
        BiFunction<String, PublicKeyInfo, JWTAssertionFailedException> errorSupplier) {
      assertions.addClaimAssertion(valueAccessor(name, String.class),
          (v, context) -> condition.test(v, context.getPublicKeyInfo()),
          (v, context) -> errorSupplier.apply(v, context.getPublicKeyInfo()));
      return this;
    }

    @Override
    public Assertions.Builder requirePublicKeyInfoSatisfies(
        Predicate<PublicKeyInfo> condition,
        Function<PublicKeyInfo, JWTAssertionFailedException> errorSupplier) {
      assertions.addClaimAssertion(
          (context) -> condition.test(context.getPublicKeyInfo()),
          (context) -> errorSupplier.apply(context.getPublicKeyInfo()));
      return this;
    }

    private <T> Function<Claims, T> valueAccessor(String name,
        Class<? extends T> type) {
      return claims -> {
        try {
          return claims.claim(name, type).orElseThrow(
              () -> new UndefinedValueAssertionException(name));
        }
        catch (ClassCastException ex) {
          throw new TypeMismatchAssertionException(
            "claim `" + name + "` type mismatch; " + ex.getMessage());
        }
      };
    }

    private Function<Claims, List> listAccessor(String name) {
      return (claims) ->
          claims.claim(name, Object.class)
              .map(v -> v instanceof List ?
                  (List) v : Collections.singletonList(v))
              .orElseThrow(() -> new UndefinedValueAssertionException(name));
    }

    @Override
    public BiPredicateAssertions build() {
      return assertions;
    }


  }

  /**
   * Gets a builder for a new instance.
   * @return builder
   */
  public static Builder builder() {
    return new Builder(new BiPredicateAssertions());
  }

  @Override
  public void assertSatisfied(Claims claims, Context context)
      throws JWTAssertionFailedException {
    final JWTAssertionFailedException ex = assertions.stream()
        .filter(assertion -> !assertion.condition.test(claims, context))
        .findFirst()
        .map(assertion -> assertion.errorSupplier.apply(claims, context))
        .orElse(null);

    if (ex != null) throw ex;
  }

}

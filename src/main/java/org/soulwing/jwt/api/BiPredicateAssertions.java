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
import java.util.Optional;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * An {@link Assertions} implementation that evaluates a list of
 * {@link BiPredicate} lambdas.
 *
 * @author Carl Harris
 */
public final class BiPredicateAssertions implements Assertions {

  private final List<BiPredicate<Claims, Context>> assertions = new ArrayList<>();

  private <T> void addClaimAssertion(Function<Claims, Optional<T>> accessor,
      Predicate<T> condition) {
     assertions.add((claims, context) ->
        accessor.apply(claims).map(condition::test).orElse(false));
  }

  private <T> void addClaimAssertion(Function<Claims, Optional<T>> accessor,
      BiPredicate<T, Context> condition) {
    assertions.add((claims, context) ->
        accessor.apply(claims)
            .map(v -> condition.test(v, context))
            .orElse(false));
  }

  private void addClaimAssertion(Predicate<Context> condition) {
    assertions.add((claims, context) -> condition.test(context));
  }

  public static final class Builder implements Assertions.Builder {

    private final BiPredicateAssertions assertions;

    Builder(BiPredicateAssertions assertions) {
      this.assertions = assertions;
    }

    @Override
    public Assertions.Builder requireId() {
      return requireIdSatisfies(v -> v != null && !v.trim().isEmpty());
    }

    @Override
    public Assertions.Builder requireIdSatisfies(Predicate<String> condition) {
      return requireSatisfies(Claims.JTI, String.class, condition);
    }

    @Override
    public Assertions.Builder requireLifetimeNotExceeded(Duration lifetime) {
      return requireIssuedAtSatisfies((t, clock) ->
          clock.instant().minus(lifetime).isBefore(t));
    }

    @Override
    public Assertions.Builder requireIssuedAtSatisfies(
        BiPredicate<Instant, Clock> condition) {
      return requireInstantSatisfies(Claims.IAT, condition);
    }

    @Override
    public Assertions.Builder requireNotExpired(Duration tolerance) {
      return requireExpirationSatisfies((t, clock) ->
          clock.instant().minus(tolerance).isBefore(t));
    }

    @Override
    public Assertions.Builder requireExpirationSatisfies(
        BiPredicate<Instant, Clock> condition) {
      return requireInstantSatisfies(Claims.EXP, condition);
    }

    @Override
    public Assertions.Builder requireIssuer(String issuer, String... otherIssuers) {
      return requireEquals(Claims.ISS, issuer, (Object[]) otherIssuers);
    }

    @Override
    public Assertions.Builder requireIssuerSatisfies(Predicate<String> condition) {
      return requireSatisfies(Claims.ISS, String.class, condition);
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
          });
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
          });
    }

    @Override
    public Assertions.Builder requireAudience(String audience,
        String... otherAudiences) {
      return requireContains(Claims.AUD, audience, (Object[]) otherAudiences);
    }

    @Override
    public Assertions.Builder requireAudienceSatisfies(Predicate<List> condition) {
      assertions.addClaimAssertion(listAccessor(Claims.AUD), condition);
      return this;
    }

    @Override
    public Assertions.Builder requireSubject(String subject, String... otherSubjects) {
      return requireEquals(Claims.SUB, subject, (Object[]) otherSubjects);
    }

    @Override
    public Assertions.Builder requireSubjectSatisfies(Predicate<String> condition) {
      return requireSatisfies(Claims.SUB, String.class, condition);
    }

    @Override
    public Assertions.Builder requireEquals(
        String name, Object value, Object... otherValues) {
      return requireSatisfies(name, Object.class,
          v -> v.equals(value) || Arrays.asList(otherValues).contains(v));
    }

    @Override
    public Assertions.Builder requireContains(
        String name, Object value, Object... otherValues) {
      assertions.addClaimAssertion(listAccessor(name),
          v -> v != null
              && (v.contains(value)
                  || Arrays.stream(otherValues).anyMatch(v::contains)));
      return this;
    }

    @Override
    @SuppressWarnings("unchecked")
    public final <T> Assertions.Builder requireSatisfies(
        String name, Class<? extends T> type, Predicate<T> condition) {
      assertions.addClaimAssertion(valueAccessor(name),
          (v) -> type.isInstance(v) && condition.test((T) v));
      return this;
    }

    @Override
    public final Assertions.Builder requireInstantSatisfies(
        String name, BiPredicate<Instant, Clock> condition) {
      assertions.addClaimAssertion(valueAccessor(name),
          (v, context) -> v instanceof Number
              && condition.test(
                    Instant.ofEpochSecond(((Number) v).longValue()),
                    context.getClock()));
      return this;
    }

    @Override
    public Assertions.Builder requirePublicKeyInfoSatisfies(
        String name, BiPredicate<String, PublicKeyInfo> condition) {
      assertions.addClaimAssertion(valueAccessor(name),
          (v, context) -> v instanceof String
              && condition.test((String) v, context.getPublicKeyInfo()));
      return this;
    }

    @Override
    public Assertions.Builder requirePublicKeyInfoSatisfies(
        Predicate<PublicKeyInfo> condition) {
      assertions.addClaimAssertion(
          (context) -> condition.test(context.getPublicKeyInfo()));
      return this;
    }

    private Function<Claims, Optional<Object>> valueAccessor(String name) {
      return (claims) -> claims.claim(name, Object.class);
    }

    private Function<Claims, Optional<List>> listAccessor(String name) {
      return (claims) ->
          claims.claim(name, Object.class)
              .map(v -> v instanceof List ?
                  (List) v : Collections.singletonList(v));
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
  public boolean test(Claims claims, Context context) {
    return assertions.stream()
        .allMatch(assertion -> assertion.test(claims, context));
  }


}

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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

/**
 * A specification of assertions for JWT claims.
 * <p>
 * An instance of this type is essentially a set of predicates which can be
 * evaluated in the context of a set of input claims.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface Assertions {

  /**
   * A builder that constructs assertions for claims.
   */
  interface Builder {

    /**
     * Requires some non-empty value for the {@value Claims#JTI} claim.
     * @return this builder
     */
    Builder requireId();

    /**
     * Requires a {@value Claims#JTI} claim that satisfies the given condition.
     * @param condition a predicate to evaluate as the condition
     * @return this builder
     */
    Builder requireIdSatisfies(Predicate<String> condition);

    /**
     * Requires a {@value Claims#IAT} claim whose value is after the current
     * time of a reference clock less the given lifetime duration.
     * @param lifetime lifetime duration to allow
     * @return this builder
     */
    Builder requireLifetimeNotExceeded(Duration lifetime);

    /**
     * Requires a {@value Claims#IAT} claim whose value satisfies the specified
     * condition.
     * @param condition a bi-predicate to evaluate as the condition
     * @return this builder
     */
    Builder requireIssuedAtSatisfies(BiPredicate<Instant, Clock> condition);

    /**
     * Requires an {@value Claims#EXP} claim whose value is after the current
     * time of a reference clock, less the given tolerance to allow for clock
     * skew.
     * @param tolerance tolerance to allow for clock skew
     * @return this builder
     */
    Builder requireNotExpired(Duration tolerance);

    /**
     * Requires a {@value Claims#EXP} claim whose value satisfies the specified
     * condition.
     * @param condition a bi-predicate to evaluate as the condition
     * @return this builder
     */
    Builder requireExpirationSatisfies(BiPredicate<Instant, Clock> condition);

    /**
     * Requires an {@value Claims#ISS} claim whose value is equal to one of the
     * given issuers.
     * @param issuer       issuer to match
     * @param otherIssuers other issuers to allow
     * @return this builder
     */
    Builder requireIssuer(String issuer, String... otherIssuers);

    /**
     * Requires a {@value Claims#ISS} claim whose value satisfies the given
     * condition.
     * @param condition predicate that represents the required condition
     * @return this builder
     */
    Builder requireIssuerSatisfies(Predicate<String> condition);

    /**
     * Requires that the certificate associated with a public key that was
     * used to verify the signature has a subject name that exactly matches
     * the value of the {@value Claims#ISS} claim.
     * <p>
     * When matching the issuer name to the certificate subject, the common
     * name (CN) component of the subject distinguished name, as well as any
     * subject alternative names are considered.
     *
     * @return this builder
     */
    Builder requireCertificateSubjectMatchesIssuer();

    /**
     * Requires that the certificate associated with a public key that was
     * used to verify the signature has a subject name that exactly matches
     * the given subject name.
     * <p>
     * When matching the given name to the certificate subject, the common
     * name (CN) component of the subject distinguished name, as well as any
     * subject alternative names are considered.
     *
     * @param subjectName the subject name to match
     * @return this builder
     */
    Builder requireCertificateSubjectMatches(String subjectName);

    /**
     * Requires an {@value Claims#AUD} claim whose value is equal to one of the
     * given audiences.
     * @param audience audience to match
     * @param otherAudiences other audiences to allow
     * @return this builder
     */
    Builder requireAudience(String audience, String... otherAudiences);

    /**
     * Requires an {@value Claims#AUD} claim whose value satisfies the given
     * condition. In the case where the audience claim is a single string value,
     * it is provided to the condition as a list with a single element.
     * @param condition predicate that represents the required condition
     * @return this builder
     */
    Builder requireAudienceSatisfies(Predicate<List> condition);

    /**
     * Requires a {@value Claims#SUB} claim whose value is equal to one of the
     * given subjects.
     * @param subject       subject to match
     * @param otherSubjects other subjects to allow
     * @return this builder
     */
    Builder requireSubject(String subject, String... otherSubjects);

    /**
     * Requires a {@value Claims#SUB} claim whose value satisfies the given
     * condition.
     * @param condition predicate that represents the required condition
     * @return this builder
     */
    Builder requireSubjectSatisfies(Predicate<String> condition);

    /**
     * Requires a named claim whose value is equal to one of the given values.
     * @param name name of the claim to test
     * @param value value to match
     * @param otherValues other values to allow
     * @return this builder
     */
    Builder requireEquals(String name, Object value, Object... otherValues);

    /**
     * Requires a named claim whose value is an array which contains one of the
     * given values.
     * @param name name of the claim to test
     * @param value value to match
     * @param otherValues other values to allow
     * @return this builder
     */
    Builder requireContains(String name, Object value, Object... otherValues);

    /**
     * Requires a named claim whose value satisfies the given condition.
     * @param name name of the claim to test
     * @param type type to which the claim value will be coerced
     * @param condition predicate that represents the required condition
     * @return this builder
     */
    <T> Builder requireSatisfies(String name, Class<? extends T> type,
        Predicate<T> condition);

    /**
     * Requires a named claim whose numeric value, interpreted as a quantity of
     * seconds from the epoch, satisfies a condition represented as bi-predicate
     * whose arguments are the given instant and a reference clock.
     * @param name name of the claim to test
     * @param condition bi-predicate that represents a condition to be
     *    evaluated about an instant relative to a reference clock
     * @return this builder
     */
    Builder requireInstantSatisfies(String name,
        BiPredicate<Instant, Clock> condition);

    /**
     * Requires that the public key info for a public key used to verify the
     * signature satisfies the given condition.
     * @param name name of a string-valued claim to pass to the condition
     * @param condition the condition to satisfy
     * @return this builder
     */
    Builder requirePublicKeyInfoSatisfies(String name,
        BiPredicate<String, PublicKeyInfo> condition);

    /**
     * Requires that the public key info for a public key used to verify the
     * signature satisfies the given condition.
     * @param condition the condition to satisfy
     * @return this builder
     */
    Builder requirePublicKeyInfoSatisfies(Predicate<PublicKeyInfo> condition);

    /**
     * Creates a new assertions object using the configuration of this builder.
     * @return assertions object.
     */
    Assertions build();

  }

  /**
   * A context for evaluation assertions on claims.
   */
  interface Context {

    /**
     * Gets the reference clock for assertions on time values.
     * @return clock (never {@code null})
     */
    Clock getClock();

    /**
     * Public key information for the public key used to verify the signature.
     * @return public key if the signature verified using a public key;
     *    otherwise the return value is {@code null}
     */
    PublicKeyInfo getPublicKeyInfo();

  }

  /**
   * Applies these assertions to the given claims.
   * @param claims the claims to test
   * @param context context for evaluating the assertions
   */
  boolean test(Claims claims, Context context);

}

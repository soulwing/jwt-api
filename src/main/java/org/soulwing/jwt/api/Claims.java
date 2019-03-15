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

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * An immutable value type representing a map of named values for a JWT payload.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface Claims {

  String JTI = "jti";
  String IAT = "iat";
  String EXP = "exp";
  String ISS = "iss";
  String AUD = "aud";
  String SUB = "sub";

  interface Builder {

    /**
     * Specifies a value for the {@value #JTI} claim.
     * @param id id value
     * @return this builder
     */
    Builder id(String id);

    /**
     * Specifies a value for the {@value #ISS} claim.
     * @param issuer issuer value
     * @return this builder
     */
    Builder issuer(String issuer);

    /**
     * Specifies a value for the {@value #AUD} claim.
     * @param audience audience value
     * @param moreAudiences additional audience values
     * @return this builder
     */
    Builder audience(String audience, String... moreAudiences);

    /**
     * Specifies a value for the {@value #SUB} claim.
     * @param subject subject value
     * @return this builder
     */
    Builder subject(String subject);

    /**
     * Specifies a value for the {@value #IAT} claim.
     * @param issuedAt instant that represents the issued-at time
     * @return this builder
     */
    Builder issuedAt(Instant issuedAt);

    /**
     * Specifies a value for the {@value #EXP} claim.
     * @param expiresAt instant that represents the expires-at time
     * @return this builder
     */
    Builder expiresAt(Instant expiresAt);

    /**
     * Specifies a value for an arbitrary claim.
     * @param name name of the claim
     * @param value string value
     * @return this builder
     */
    Builder set(String name, String value);

    /**
     * Specifies a value for an arbitrary claim.
     * @param name name of the claim
     * @param value number value
     * @return this builder
     */
    Builder set(String name, Number value);

    /**
     * Specifies a value for an arbitrary claim.
     * @param name name of the claim
     * @param value boolean value
     * @return this builder
     */
    Builder set(String name, Boolean value);

    /**
     * Specifies a value for an arbitrary claim.
     * @param name name of the claim
     * @param value first value for the claim
     * @param moreValues more values for the claim
     * @return this builder
     * @throws IllegalArgumentException if the provider does not support
     *    any one of the data types composed in the array
     */
    Builder set(String name, Object value, Object... moreValues);

    /**
     * Specifies a value for an arbitrary claim.
     * @param name name of the claim
     * @param values value(s) for the claim; if empty array, any existing
     *    value for the claim will be removed and the claim will not be included
     *    in the resulting representation
     * @return this builder
     * @throws IllegalArgumentException if the provider does not support the
     *    given collection type or any one of the types of values composed in
     *    the collection
     */
    Builder set(String name, Object[] values);

    /**
     * Specifies a value for an arbitrary claim.
     * @param name name of the claim
     * @param values value(s) for the claim; if empty collection, any existing
     *    value for the claim will be removed and the claim will not be included
     *    in the resulting representation
     * @return this builder
     * @throws IllegalArgumentException if the provider does not support the
     *    given collection type or any one of the types of values composed in
     *    the collection
     */
    Builder set(String name, Collection<?> values);

    /**
     * Creates a {@link Claims} instance using the configuration of this
     * builder.
     * @return Claims instance
     */
    Claims build();

  }

  /**
   * Gets the set of names for claims in this collection.
   * @return set of claim names
   */
  Set<String> names();

  /**
   * Gets the value of the {@value #JTI} claim.
   * @return claim value
   * @throws NullPointerException if there is no {@value #JTI} claim
   */
  String getId();

  /**
   * Gets the value of the {@value #ISS} claim.
   * @return claim value
   * @throws NullPointerException if there is no {@value #ISS} claim
   */
  String getIssuer();

  /**
   * Gets the value of the {@value #AUD} claim.
   * @return claim value
   * @throws NullPointerException if there is no {@value #AUD} claim
   */
  List getAudience();

  /**
   * Gets the value of the {@value #SUB} claim.
   * @return claim value
   * @throws NullPointerException if there is no {@value #SUB} claim
   */
  String getSubject();

  /**
   * Gets the value of the {@value #IAT} claim.
   * @return claim value
   * @throws NullPointerException if there is no {@value #IAT} claim
   */
  Instant getIssuedAt();

  /**
   * Gets the value of the {@value #EXP} claim.
   * @return claim value
   * @throws NullPointerException if there is no {@value #EXP} claim
   */
  Instant getExpiresAt();

  /**
   * Gets an optional value for the {@value #JTI} claim.
   * @return optional claim value
   */
  Optional<String> id();

  /**
   * Gets an optional value for the {@value #ISS} claim.
   * @return optional claim value
   */
  Optional<String> issuer();

  <T> T get(String name, Class<? extends T> type);

  /**
   * Gets an optional list of values for the {@value #AUD}.
   * @return optional list of audience values
   */
  Optional<List> audiences();

  /**
   * Gets an optional value for {@value #SUB} claim.
   * @return optional claim value
   */
  Optional<String> subject();

  /**
   * Gets an optional value for {@value #IAT} claim.
   * @return optional claim value
   */
  Optional<Instant> issuedAt();

  /**
   * Gets an optional value for {@value #EXP} claim.
   * @return optional claim value
   */
  Optional<Instant> expiresAt();

  /**
   * Gets an optional value for arbitrary claim.
   * @param name name of the claim
   * @param type type to which the value will be coerced
   * @param <T> return data type
   * @return optional claim value
   * @throws ClassCastException if the value cannot be coerced to the given
   *    type
   */
  <T> Optional<T> claim(String name, Class<? extends T> type);

  /**
   * Produces a JSON object representation of this Claims object encoded as a
   * string.
   * @return JSON string encoding
   */
  String toJson();

}

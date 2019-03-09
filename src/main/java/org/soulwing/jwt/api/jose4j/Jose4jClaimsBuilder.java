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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.soulwing.jwt.api.Claims;

/**
 * A Jose4j implementation of {@link Claims.Builder}.
 *
 * @author Carl Harris
 */
class Jose4jClaimsBuilder implements Claims.Builder {

  private final JwtClaims delegate = new JwtClaims();

  @Override
  public Claims.Builder id(String id) {
    delegate.setJwtId(id);
    return this;
  }

  @Override
  public Claims.Builder issuer(String issuer) {
    delegate.setIssuer(issuer);
    return this;
  }

  @Override
  public Claims.Builder audience(String audience, String... moreAudiences) {
    if (moreAudiences.length == 0) {
      delegate.setAudience(audience);
    }
    else {
      delegate.setAudience(
          Stream.concat(Stream.of(audience), Stream.of(moreAudiences))
              .collect(Collectors.toList()));
    }
    return this;
  }

  @Override
  public Claims.Builder subject(String subject) {
    delegate.setSubject(subject);
    return this;
  }

  @Override
  public Claims.Builder issuedAt(Instant issuedAt) {
    delegate.setIssuedAt(
        NumericDate.fromSeconds(issuedAt.getEpochSecond()));
    return this;
  }

  @Override
  public Claims.Builder expiresAt(Instant expiresAt) {
    delegate.setExpirationTime(
        NumericDate.fromSeconds(expiresAt.getEpochSecond()));
    return this;
  }

  @Override
  public Claims.Builder set(String name, String value) {
    delegate.setClaim(name, value);
    return this;
  }

  @Override
  public Claims.Builder set(String name, Number value) {
    delegate.setClaim(name, value);
    return this;
  }

  @Override
  public Claims.Builder set(String name, Boolean value) {
    delegate.setClaim(name, value);
    return this;
  }

  @Override
  public Claims.Builder set(String name, Object... values) {
    delegate.setClaim(name, Arrays.asList(values));
    return this;
  }

  @Override
  public Claims.Builder set(String name, Collection<?> values) {
    delegate.setClaim(name, new ArrayList<>(values));
    return this;
  }

  @Override
  public Claims build() {
    return new Jose4jClaims(delegate);
  }

}

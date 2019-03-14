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

import java.lang.reflect.Array;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.soulwing.jwt.api.Claims;

/**
 * A Jose4J implementation of {@link Claims}.
 *
 * @author Carl Harris
 */
class Jose4jClaims implements Claims {

  private final JwtClaims delegate;

  Jose4jClaims(JwtClaims delegate) {
    this.delegate = delegate;
  }

  @Override
  public String getId() {
    return get(JTI, String.class);
  }

  @Override
  public String getIssuer() {
    return get(ISS, String.class);
  }

  @Override
  public Set<String> names() {
    return new HashSet<>(delegate.getClaimNames());
  }

  @Override
  public List getAudience() {
    return audiences().orElseThrow(
        () -> new NullPointerException("`" + AUD + "` claim not present"));
  }

  @Override
  public String getSubject() {
    return get(SUB, String.class);
  }

  @Override
  public Instant getIssuedAt() {
    return issuedAt().orElseThrow(
        () -> new NullPointerException("`" + IAT + "` claim not present"));
  }

  @Override
  public Instant getExpiresAt() {
    return expiresAt().orElseThrow(
        () -> new NullPointerException("`" + EXP + "` claim not present"));
  }

  @Override
  public <T> T get(String name, Class<? extends T> type) {
    return claim(name, type).orElseThrow(
        () -> new NullPointerException("`" + name + "` claim not present"));
  }

  @Override
  public Optional<String> id() {
    return claim(JTI, String.class);
  }

  @Override
  public Optional<String> issuer() {
    return claim(ISS, String.class);
  }

  @Override
  public Optional<List> audiences() {
    final Object value = delegate.getClaimValue(AUD);
    if (value == null) return Optional.empty();
    if (value instanceof List) {
      return Optional.of((List) value);
    }
    return Optional.of(Collections.singletonList(value));
  }

  @Override
  public Optional<String> subject() {
    return claim(SUB, String.class);
  }

  @Override
  public Optional<Instant> issuedAt() {
    return claim(IAT, Long.class).map(Instant::ofEpochSecond);
  }

  @Override
  public Optional<Instant> expiresAt() {
    return claim(EXP, Long.class).map(Instant::ofEpochSecond);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T> Optional<T> claim(String name, Class<? extends T> type) {
    try {
      if (Set.class.isAssignableFrom(type)) {
        return (Optional<T>) Optional.of(
            new LinkedHashSet(delegate.getClaimValue(name, List.class)));
      }
      if (type.isArray()) {
        final List values = delegate.getClaimValue(name, List.class);
        final Object[] array = (Object[]) Array.newInstance(type.getComponentType(), 0);
        return (Optional<T>) Optional.of(values.toArray(array));
      }
      if (Integer.class.isAssignableFrom(type)) {
        final Number number = delegate.getClaimValue(name, Number.class);
        if (number == null) return Optional.empty();
        return (Optional<T>) Optional.of(number.intValue());
      }
      if (Long.class.isAssignableFrom(type)) {
        final Number number = delegate.getClaimValue(name, Number.class);
        if (number == null) return Optional.empty();
        return (Optional<T>) Optional.of(number.longValue());
      }
      if (Double.class.isAssignableFrom(type)) {
        final Number number = delegate.getClaimValue(name, Number.class);
        if (number == null) return Optional.empty();
        return (Optional<T>) Optional.of(number.doubleValue());
      }
      return Optional.ofNullable(delegate.getClaimValue(name, type));
    }
    catch (MalformedClaimException ex) {
      throw new ClassCastException("claim value is of type "
          + delegate.getClaimValue(name).getClass().getSimpleName()
          + ", not " + type.getSimpleName());
    }
  }

  @Override
  public String toJson() {
    return delegate.toJson();
  }

}

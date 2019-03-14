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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A map-based claims implementation suitable for use in unit tests.
 *
 * @author Carl Harris
 */
public class MockClaims implements Claims {

  private final Map<String, Object> map = new HashMap<>();

  public void put(String name, Object value, Object... moreValues) {
    if (moreValues.length == 0) {
      map.put(name, value);
    }
    else {
      final List<Object> values = new ArrayList<>();
      values.add(value);
      values.addAll(Arrays.asList(moreValues));
      map.put(name, values);
    }
  }

  @Override
  public Set<String> names() {
    return map.keySet();
  }

  @Override
  public String getId() {
    return id().orElseThrow(NullPointerException::new);
  }

  @Override
  public String getIssuer() {
    return issuer().orElseThrow(NullPointerException::new);
  }

  @Override
  public List getAudience() {
    return audiences().orElseThrow(NullPointerException::new);
  }

  @Override
  public String getSubject() {
    return subject().orElseThrow(NullPointerException::new);
  }

  @Override
  public Instant getIssuedAt() {
    return issuedAt().orElseThrow(NullPointerException::new);
  }

  @Override
  public Instant getExpiresAt() {
    return expiresAt().orElseThrow(NullPointerException::new);
  }

  @Override
  public <T> T get(String name, Class<? extends T> type) {
    return claim(name, type).orElseThrow(NullPointerException::new);
  }

  @Override
  public Optional<String> id() {
    return Optional.ofNullable((String) map.get(Claims.JTI));
  }

  @Override
  public Optional<String> issuer() {
    return Optional.ofNullable((String) map.get(Claims.ISS));
  }

  @Override
  public Optional<List> audiences() {
    final Object value = map.get(Claims.AUD);
    if (value == null) return Optional.empty();
    if (value instanceof List) return Optional.of((List) value);
    return Optional.of(Collections.singletonList(value));
  }

  @Override
  public Optional<String> subject() {
    return Optional.ofNullable((String) map.get(Claims.SUB));
  }

  @Override
  public Optional<Instant> issuedAt() {
    return Optional.ofNullable((Long) map.get(Claims.IAT))
        .map(Instant::ofEpochSecond);
  }

  @Override
  public Optional<Instant> expiresAt() {
    return Optional.ofNullable((Long) map.get(Claims.EXP))
        .map(Instant::ofEpochSecond);
  }

  @Override
  public <T> Optional<T> claim(String name, Class<? extends T> type) {
    return Optional.ofNullable(map.get(name))
        .map(type::cast);
  }

  @Override
  public String toJson() {
    throw new UnsupportedOperationException();
  }

}

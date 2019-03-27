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

import java.security.Key;
import java.util.Optional;

/**
 * A {@link KeyProvider} that holds a single key.
 *
 * @author Carl Harris
 */
public class SingletonKeyProvider implements KeyProvider {

  private final KeyInfo keyInfo;

  /**
   * Creates a new instance using the specified key.
   * @param key the subject key
   * @return key provider
   */
  public static SingletonKeyProvider with(Key key) {
    return new SingletonKeyProvider(KeyInfo.builder().key(key).build());
  }

  /**
   * Creates a new instance using the specified key.
   * @param id key identifier
   * @param key the subject key
   * @return key provider
   */
  public static SingletonKeyProvider with(String id, Key key) {
    return new SingletonKeyProvider(KeyInfo.builder().id(id).key(key).build());
  }

  private SingletonKeyProvider(KeyInfo keyInfo) {
    this.keyInfo = keyInfo;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public KeyInfo currentKey() {
    return keyInfo;
  }

  /**
   * Retrieves the singleton key.
   * <p>
   * @param id ID of the key to retrieve
   * @return if the {@code id} parameter is null or if the singleton key has
   *    no identifier, the return value is the singleton key. Otherwise, the
   *    return value is the singleton key if the specified {@code id} equals
   *    the ID of the singleton key, or empty if the IDs do not match.
   */
  @Override
  public Optional<Key> retrieveKey(String id) {
    final String keyId = keyInfo.getId();
    if (id != null && keyId != null && !id.equals(keyId)) {
      return Optional.empty();
    }
    return Optional.of(keyInfo.getKey());
  }

}

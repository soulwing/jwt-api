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
 * A provider for keys used in signature and encipherment operations.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface KeyProvider {

  /**
   * A tuple containing a key and its (optional) corresponding ID.
   */
  class Tuple {

    private final String id;
    private final Key key;

    public Tuple(String id, Key key) {
      if (key == null) {
        throw new NullPointerException("key is required");
      }
      this.id = id;
      this.key = key;
    }

    /**
     * Unique identifier for the key.
     * @return identifier or {@code null} if none has been set
     */
    public String getId() {
      return id;
    }

    /**
     * The subject key.
     * @return key
     */
    public Key getKey() {
      return key;
    }

  }

  /**
   * Gets the current key to use for signature or encryption operations.
    * @return tuple containing the key and optional corresponding identifier
   */
  Tuple currentKey();

  /**
   * Retrieves a key to use for signature validation or decryption operations.
   * @param id ID of the key to retrieve; if {@code null}, the return value is
   *    effectively the same as {@code Optional.of(currentKey().key()}.
   * @return key if found, otherwise empty
   */
  Optional<Key> retrieveKey(String id);

}

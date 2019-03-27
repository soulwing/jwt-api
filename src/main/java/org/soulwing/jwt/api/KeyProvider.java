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

import org.soulwing.jwt.api.exceptions.KeyProviderException;

/**
 * A provider for keys used in signature and encipherment operations.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface KeyProvider {

  /**
   * Gets the current key to use for signature or encryption operations.
   * @return tuple containing the key and optional corresponding identifier
   * @throws KeyProviderException if an error occurs in obtaining the key
   */
  KeyInfo currentKey() throws KeyProviderException;

  /**
   * Retrieves a key to use for signature validation or decryption operations.
   * @param id ID of the key to retrieve; if {@code null}, the return value is
   *    effectively the same as {@code Optional.of(currentKey().key()}.
   * @return key if found, otherwise empty
   * @throws KeyProviderException if an error occurs in obtaining the key
   */
  Optional<Key> retrieveKey(String id) throws KeyProviderException;

}

/*
 * File created on Apr 13, 2021
 *
 * Copyright (c) 2021 Carl Harris, Jr
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

import javax.json.JsonObject;

/**
 * A JSON Web Key Set.
 *
 * @author Carl Harris
 */
public interface JWKS {

  /**
   * A builder that produces a JWKS instance.
   */
  interface Builder {

    /**
     * Specifies a JSON web key to include in the set.
     * @param key the subject key
     * @return this builder
     */
    Builder add(JWK key);

    /**
     * Specifies a JSON web key to include in the set.
     * @param builder builder for the subject key
     * @return this builder
     */
    Builder add(JWK.Builder builder);

    /**
     * Builds the JWKS instance.
     * @return JWKS instance
     */
    JWKS build();

  }

  /**
   * Gets this JWKS as a JSON-P object instance.
   * @return JSON-P representation of this JWK
   */
  JsonObject toJson();

  /**
   * Produces the JSON representation of this JWKS.s
   * @return JSON string representation
   */
  @Override
  String toString();

}

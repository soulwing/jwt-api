/*
 * File created on Mar 17, 2019
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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import javax.json.JsonObject;

/**
 * A JSON Web Key.
 *
 * @author Carl Harris
 */
public interface JWK {

  /**
   * A builder that produces JSON web keys.
   */
  interface Builder {

    /**
     * Specifies the value for the {@code kid} property.
     * @param id key ID
     * @return this builder
     */
    Builder id(String id);

    /**
     * Specifies the value for the {@code kty} property.
     * <p>
     * If this value is not specified, it is inferred from the value specified
     * to the {@link #key(Key)} builder method.
     * @param type key type
     * @return this builder
     */
    Builder type(String type);

    /**
     * Specifies the value for the {@code alg} property.
     * @param algorithm algorithm ID
     * @return this builder
     */
    Builder algorithm(String algorithm);

    /**
     * Specifies the public key {@code use} property.
     * @param use use designator
     * @return this builder
     */
    Builder use(String use);

    /**
     * Specifies key operations designated for this key.
     * @param ops key operation names
     * @return this builder
     */
    Builder ops(String... ops);

    /**
     * Specifies key operations designated for this key.
     * @param ops key operation names
     * @return this builder
     */
    Builder ops(Collection<String> ops);

    /**
     * Specifies a JCA key to be used for this web key.
     * @return this builder
     */
    Builder key(Key key);

    /**
     * Specifies one or more certificates for this key.
     * @param certificates certificates
     * @return this builder
     */
    Builder certificates(X509Certificate... certificates);

    /**
     * Specifies one or more certificates for this key.
     * @param certificates certificates
     * @return this builder
     */
    Builder certificates(List<X509Certificate> certificates);

    /**
     * Builds a JWK using the configuration of this builder.
     * @return JWK instance
     */
    JWK build();

  }

  /**
   * Gets the JCA key that corresponds to this web key.
   *
   * @return JCA key
   */
  Key getKey();

  /**
   * Gets this JWK as a JSON-P object instance.
   * @return JSON-P representation of this JWK
   */
  JsonObject toJson();

  /**
   * Produces the JSON representation of this JSON web key.
   * @return JSON string representation
   */
  @Override
  String toString();

}

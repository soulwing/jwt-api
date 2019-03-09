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

import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;

/**
 * A generator that produces JSON Web Token (JWT) objects.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface JWTGenerator {

  interface Builder {

    /**
     * Sets the JWE operator to use for encryption operations.
     * @param operator JWE operator
     * @return this builder
     */
    Builder encryption(JWE operator);

    /**
     * Sets the JWS operator to use for signature operations.
     * @param operator JWS operator
     * @return this builder
     */
    Builder signature(JWS operator);

    /**
     * Creates a generator using the configuration of this builder.
     * @return generator
     */
    JWTGenerator build() throws JWTConfigurationException;

  }

  /**
   * Generates a signed and optionally encrypted JWT.
   * <p>
   * @param claims claims for the nested payload (JWS in JWE) or payload
   *    (JWS only)
   * @return JWS or JWE in Compact Serialization encoding; if a {@link JWE}
   *    operator is available to the generator, a JWE is returned, otherwise a
   *    JWS is returned
   * @throws JWTSignatureException if an error occurs in signing the payload
   * @throws JWTEncryptionException if an error occurs in encrypting the signed
   *    payload
   */
  String generate(Claims claims)
      throws JWTSignatureException, JWTEncryptionException;

}

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

import java.time.Clock;

import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;
import org.soulwing.jwt.api.exceptions.JWTValidationException;

/**
 * A validator for JSON Web Token (JWT) inputs.
 * <p>
 * A validator encapsulates all of the most common assertion tests to perform
 * on an input JWT.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface JWTValidator {

  /**
   * A builder that produces validator instances.
   */
  interface Builder {

    /**
     * Sets the JWE operator to use for decryption operations.
     * @param operator JWE operator
     * @return this builder
     */
    Builder decryption(JWE operator);

    /**
     * Sets the JWS operator to use for signature validation operations.
     * @param operator JWS operator
     * @return this builder
     */
    Builder signatureValidation(JWS operator);

    /**
     * Sets assertions to be tested on claims.
     * @param assertions assertions to test
     * @return this builder
     */
    Builder claimsAssertions(Assertions assertions);

    /**
     * Sets the reference clock to use for assertions on time values.
     * @param clock reference clock
     * @return this builder
     */
    Builder clock(Clock clock);

    /**
     * Creates a validator using the configuration of this builder.
     * @return validator
     */
    JWTValidator build() throws JWTConfigurationException;

  }

  /**
   * Validates a JWT.
   * <p>
   * If the validator is configured with a {@link JWE} operator for decryption,
   * a valid input must be JWE in Compact Serialization encoding that satisfies
   * all of the basic JWE header, key management, and encapsulated content
   * constraints. Assuming the input JWE is valid, the encapsulated payload is
   * then validated as JWS as described below. If the validator is not
   * configured with a {@link JWE} operator for decryption, a valid input must
   * be a JWS as described below.
   * <p>
   * A valid JWS input must use the Compact Serialization encoding, and must
   * satisfy all of the header and signature validation constraints. Assuming
   * the JWS is valid, the encapsulated payload is then validated as a set of
   * JWT claims.
   * <p>
   * JWT claims contained in the nested payload (JWS in JWE) or payload (JWE)
   * must be a valid JSON object and must satisfy the claim assertions specified
   * for the validator.
   *
   * @param encoded JWE or JWS in the Compact Serialization encoding
   * @return claims encapsulated in the JWT
   * @throws JWTEncryptionException if decryption if an input JWE cannot be
   *    decrypted due a problem other than local configuration
   * @throws JWTSignatureException if an input JWE+JWS or JWE fails signature
   *    validation due to a problem other than local configuration
   * @throws JWTValidationException if the input fails any other aspect of
   *    validation (e.g. a claims assertion failed)
   * @throws JWTConfigurationException if the validation request fails due to
   *    a local configuration problem; e.g. JCA NoSuchAlgorithmException
   */
  Claims validate(String encoded) throws JWTEncryptionException,
      JWTSignatureException, JWTValidationException, JWTConfigurationException;

}

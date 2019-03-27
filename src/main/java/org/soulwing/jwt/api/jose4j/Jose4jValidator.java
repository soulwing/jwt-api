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

import java.time.Clock;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.soulwing.jwt.api.Assertions;
import org.soulwing.jwt.api.Claims;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.JWTValidator;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;
import org.soulwing.jwt.api.exceptions.JWTValidationException;

/**
 * An obvious {@link JWTValidator} implementation.
 * @author Carl Harris
 */
class Jose4jValidator implements JWTValidator {

  private Clock clock = Clock.systemUTC();
  private JWE encryptionOperator = NoOpEncryptionOperator.INSTANCE;

  private JWS signatureOperator;
  private Assertions assertions;

  static class Builder implements JWTValidator.Builder {

    private final Jose4jValidator validator = new Jose4jValidator();

    private Builder() {
    }

    @Override
    public JWTValidator.Builder decryption(JWE operator) {
      if (operator == null) {
        operator = NoOpEncryptionOperator.INSTANCE;
      }
      validator.encryptionOperator = operator;
      return this;
    }

    @Override
    public JWTValidator.Builder signatureValidation(JWS operator) {
      validator.signatureOperator = operator;
      return this;
    }

    @Override
    public JWTValidator.Builder claimsAssertions(Assertions assertions) {
      validator.assertions = assertions;
      return this;
    }

    @Override
    public JWTValidator.Builder clock(Clock clock) {
      if (clock == null) {
        clock = Clock.systemUTC();
      }
      validator.clock = clock;
      return this;
    }

    @Override
    public JWTValidator build() throws JWTConfigurationException {
      if (validator.clock == null) {
        throw new JWTConfigurationException("clock is required");
      }
      if (validator.encryptionOperator == null) {
        throw new JWTConfigurationException("encryption operator is required");
      }
      if (validator.signatureOperator == null) {
        throw new JWTConfigurationException("signature operator is required");
      }
      if (validator.assertions == null) {
        throw new JWTConfigurationException("assertions are required");
      }
      return validator;
    }
  }

  /**
   * Gets a builder that will create a new instance.
   * @return builder
   */
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public Claims validate(String encoded) throws JWTEncryptionException,
      JWTSignatureException, JWTValidationException {
    try {
      final JWS.Result result = signatureOperator.verify(
          encryptionOperator.decrypt(encoded));

      final Claims claims = new Jose4jClaims(JwtClaims.parse(result.getPayload()));

      if (!assertions.test(claims, new Jose4jAssertionContext(clock,
          result.getPublicKeyInfo()))) {
        // TODO -- characterize which assertion(s) failed
        throw new JWTValidationException("one or more claims assertions failed");
      }

      return claims;
    }
    catch (InvalidJwtException ex) {
      throw new JWTValidationException("invalid claims representation", ex);
    }
  }

}

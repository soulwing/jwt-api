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

import org.soulwing.jwt.api.Assertions;
import org.soulwing.jwt.api.Claims;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.JWTProvider;
import org.soulwing.jwt.api.JWTValidator;
import org.soulwing.jwt.api.JoseHeader;
import org.soulwing.jwt.api.exceptions.JWTAssertionFailedException;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;
import org.soulwing.jwt.api.exceptions.JWTParseException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;
import org.soulwing.jwt.api.exceptions.JWTValidationException;

/**
 * An obvious {@link JWTValidator} implementation.
 * @author Carl Harris
 */
class Jose4jValidator implements JWTValidator {

  private JWTProvider provider;

  private Clock clock = Clock.systemUTC();

  private JWE encryptionOperator;
  private JWE.Factory encryptionOperatorFactory;

  private JWS signatureOperator;
  private JWS.Factory signatureOperatorFactory;

  private Assertions assertions;

  static class Builder implements JWTValidator.Builder {

    private final Jose4jValidator validator = new Jose4jValidator();

    private Builder(JWTProvider provider) {
      validator.provider = provider;
    }

    @Override
    public JWTValidator.Builder encryptionOperator(JWE operator) {
      if (operator == null) {
        operator = NoOpEncryptionOperator.INSTANCE;
      }
      validator.encryptionOperator = operator;
      return this;
    }

    @Override
    public JWTValidator.Builder encryptionOperatorFactory(
        JWE.Factory operatorFactory) {
      validator.encryptionOperatorFactory = operatorFactory;
      return this;
    }

    @Override
    public JWTValidator.Builder signatureOperator(JWS operator) {
      validator.signatureOperator = operator;
      return this;
    }

    @Override
    public JWTValidator.Builder signatureOperatorFactory(
        JWS.Factory operatorFactory) {
      validator.signatureOperatorFactory = operatorFactory;
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
      if (validator.encryptionOperator == null
          && validator.encryptionOperatorFactory == null) {
        validator.encryptionOperator = NoOpEncryptionOperator.INSTANCE;
      }
      if (validator.signatureOperator == null
          && validator.signatureOperatorFactory == null) {
        throw new JWTConfigurationException(
            "signature operator or factory is required");
      }
      if (validator.assertions == null) {
        throw new JWTConfigurationException("assertions are required");
      }
      if (validator.encryptionOperator != null
          && validator.encryptionOperatorFactory != null) {
        throw new JWTConfigurationException("specify an encryption "
            + "operator or operator factory, not both");
      }
      if (validator.signatureOperator != null
          && validator.signatureOperatorFactory != null) {
        throw new JWTConfigurationException("specify a signature "
            + "operator or operator factory, not both");
      }
      return validator;
    }
  }

  /**
   * Gets a builder that will create a new instance.
   * @param provider the provider that requested a builder
   * @return builder
   */
  public static Builder builder(JWTProvider provider) {
    return new Builder(provider);
  }

  @Override
  public Claims validate(String encoded) throws JWTParseException,
      JWTEncryptionException, JWTSignatureException, JWTValidationException {
    try {
      final JWS.Result result = verify(decrypt(encoded));
      final Claims claims = provider.parse(result.getPayload());

      assertions.assertSatisfied(claims,
          new Jose4jAssertionContext(clock, result.getPublicKeyInfo()));

      return claims;
    }
    catch (JWTConfigurationException | JWTAssertionFailedException ex) {
      throw new JWTValidationException(ex.getMessage(), ex);
    }
  }

  private String decrypt(String encoded)
      throws JWTEncryptionException, JWTConfigurationException, JWTParseException {
    return getEncryptionOperator(provider.header(encoded)).decrypt(encoded);
  }

  private JWE getEncryptionOperator(JoseHeader header)
      throws JWTConfigurationException {
    if (encryptionOperator != null) return encryptionOperator;
    return encryptionOperatorFactory.getOperator((JWE.Header) header);
  }

  private JWS.Result verify(String encoded)
      throws JWTSignatureException, JWTConfigurationException, JWTParseException {
    return getSignatureOperator(provider.header(encoded)).verify(encoded);
  }

  private JWS getSignatureOperator(JoseHeader header)
      throws JWTConfigurationException {
    if (signatureOperator != null) return signatureOperator;
    return signatureOperatorFactory.getOperator((JWS.Header) header);
  }

}

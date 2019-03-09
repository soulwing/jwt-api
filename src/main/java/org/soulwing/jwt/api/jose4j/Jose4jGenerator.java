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

import org.soulwing.jwt.api.Claims;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.JWTGenerator;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;

/**
 * An obvious {@link JWTGenerator} implementation.
 *
 * @author Carl Harris
 */
class Jose4jGenerator implements JWTGenerator {

  private JWS signatureOperator;
  private JWE encryptionOperator = NoOpEncryptionOperator.INSTANCE;

  static class Builder implements JWTGenerator.Builder {

    private final Jose4jGenerator generator = new Jose4jGenerator();

    private Builder() {
    }

    @Override
    public JWTGenerator.Builder encryption(JWE operator) {
      if (operator == null) {
        operator = NoOpEncryptionOperator.INSTANCE;
      }
      generator.encryptionOperator = operator;
      return this;
    }

    @Override
    public JWTGenerator.Builder signature(JWS operator) {
      generator.signatureOperator = operator;
      return this;
    }

    @Override
    public JWTGenerator build() throws JWTConfigurationException {
      if (generator.signatureOperator == null) {
        throw new JWTConfigurationException("signature operator is required");
      }
      if (generator.encryptionOperator == null) {
        throw new JWTConfigurationException("encryption operator is required");
      }
      return generator;
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
  public String generate(Claims claims)
      throws JWTSignatureException, JWTEncryptionException {
    return encryptionOperator.encrypt(signatureOperator.sign(claims.toJson()));
  }

}

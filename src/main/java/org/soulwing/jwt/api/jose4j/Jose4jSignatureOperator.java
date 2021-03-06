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

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.KeyProvider;
import org.soulwing.jwt.api.PublicKeyInfo;
import org.soulwing.jwt.api.PublicKeyLocator;
import org.soulwing.jwt.api.exceptions.CertificateException;
import org.soulwing.jwt.api.exceptions.InvalidSignatureException;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;
import org.soulwing.jwt.api.exceptions.KeyProviderException;
import org.soulwing.jwt.api.exceptions.PublicKeyNotFoundException;
import org.soulwing.jwt.api.exceptions.SignatureKeyNotFoundException;

/**
 * A {@link JWS} signature operation implemented using Jose4j.
 *
 * @author Carl Harris
 */
class Jose4jSignatureOperator implements JWS {

  private Algorithm algorithm;
  private KeyProvider keyProvider;
  private PublicKeyLocator publicKeyLocator;

  private Jose4jSignatureOperator() {
  }

  static class Builder implements JWS.Builder {

    final Jose4jSignatureOperator operation = new Jose4jSignatureOperator();

    private Builder() {
    }

    @Override
    public JWS.Builder keyProvider(KeyProvider keyProvider) {
      operation.keyProvider = keyProvider;
      return this;
    }

    @Override
    public JWS.Builder publicKeyLocator(PublicKeyLocator publicKeyLocator) {
      operation.publicKeyLocator = publicKeyLocator;
      return this;
    }

    @Override
    public JWS.Builder algorithm(Algorithm algorithm) {
      operation.algorithm = algorithm;
      return this;
    }

    @Override
    public JWS build() throws JWTConfigurationException {
      if (operation.algorithm == null) {
        throw new JWTConfigurationException("algorithm is required");
      }
      if (operation.keyProvider == null && operation.publicKeyLocator == null
          && operation.algorithm != Algorithm.none) {
        throw new JWTConfigurationException("keyProvider or publicKeyLocator is required");
      }
      return operation;
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
  public String sign(String payload) throws JWTSignatureException {
    try {
      final JsonWebSignature jws = new JsonWebSignature();

      jws.setPayload(payload);
      jws.setAlgorithmHeaderValue(algorithm.toToken());
      if (algorithm != Algorithm.none) {
        JoseKeyInfoUtil.configureKeyInfo(jws, keyProvider.currentKey());
      }
      return jws.getCompactSerialization();
    }
    catch (KeyProviderException | JoseException ex) {
      throw new JWTSignatureException(ex.toString(), ex);
    }
  }

  @Override
  public Result verify(String encoded) throws JWTSignatureException {
    try {
      final JsonWebSignature jws = new JsonWebSignature();
      jws.setCompactSerialization(encoded);
      jws.setAlgorithmConstraints(
          new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
              algorithm.toToken()));

      final PublicKeyInfo publicKeyInfo;
      if (algorithm.isAsymmetric() && publicKeyLocator != null) {
        publicKeyInfo =
            publicKeyLocator.locate(new Jose4jPublicKeyCriteria(jws));
        jws.setKey(publicKeyInfo.getPublicKey());
      }
      else {
        publicKeyInfo = null;
        jws.setKey(keyProvider.retrieveKey(jws.getKeyIdHeaderValue())
            .orElseThrow(SignatureKeyNotFoundException::new));
      }

      if (!jws.verifySignature()) {
        throw new InvalidSignatureException(algorithm);
      }

      return new Jose4jVerificationResult(jws.getPayload(), publicKeyInfo);
    }
    catch (CertificateException ex) {
      if (ex.getCause() != null) {
        throw new JWTSignatureException(ex.getCause().getMessage(),
            ex.getCause());
      }
      throw new JWTSignatureException(ex.getMessage(), ex);
    }
    catch (PublicKeyNotFoundException ex) {
      throw new SignatureKeyNotFoundException();
    }
    catch (KeyProviderException | JoseException ex) {
      throw new JWTSignatureException(ex.toString(), ex);
    }
  }

}

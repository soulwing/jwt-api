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
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.lang.JoseException;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.KeyInfo;
import org.soulwing.jwt.api.KeyProvider;
import org.soulwing.jwt.api.exceptions.DecryptionKeyNotFoundException;
import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;
import org.soulwing.jwt.api.exceptions.KeyProviderException;

/**
 * A {@link JWE} operator implemented using Jose4j.
 *
 * @author Carl Harris
 */
class Jose4jEncryptionOperator implements JWE {

  private KeyProvider keyProvider;
  private KeyManagementAlgorithm keyManagementAlgorithm;
  private ContentEncryptionAlgorithm contentEncryptionAlgorithm;
  private CompressionAlgorithm compressionAlgorithm;
  private String contentType;

  static class Builder implements JWE.Builder {

    private final Jose4jEncryptionOperator operation =
        new Jose4jEncryptionOperator();

    private Builder() {
    }

    @Override
    public JWE.Builder keyProvider(KeyProvider keyProvider) {
      operation.keyProvider = keyProvider;
      return this;
    }

    @Override
    public JWE.Builder keyManagementAlgorithm(
        KeyManagementAlgorithm algorithm) {
      operation.keyManagementAlgorithm = algorithm;
      return this;
    }

    @Override
    public JWE.Builder contentEncryptionAlgorithm(
        ContentEncryptionAlgorithm algorithm) {
      operation.contentEncryptionAlgorithm = algorithm;
      return this;
    }

    @Override
    public JWE.Builder compressionAlgorithm(CompressionAlgorithm algorithm) {
      operation.compressionAlgorithm = algorithm;
      return this;
    }

    @Override
    public JWE.Builder contentType(String type) {
      operation.contentType = type;
      return this;
    }

    @Override
    public JWE build() throws JWTConfigurationException {
      if (operation.keyProvider == null) {
        throw new JWTConfigurationException("keyProvider is required");
      }
      if (operation.keyManagementAlgorithm == null) {
        throw new JWTConfigurationException("keyManagementAlgorithm is required");
      }
      if (operation.contentEncryptionAlgorithm == null) {
        throw new JWTConfigurationException("contentEncryptionAlgorithm is required");
      }
      if (operation.contentType == null) {
        throw new JWTConfigurationException("contentType is required");
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
  public String encrypt(String payload) throws JWTEncryptionException {
    try {
      final JsonWebEncryption jwe = new JsonWebEncryption();

      final KeyInfo keyInfo = keyProvider.currentKey();
      jwe.setKey(keyInfo.getKey());
      if (keyInfo.getId() != null) {
        jwe.setKeyIdHeaderValue(keyInfo.getId());
      }

      jwe.setAlgorithmHeaderValue(keyManagementAlgorithm.toToken());
      jwe.setEncryptionMethodHeaderParameter(contentEncryptionAlgorithm.toToken());
      if (compressionAlgorithm != null) {
        jwe.setCompressionAlgorithmHeaderParameter(compressionAlgorithm.toToken());
      }

      jwe.setPayload(payload);
      jwe.setContentTypeHeaderValue(contentType);

      return jwe.getCompactSerialization();
    }
    catch (KeyProviderException | JoseException ex) {
      throw new JWTEncryptionException(ex);
    }
  }

  @Override
  public String decrypt(String encoded) throws JWTEncryptionException {
    try {
      final JsonWebEncryption jwe = new JsonWebEncryption();

      jwe.setCompactSerialization(encoded);

      final String keyId = jwe.getKeyIdHeaderValue();
      jwe.setKey(keyProvider.retrieveKey(keyId).orElseThrow(
          () -> new DecryptionKeyNotFoundException(keyId)));

      jwe.setContentEncryptionAlgorithmConstraints(
          new AlgorithmConstraints(
              AlgorithmConstraints.ConstraintType.WHITELIST,
              contentEncryptionAlgorithm.toToken()));

      jwe.setAlgorithmConstraints(
          new AlgorithmConstraints(
              AlgorithmConstraints.ConstraintType.WHITELIST,
              keyManagementAlgorithm.toToken()));

      return jwe.getPayload();
    }
    catch (KeyProviderException | JoseException ex) {
      throw new JWTEncryptionException(ex);
    }
  }

}

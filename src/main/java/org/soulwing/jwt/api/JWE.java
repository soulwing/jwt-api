/*
 * File created on Mar 10, 2019
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

import java.util.Arrays;

import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;

/**
 * A JSON Web Encryption operator.
 * <p>
 * Using the builder interface, a user of this API creates an object that can
 * be used to encrypt arbitrary payloads (creating a JWE in Compact
 * Serialization encoding) and/or to decrypt a JWE in Compact Serialization
 * encoding and retrieve the encapsulated payload.
 * <p>
 * An instance returned by the builder can be used for multiple, possibly
 * concurrent encryption and/or decryption operations.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface JWE {

  /**
   * The {@code cty} header value for JWT content (value {@value #JWT}).
   */
  String JWT = "JWT";

  /**
   * JWE key management algorithms.
   */
  enum KeyManagementAlgorithm {

    DIRECT("dir"),
    RSA1_5("RSA1_5"),
    RSA_OAEP("RSA-OAEP"),
    RSA_OAEP_256("RSA-OAEP-256"),
    ECDH_ES("ECDH-ES"),
    ECDH_ES_A128KW("ECDH-ES+A128KW"),
    ECDH_ES_A192KW("ECDH-ES+A192KW"),
    ECDH_ES_A256KW("ECDH-ES+A256KW"),
    A128KW("A128KW"),
    A192KW("A192KW"),
    A256KW("A256KW"),
    A128GCMKW("A128GCMKW"),
    A192GCMKW("A192GCMKW"),
    A256GCMKW("A256GCMKW"),
    PBES2_HS256_A128KW("PBES2-HS256+A128KW"),
    PBES2_HS384_A192KW("PBES2-HS384+A192KW"),
    PBES2_HS512_A256KW("PBES2-HS512+A256KW");

    private final String token;

    KeyManagementAlgorithm(String token) {
      this.token = token;
    }

    public String toToken() {
      return token;
    }

    public static KeyManagementAlgorithm of(String token) {
      return Arrays.stream(values())
          .filter(v -> v.toToken().equals(token))
          .findFirst()
          .orElseThrow(() -> new IllegalArgumentException(
              "unrecognized algorithm name: `" + token + "`"));
    }

  }

  /**
   * JWE content encryption algorithms.
   */
  enum ContentEncryptionAlgorithm {
    A128CBC_HS256("A128CBC-HS256"),
    A192CBC_HS384("A192CBC-HS384"),
    A256CBC_HS512("A256CBC-HS512"),
    A128GCM("A128GCM"),
    A192GCM("A192GCM"),
    A256GCM("A256GCM");

    private final String token;

    ContentEncryptionAlgorithm(String token) {
      this.token = token;
    }

    public String toToken() {
      return token;
    }

    public static ContentEncryptionAlgorithm of(String token) {
      return Arrays.stream(values())
          .filter(v -> v.toToken().equals(token))
          .findFirst()
          .orElseThrow(() -> new IllegalArgumentException(
              "unrecognized algorithm name: `" + token + "`"));
    }

  }

  /**
   * JWE content compression algorithms
   */
  enum CompressionAlgorithm {
    DEFLATE("DEF");

    private final String token;

    CompressionAlgorithm(String token) {
      this.token = token;
    }

    public String toToken() {
      return token;
    }

    public static CompressionAlgorithm of(String token) {
      return Arrays.stream(values())
          .filter(v -> v.toToken().equals(token))
          .findFirst()
          .orElseThrow(() -> new IllegalArgumentException(
              "unrecognized algorithm name: `" + token + "`"));
    }

  }

  /**
   * A builder that produces a JWE operator.
   */
  interface Builder {

    /**
     * Sets the key provider to use to obtain keys for encryption or decryption
     * operations.
     * @param keyProvider key provider
     * @return this builder
     */
    Builder keyProvider(KeyProvider keyProvider);

    /**
     * Sets the key management algorithm.
     * @param algorithm selected algorithm
     * @return this builder
     */
    Builder keyManagementAlgorithm(KeyManagementAlgorithm algorithm);

    /**
     * Sets the content encryption algorithm.
     * @param algorithm selected algorithm
     * @return this builder
     */
    Builder contentEncryptionAlgorithm(ContentEncryptionAlgorithm algorithm);

    /**
     * Sets the compression algorithm.
     * @param algorithm selected algorithm
     * @return this builder
     */
    Builder compressionAlgorithm(CompressionAlgorithm algorithm);

    /**
     * Sets the value for the {@code cty} header value.
     * @param type payload type; use {@value #JWT} for JWT payloads.
     * @return this builder
     */
    Builder contentType(String type);

    /**
     * Creates a JSON Web Encryption operator using the configuration of this
     * builder.
     * @return encryption operator
     * @throws JWTConfigurationException if an error occurs in creating the
     *    encryption operator
     */
    JWE build() throws JWTConfigurationException;

  }

  /**
   * Creates a JWE in Compact Serialization encoding using the given payload.
   * @param payload payload
   * @return JWE object in Compact Serialization encoding
   * @throws JWTEncryptionException if an exception occurs in performing the
   *    encryption
   */
  String encrypt(String payload) throws JWTEncryptionException;

  /**
   * Validates a JWE in Compact Serialization and extracts the encapsulated
   * payload.
   * @param encoded JWE in Compact Serialization encoding
   * @return payload encapsulated in the source JWE
   * @throws JWTEncryptionException if an exception occurs in validating and
   *    performing the decryption
   */
  String decrypt(String encoded) throws JWTEncryptionException;

}

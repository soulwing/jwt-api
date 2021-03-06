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

import java.util.Arrays;

import org.soulwing.jwt.api.exceptions.JWTConfigurationException;
import org.soulwing.jwt.api.exceptions.JWTSignatureException;

/**
 * A JSON Web Signature operator.
 * <p>
 * Using the builder interface, a user of this API creates an object that can
 * be used to sign payloads (creating a JWS in Compact Serialization encoding)
 * and/or to validate a JWS in Compact Serialization encoding and obtain the
 * encapsulated payload.
 * <p>
 * An instance returned by the builder can be used for multiple, possibly
 * concurrent signing and/or validation operations.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface JWS {

  /**
   * An enumeration of standard algorithms for signatures
   */
  enum Algorithm {
    none(0, false),
    HS256(256, false),
    HS384(384, false),
    HS512(512, false),
    RS256(2048, true),
    RS384(2048, true),
    RS512(2048, true),
    ES256(256, true),
    ES384(384, true),
    ES512(512, true),
    PS256(2048, true),
    PS384(2048, true),
    PS512(2048, true);

    private final int keyBitLength;
    private final boolean asymmetric;

    Algorithm(int keyBitLength, boolean asymmetric) {
      this.keyBitLength = keyBitLength;
      this.asymmetric = asymmetric;
    }

    public int getKeyBitLength() {
      return keyBitLength;
    }

    public boolean isAsymmetric() {
      return asymmetric;
    }

    public String toToken() {
      return name();
    }

    public static JWS.Algorithm of(String token) {
      return Arrays.stream(values())
          .filter(v -> v.toToken().equals(token))
          .findFirst()
          .orElseThrow(() -> new IllegalArgumentException(
              "unrecognized algorithm name: `" + token + "`"));
    }

  }

  /**
   * A builder for a JSON Web Signature operator.
   */
  interface Builder {

    /**
     * Sets the key provider to use to obtain keys for signature or validation
     * operations.
     * @param keyProvider key provider
     * @return this builder
     */
    Builder keyProvider(KeyProvider keyProvider);

    /**
     * Sets the public key locator to use for signature validation.
     * @param publicKeyLocator public key locator
     * @return this builder
     */
    Builder publicKeyLocator(PublicKeyLocator publicKeyLocator);

    /**
     * Sets the algorithm to use for signature generation of validation.
     * @param algorithm algorithm
     * @return this builder
     */
    Builder algorithm(Algorithm algorithm);

    /**
     * Creates a JSON Web Signature operator using the configuration of this
     * builder.
     * @return signature operator
     * @throws JWTConfigurationException if an error occurs in creating the
     *    signature operator
     */
    JWS build() throws JWTConfigurationException;

  }

  /**
   * A JWS JOSE header.
   */
  interface Header extends JoseHeader {

    /**
     * Gets the value of the algorithm header ({@code alg})
     * @return header value or {@code null} if not present
     */
    String getAlgorithm();

  }

  /**
   * A factory that produces JWS operator instances.
   * <p>
   * An instance of this type can be used to produce an operator based on the
   * header specified for a JWT.
   */
  interface Factory {

    /**
     * Gets an operator appropriate for use with a signed JWT with the
     * specified header claims.
     * @param header JOSE header
     * @return operator
     * @throws JWTConfigurationException if an unexpected error occurs in
     *    producing an operator
     */
    JWS getOperator(Header header) throws JWTConfigurationException;

  }

  /**
   * A signature verification result.
   */
  interface Result {

    /**
     * Gets the payload whose signature was verified.
     * @return payload
     */
    String getPayload();

    /**
     * Public key information for the public key used to verify the signature.
     * @return public key if the signature was verified using a public key;
     *    otherwise the return value is {@code null}
     */
    PublicKeyInfo getPublicKeyInfo();

  }

  /**
   * Creates a signed Compact Serialization of a JWS using the given payload.
   * @param payload payload
   * @return signed JWS object
   * @throws JWTSignatureException if an exception occurs in creating the
   *    signature
   */
  String sign(String payload) throws JWTSignatureException;

  /**
   * Verifies the signature and extracts the encapsulated payload of a JWS.
   * @param encoded signed JWS in Compact Serialization encoding
   * @return payload encapsulated in the source JWS
   * @throws JWTSignatureException if the signature is invalid or an error
   *    occurs in trying to validate it
   */
  Result verify(String encoded) throws JWTSignatureException;

}

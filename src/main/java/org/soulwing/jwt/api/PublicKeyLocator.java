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

import java.net.URI;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import org.soulwing.jwt.api.exceptions.CertificateException;
import org.soulwing.jwt.api.exceptions.CertificateValidationException;
import org.soulwing.jwt.api.exceptions.PublicKeyNotFoundException;

/**
 * A service provider that locates a public key given criteria from a JOSE
 * header.
 *
 * @author Carl Harris
 */
public interface PublicKeyLocator {

  /**
   * An enumeration of strategy types for locating public keys.
   */
  enum StrategyType {
    /** certificate chain in {@code x5c} header claim */
    CERT_CHAIN,
    /** certificate chain URL in {@code x5u} header claim */
    CERT_CHAIN_URL,
    /** JSON web key in {@code jwk} header claim */
    JWK,
    /** JSON web key URL in {@code jku} header claim */
    JWK_URL
  }

  /**
   * A builder that creates a {@link PublicKeyLocator}.
   */
  interface Builder {

    /**
     * Locator strategies to enable; by default <em>all</em> strategies are
     * considered in the order given in the {@link StrategyType} enumeration.
     * @param strategies locator strategies;
     * @return this builder
     */
    Builder strategies(Set<StrategyType> strategies);

    /**
     * Specifies the certificate validator.
     * @param certificateValidator certificate validator
     * @return this builder
     */
    Builder certificateValidator(X509CertificateValidator certificateValidator);

    /**
     * Builds a locator in accordance with the configuration of this builder.
     * @return locator
     */
    PublicKeyLocator build();

  }


  /**
   * Criteria for a public key search as obtained from the JOSE header.
   */
  interface Criteria {

    /**
     * Gets the value of the {@code kid} header.
     * @return header value or {@code null} if the header is not present
     */
    String getKeyId();

    /**
     * Gets the value of the {@code x5c} header.
     * @return list of certificates or {@code null} if header is not present
     * @throws CertificateException if an error occurs in producing the
     *    certificate chain
     */
   List<X509Certificate> getCertificateChain()
        throws CertificateException;

    /**
     * Gets the value of the {@code x5u} header.
     * @return certificate chain URL or {@code null} if header is not present
     */
    URI getCertificateChainUrl();

    /**
     * Gets an object that can be used to match values of the {@code x5t}
     * and {@code x5t#S256} headers.
     * @return thumbprint if either header is available, otherwise {@code null}
     * @throws CertificateException if an error occurs in producing the
     *    thumbprint
     */
    Thumbprint getCertificateThumbprint() throws CertificateException;

    /**
     * Gets the value of the {@code jwk} header.
     * @return web key or {@code null} if header is not present
     * @throws CertificateException if an error occurs in producing the web key
     */
    JWK getWebKey() throws CertificateException;

    /**
     * Gets the value of the {@code jku} header.
     * @return URL or {@code null} if header is not present
     */
    URI getWebKeyUrl();

  }

  /**
   * An object that encapsulates the algorithms and matching operations for
   * certificate thumbprints provided in the JOSE header.
   */
  interface Thumbprint {

    /**
     * Gets a predicate that tests whether this thumbprint matches a given
     * certificate
     * @return predicate
     * @throws CertificateException if the matcher cannot be created due to
     *    an error (e.g. a JCA error in obtaining MessageDigest instances)
     */
    Predicate<X509Certificate> matcher() throws CertificateException;

  }

  /**
   * Locates the public key described by the given criteria, if possible.
   * @param criteria criteria to match
   * @return public key
   * @throws CertificateValidationException if a certificate containing the
   *    matching public key fails validation; e.g. expired, revoked,
   *    untrusted, etc
   * @throws PublicKeyNotFoundException if a matching public key cannot be
   *    found
   */
  PublicKey locate(Criteria criteria) throws PublicKeyNotFoundException,
      CertificateValidationException;

}

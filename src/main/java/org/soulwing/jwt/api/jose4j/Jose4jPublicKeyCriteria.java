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
package org.soulwing.jwt.api.jose4j;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;
import org.soulwing.jwt.api.JWK;
import org.soulwing.jwt.api.PublicKeyLocator;
import org.soulwing.jwt.api.exceptions.CertificateException;

/**
 * A {@link PublicKeyLocator.Criteria} implementation that delegates to a
 * Jose4j {@link JsonWebSignature}.
 *
 * @author Carl Harris
 */
class Jose4jPublicKeyCriteria implements PublicKeyLocator.Criteria {

  static final String X5U = "x5u";
  static final String JWK = "jwk";
  static final String JKU = "jku";

  private final JsonWebSignature delegate;

  Jose4jPublicKeyCriteria(JsonWebSignature delegate) {
    this.delegate = delegate;
  }

  @Override
  public String getKeyId() {
    return delegate.getKeyIdHeaderValue();
  }

  @Override
  public List<X509Certificate> getCertificateChain()
      throws CertificateException {
    try {
      return delegate.getCertificateChainHeaderValue();
    }
    catch (JoseException ex) {
      throw new CertificateException(ex);
    }
  }

  @Override
  public URI getCertificateChainUrl() {
    return Optional.ofNullable(delegate.getHeader(X5U)).map(URI::create)
        .orElse(null);
  }

  @Override
  public PublicKeyLocator.Thumbprint getCertificateThumbprint() {
    if (delegate.getX509CertSha1ThumbprintHeaderValue() == null
        && delegate.getX509CertSha256ThumbprintHeaderValue() == null) {
      return null;
    }
    return new Jose4jPublicKeyThumbprint(delegate);
  }

  @Override
  public JWK getWebKey() throws CertificateException {
    return Optional.ofNullable(getJwk())
        .map(Jose4jWebKey::new)
        .orElse(null);
  }

  /**
   * Gets a new web key from its JSON representation.
   * @return web key or {@code null} if the {@code jwk} header is not present
   * @throws CertificateException if an error occurs in creating the key
   */
  private JsonWebKey getJwk() {
    try {
      final Headers headers = delegate.getHeaders();
      if (headers.getObjectHeaderValue(JWK) == null) return null;
      return headers.getJwkHeaderValue(JWK);
    }
    catch (JoseException ex) {
      throw new CertificateException(ex);
    }
  }

  @Override
  public URI getWebKeyUrl() {
    return Optional.ofNullable(delegate.getHeader(JKU)).map(URI::create)
        .orElse(null);
  }

}

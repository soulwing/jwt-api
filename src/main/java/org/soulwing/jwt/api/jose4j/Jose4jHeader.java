/*
 * File created on Mar 29, 2019
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.exceptions.JWTParseException;

/**
 * A {@link org.soulwing.jwt.api.JoseHeader} implemented using Jose4j.
 *
 * @author Carl Harris
 */
class Jose4jHeader implements JWE.Header, JWS.Header {

  static final String TYP = HeaderParameterNames.TYPE;
  static final String CTY = HeaderParameterNames.CONTENT_TYPE;
  static final String KID = HeaderParameterNames.KEY_ID;
  static final String JWK = "jwk";
  static final String JKU = HeaderParameterNames.JWK_SET_URL;
  static final String X5C = HeaderParameterNames.X509_CERTIFICATE_CHAIN;
  static final String X5U = HeaderParameterNames.X509_URL;
  static final String X5T = HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT;
  static final String X5T_256 = HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT;
  static final String CRIT = HeaderParameterNames.CRITICAL;
  static final String ALG = HeaderParameterNames.ALGORITHM;
  static final String ENC = HeaderParameterNames.ENCRYPTION_METHOD;
  static final String ZIP = HeaderParameterNames.ZIP;

  private final Headers delegate;

  /**
   * Creates a new instance from a JWT encoded using compact serialization.
   * @param encoded JWT in compact serialization encoding
   * @return headers instance
   * @throws JWTParseException if an error occurs in decoding the JOSE header
   */
  static Jose4jHeader newInstance(String encoded) throws JWTParseException {
    if (encoded == null || encoded.trim().isEmpty()) {
      throw new JWTParseException("encoded token is required");
    }
    final String[] parts = CompactSerializer.deserialize(encoded);
    return toHeaders(decode(parts[0]));
  }

  private static Jose4jHeader toHeaders(String json) throws JWTParseException {
    try {
      final Headers headers = new Headers();
      headers.setFullHeaderAsJsonString(json);
      return new Jose4jHeader(headers);
    }
    catch (JoseException ex) {
      throw new JWTParseException(ex.getMessage(), ex);
    }
  }

  private static String decode(String part) throws JWTParseException {
    try {
      return new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8);
    }
    catch (RuntimeException ex) {
      throw new JWTParseException("invalid header encoding", ex);
    }
  }

  private Jose4jHeader(Headers delegate) {
    this.delegate = delegate;
  }

  @Override
  public String getType() {
    return delegate.getStringHeaderValue(TYP);
  }

  @Override
  public String getContentType() {
    return delegate.getStringHeaderValue(CTY);
  }

  @Override
  public String getKeyId() {
    return delegate.getStringHeaderValue(KID);
  }

  @Override
  public String getJsonWebKey() {
    return delegate.getStringHeaderValue(JWK);
  }

  @Override
  public String getJsonWebKeyUrl() {
    return delegate.getStringHeaderValue(JKU);
  }

  @Override
  public String getCertificateChain() {
    return delegate.getStringHeaderValue(X5C);
  }

  @Override
  public String getCertificateChainUrl() {
    return delegate.getStringHeaderValue(X5U);
  }

  @Override
  public String getCertificateSha1Fingerprint() {
    return delegate.getStringHeaderValue(X5T);
  }

  @Override
  public String getCertificateSha256Fingerprint() {
    return delegate.getStringHeaderValue(X5T_256);
  }

  @Override
  public String getCritical() {
    return delegate.getStringHeaderValue(CRIT);
  }

  @Override
  public String getKeyManagementAlgorithm() {
    return delegate.getStringHeaderValue(ALG);
  }

  @Override
  public String getContentEncryptionAlgorithm() {
    return delegate.getStringHeaderValue(ENC);
  }

  @Override
  public String getCompressionAlgorithm() {
    return delegate.getStringHeaderValue(ZIP);
  }

  @Override
  public String getAlgorithm() {
    return delegate.getStringHeaderValue(ALG);
  }

}

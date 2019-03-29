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
package org.soulwing.jwt.api;

/**
 * JOSE header fields for JWE and JWS.
 *
 * @author Carl Harris
 */
public interface JoseHeader {

  /**
   * Gets the value of the type header ({@code typ})
   * @return header value or {@code null} if not present
   */
  String getType();

  /**
   * Gets the value of the content type header ({@code cty})
   * @return header value or {@code null} if not present
   */
  String getContentType();

  /**
   * Gets the value of the key ID header ({@code kid})
   * @return header value or {@code null} if not present
   */
  String getKeyId();

  /**
   * Gets the value of the JSON web key header ({@code jwk})
   * @return header value or {@code null} if not present
   */
  String getJsonWebKey();

  /**
   * Gets the value of the JSON web key URL header ({@code jku})
   * @return header value or {@code null} if not present
   */
  String getJsonWebKeyUrl();

  /**
   * Gets the value of the certificate chain header ({@code x5c})
   * @return header value or {@code null} if not present
   */
  String getCertificateChain();

  /**
   * Gets the value of the certificate chain URL header ({@code x5u})
   * @return header value or {@code null} if not present
   */
  String getCertificateChainUrl();

  /**
   * Gets the value of the certificate SHA1 fingerprint header ({@code x5t})
   * @return header value or {@code null} if not present
   */
  String getCertificateSha1Fingerprint();

  /**
   * Gets the value of the certificate SHA256 fingerprint header ({@code x5t#256})
   * @return header value or {@code null} if not present
   */
  String getCertificateSha256Fingerprint();

  /**
   * Gets the value of the critical header ({@code crit})
   * @return header value or {@code null} if not present
   */
  String getCritical();

}

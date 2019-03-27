/*
 * File created on Mar 27, 2019
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

import java.security.cert.X509Certificate;

import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.soulwing.jwt.api.KeyInfo;

/**
 * Utility for configuring key-related characteristics of a JSON web structure.
 *
 * @author Carl Harris
 */
class JoseKeyInfoUtil {

  /**
   * Configures the key to use for a JSON web signature or encryption operation
   * and sets corresponding JOSE header claims.
   * @param jws the structure to configure
   * @param keyInfo key and associated information elements
   */
  static void configureKeyInfo(JsonWebStructure jws, KeyInfo keyInfo) {
    jws.setKey(keyInfo.getKey());
    if (keyInfo.getId() != null) {
      jws.setKeyIdHeaderValue(keyInfo.getId());
    }
    if (!keyInfo.getCertificates().isEmpty()) {
      jws.setX509CertSha1ThumbprintHeaderValue(keyInfo.getCertificates().get(0));
      jws.setX509CertSha256ThumbprintHeaderValue(keyInfo.getCertificates().get(0));
      if (keyInfo.getCertificateUrl() != null) {
        jws.setHeader(HeaderParameterNames.X509_URL,
            keyInfo.getCertificateUrl().toString());
      }
      else {
        jws.setCertificateChainHeaderValue(keyInfo.getCertificates().toArray(
            new X509Certificate[0]));
      }
    }
  }

}

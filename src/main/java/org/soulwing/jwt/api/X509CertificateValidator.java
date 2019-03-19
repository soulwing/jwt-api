/*
 * File created on Mar 18, 2019
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

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import org.soulwing.jwt.api.exceptions.CertificateValidationException;

/**
 * An X.509 certificate validator
 *
 * @author Carl Harris
 */
public interface X509CertificateValidator {

  /**
   * Validates the given chain of certificates.
   * @param chain chain of certificates
   * @throws CertificateValidationException if the certificate at the front
   *    of chain is not valid based on the remaining certificates in the chain
   *    and the given trust store
   */
  void validate(List<X509Certificate> chain)
      throws CertificateValidationException;

}

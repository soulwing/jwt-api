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
   * A factory for a {@link X509CertificateValidator}.
   * <p>
   * An instance of this factory type can be used to allow the validator
   * configuration to be determined from public key search criteria and
   * the certificate chain derived for those criteria.
   */
  interface Factory {

    /**
     * Gets a validator appropriate to the given public key criteria and
     * the certificate chain derived from it.
     * @param criteria public key criteria
     * @param certificateChain certificate chain
     * @return certificate validator
     * @throws CertificateValidationException if a validator cannot be
     *    produced due to an unexpected error
     */
    X509CertificateValidator getValidator(PublicKeyLocator.Criteria criteria,
        List<X509Certificate> certificateChain)
        throws CertificateValidationException;

  }

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

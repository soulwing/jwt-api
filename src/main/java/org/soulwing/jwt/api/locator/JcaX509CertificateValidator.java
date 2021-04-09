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
package org.soulwing.jwt.api.locator;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;

import org.soulwing.jwt.api.X509CertificateValidator;
import org.soulwing.jwt.api.exceptions.CertificateException;
import org.soulwing.jwt.api.exceptions.CertificateValidationException;

/**
 * A {@link X509CertificateValidator} implemented using a JCA PKIX path
 * builder.
 *
 * @author Carl Harris
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class JcaX509CertificateValidator implements X509CertificateValidator {

  private boolean checkRevocation = true;
  private boolean checkExpiration = true;
  private boolean checkSubjectOnly = false;
  private Clock clock = Clock.systemUTC();
  private KeyStore trustStore;

  private JcaX509CertificateValidator() {}

  /**
   * A builder that produces a {@link JcaX509CertificateValidator}.
   */
  public static class Builder {

    private final JcaX509CertificateValidator validator =
        new JcaX509CertificateValidator();

    private Builder() {}

    /**
     * Specifies the clock to use as the basis for validity checks.
     * @param clock clock
     * @return this builder
     */
    public Builder clock(Clock clock) {
      validator.clock = clock;
      return this;
    }

    /**
     * Specifies whether certificate revocation status should be checked.
     * @param checkRevocation flag indicating whether revocation status
     *    should be checked
     * @return this builder
     */
    public Builder checkRevocation(boolean checkRevocation) {
      validator.checkRevocation = checkRevocation;
      return this;
    }

    /**
     * Specifies whether certificate expiration status should be checked.
     * @param checkExpiration flag indicating whether expiration status
     *    should be checked
     * @return this builder
     */
    public Builder checkExpiration(boolean checkExpiration) {
      validator.checkExpiration = checkExpiration;
      return this;
    }

    /**
     * Specifies whether status checks should only be applied to the subject
     * certificate.
     * @param checkSubjectOnly flag indicating whether status checks should
     *    be applied to the subject certificate only
     * @return this builder
     */
    public Builder checkSubjectOnly(boolean checkSubjectOnly) {
      validator.checkSubjectOnly = checkSubjectOnly;
      return this;
    }

    /**
     * Specifies the trust store.
     * @param trustStore key store containing trusted root certificates
     * @return this builder
     */
    public Builder trustStore(KeyStore trustStore) {
      validator.trustStore = trustStore;
      return this;
    }

    /**
     * Creates a new validator in accordance with the configuration of this
     * builder.
     * @return validator instance
     */
    public X509CertificateValidator build() {
      if (validator.clock == null) {
        throw new IllegalArgumentException("clock is required");
      }
      if (validator.trustStore == null) {
        throw new IllegalArgumentException("trustStore is required");
      }
      return validator;
    }

  }

  /**
   * Gets a builder that creates a new instance.
   * @return builder
   */
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public void validate(List<X509Certificate> chain)
      throws CertificateValidationException {
    Date validityBasis = validityBasis(chain);
    checkExpiration(chain, validityBasis);
    validateCertPath(chain, trustStore, validityBasis);
  }

  private Date validityBasis(List<X509Certificate> chain) {
    Date validityBasis = new Date(clock.instant().toEpochMilli());
    if (!checkExpiration) {
      for (X509Certificate cert : chain) {
        if (cert.getNotAfter().before(validityBasis)) {
          validityBasis = cert.getNotAfter();
        }
      }
    }
    return validityBasis;
  }

  private void checkExpiration(List<X509Certificate> chain, Date validityBasis)
      throws CertificateValidationException {
    int depth = 0;
    try {
      for (final X509Certificate certificate : chain) {
        certificate.checkValidity(validityBasis);
        if (checkSubjectOnly) return;
        depth++;
      }
    }
    catch (CertificateExpiredException | CertificateNotYetValidException ex) {
      if (depth >= chain.size() - 1) {
        throw new CertificateValidationException("root " + ex.getMessage(), ex);
      }
      if (depth > 0) {
        throw new CertificateValidationException("issuer " + ex.getMessage(), ex);
      }
      throw new CertificateValidationException(ex.getMessage(), ex);
    }
  }

  private void validateCertPath(List<X509Certificate> chain,
      KeyStore trustStore, Date validityBasis)
      throws CertificateValidationException {
    try {
      final X509CertSelector target = new X509CertSelector();
      target.setCertificate(chain.get(0));

      final CertPathBuilder pkix = CertPathBuilder.getInstance("PKIX");

      final PKIXBuilderParameters params =
          new PKIXBuilderParameters(trustStore, target);

      if (checkExpiration) {
        params.setDate(validityBasis);
      }
      else {
        Date notAfter = validityBasis;
        for (X509Certificate cert : chain) {
          if (cert.getNotAfter().before(notAfter)) {
            notAfter = cert.getNotAfter();
          }
        }
        params.setDate(notAfter);
      }

      params.setRevocationEnabled(checkRevocation);
      if (checkRevocation) {
        final PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker)
            pkix.getRevocationChecker();

        if (checkSubjectOnly) {
          revocationChecker.setOptions(EnumSet.of(
              PKIXRevocationChecker.Option.ONLY_END_ENTITY));
        }
        params.addCertPathChecker(revocationChecker);
      }

      final CertStoreParameters intermediates =
          new CollectionCertStoreParameters(chain.subList(1, chain.size()));

      params.addCertStore(CertStore.getInstance("Collection", intermediates));

      pkix.build(params);
    }
    catch (CertPathBuilderException ex) {

      throw new CertificateValidationException(ex.getMessage(), ex);
    }
    catch (InvalidAlgorithmParameterException
            | KeyStoreException | NoSuchAlgorithmException ex) {
      throw new CertificateException(ex);
    }
  }

}

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

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.soulwing.jwt.api.PublicKeyInfo;
import org.soulwing.jwt.api.PublicKeyLocator;
import org.soulwing.jwt.api.X509CertificateValidator;
import org.soulwing.jwt.api.exceptions.CertificateException;
import org.soulwing.jwt.api.exceptions.CertificateValidationException;
import org.soulwing.jwt.api.exceptions.PublicKeyNotFoundException;

/**
 * A {@link PublicKeyLocator} implemented using the JCA.
 *
 * @author Carl Harris
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class JcaPublicKeyLocator implements PublicKeyLocator {

  private final Map<StrategyType, Strategy> strategies = new LinkedHashMap<>();

  private CertificateChainLoader chainLoader = PemCertificateChainLoader.getDefaultInstance();
  private Set<StrategyType> enabledStrategies = EnumSet.allOf(StrategyType.class);
  private X509CertificateValidator certificateValidator;
  private X509CertificateValidator.Factory certificateValidatorFactory;

  private JcaPublicKeyLocator() {
    strategies.put(StrategyType.CERT_CHAIN, new CertificateChainStrategy());
    strategies.put(StrategyType.CERT_CHAIN_URL, new CertificateChainUrlStrategy());
    strategies.put(StrategyType.JWK, new JsonWebKeyStrategy());
    strategies.put(StrategyType.JWK_URL, new JsonWebKeyUrlStrategy());
  }

  public static class Builder implements PublicKeyLocator.Builder {

    private JcaPublicKeyLocator locator = new JcaPublicKeyLocator();

    private Builder() {}

    public PublicKeyLocator.Builder chainLoader(
        CertificateChainLoader chainLoader) {
      locator.chainLoader = chainLoader;
      return this;
    }

    @Override
    public PublicKeyLocator.Builder strategies(Set<StrategyType> strategies) {
      locator.enabledStrategies = strategies;
      return this;
    }

    @Override
    public PublicKeyLocator.Builder certificateValidator(
        X509CertificateValidator validator) {
      locator.certificateValidator = validator;
      return this;
    }

    @Override
    public PublicKeyLocator.Builder certificateValidatorFactory(
        X509CertificateValidator.Factory validatorFactory) {
      locator.certificateValidatorFactory = validatorFactory;
      return this;
    }

    @Override
    public PublicKeyLocator build() {
      if (locator.certificateValidator == null
          && locator.certificateValidatorFactory == null) {
        throw new IllegalArgumentException(
            "certificate validator or validator factory is required");
      }
      if (locator.certificateValidator != null
          && locator.certificateValidatorFactory != null) {
        throw new IllegalArgumentException("specify either a certificate " +
            "validator or validator factory, not both");
      }
      return locator;
    }

  }

  /**
   * Gets a builder that builds a new locator.
   * @return builder
   */
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public PublicKeyInfo locate(Criteria criteria)
      throws PublicKeyNotFoundException, CertificateValidationException {
    try {
      for (final StrategyType type : strategies.keySet()) {
        if (!enabledStrategies.contains(type)) continue;
        final PublicKeyInfo info = strategies.get(type).locate(criteria);
        if (info != null) return info;
      }
      throw new PublicKeyNotFoundException();
    }
    catch (IOException ex) {
      throw new CertificateException(ex);
    }
  }

  private X509CertificateValidator getValidator(Criteria criteria,
      List<X509Certificate> chain) throws CertificateValidationException {
    if (certificateValidator != null) return certificateValidator;
    return certificateValidatorFactory.getValidator(criteria, chain);
  }

  private interface Strategy {
    PublicKeyInfo locate(Criteria criteria)
        throws CertificateValidationException, IOException;
  }

  private class CertificateChainStrategy implements Strategy {

    @Override
    public PublicKeyInfo locate(Criteria criteria)
        throws CertificateValidationException {
      final List<X509Certificate> chain = criteria.getCertificateChain();
      if (chain == null || chain.isEmpty()) return null;
      getValidator(criteria, chain).validate(chain);
      return PublicKeyInfo.builder()
          .publicKey(chain.get(0).getPublicKey())
          .certificates(chain)
          .build();
    }

  }

  private class CertificateChainUrlStrategy implements Strategy {

    @Override
    public PublicKeyInfo locate(Criteria criteria)
        throws CertificateValidationException, IOException {
      final URI url = criteria.getCertificateChainUrl();
      if (url == null) return null;
      final List<X509Certificate> chain = chainLoader.load(url);
      getValidator(criteria, chain).validate(chain);
      return PublicKeyInfo.builder()
          .publicKey(chain.get(0).getPublicKey())
          .certificates(chain)
          .build();
    }

  }

  private class JsonWebKeyStrategy implements Strategy {

    @Override
    public PublicKeyInfo locate(Criteria criteria) {
      // TODO: implement me
      return null;
    }

  }

  private class JsonWebKeyUrlStrategy implements Strategy {

    @Override
    public PublicKeyInfo locate(Criteria criteria) {
      // TODO: implement me
      return null;
    }

  }

}

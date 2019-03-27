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
package org.soulwing.jwt.api;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * A {@link PublicKey} and associated information.
 *
 * @author Carl Harris
 */
public class PublicKeyInfo {

  private final List<X509Certificate> certificates = new ArrayList<>();

  private PublicKey publicKey;

  private PublicKeyInfo() {}

  /**
   * A builder that creates a {@link PublicKeyInfo} instance.
   */
  public static class Builder {

    private final PublicKeyInfo info = new PublicKeyInfo();

    private Builder() {}

    /**
     * Specifies the subject public key.
     * @param publicKey public key
     * @return this builder
     */
    public Builder publicKey(PublicKey publicKey) {
      info.publicKey = publicKey;
      return this;
    }

    /**
     * Specifies certificates that will be added to the public key info.
     * @param certificates certificates
     * @return this builder
     */
    public Builder certificates(List<X509Certificate> certificates) {
      info.certificates.addAll(certificates);
      return this;
    }

    /**
     * Builds an instance according to the configuration of this builder.
     * @return public key info instance
     */
    public PublicKeyInfo build() {
      if (info.publicKey == null) {
        throw new IllegalArgumentException("public key is required");
      }
      return info;
    }

  }

  /**
   * Creates a builder that will build a new instance.
   * @return builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Gets the subject public key.
   * @return public key
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Gets the chain of certificates associated with the public key, if any
   * @return certificate chain (perhaps empty, but never {@code null})
   */
  public List<X509Certificate> getCertificates() {
    return certificates;
  }

}

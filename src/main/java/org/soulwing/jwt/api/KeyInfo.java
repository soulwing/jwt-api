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

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A key and optional associated information.
 *
 * @author Carl Harris
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class KeyInfo {

  private String id;
  private Key key;
  private List<X509Certificate> certificates = new ArrayList<>();
  private URI certificateUrl;

  private KeyInfo() {}

  /**
   * A builder that constructs a {@link KeyInfo} instance.
   */
  public static class Builder {

    private final KeyInfo keyInfo = new KeyInfo();

    private Builder() {}

    /**
     * Specifies an identifier for this key.
     * @param id identifier
     * @return this builder
     */
    public Builder id(String id) {
      keyInfo.id = id;
      return this;
    }

    /**
     * Specifies the key itself.
     * @param key the subject key
     * @return this builder
     */
    public Builder key(Key key) {
      keyInfo.key = key;
      return this;
    }

    /**
     * Specifies a list of certificates associated with this key.
     * @param certificates certificates to add to the resulting key info
     * @return this builder
     */
    public Builder certificates(List<X509Certificate> certificates) {
      keyInfo.certificates.addAll(certificates);
      return this;
    }

    /**
     * Specifies a URL from which certificates associated with this key may
     * be retrieved.
     * @param url URL
     * @return this builder
     */
    public Builder certificateUrl(URI url) {
      keyInfo.certificateUrl = url;
      return this;
    }

    /**
     * Builds and returns an instance according to the configuration of this
     * builder.
     * @return key info instance
     */
    public KeyInfo build() {
      if (keyInfo.key == null) {
        throw new IllegalArgumentException("key is required");
      }
      return keyInfo;
    }

  }

  /**
   * Creates a builder that constructs a new instance.
   * @return builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Gets the ID specified for this key.
   * @return ID or {@code null} if none was specified
   */
  public String getId() {
    return id;
  }

  /**
   * Gets the subject key.
   * @return key
   */
  public Key getKey() {
    return key;
  }

  /**
   * Gets the list of certificates associated with the key.
   * @return certificate list (possibly empty, but never {@code null})
   */
  public List<X509Certificate> getCertificates() {
    return Collections.unmodifiableList(certificates);
  }

  /**
   * Gets the URL from which certificates associated with the key may be
   * retrieved.
   * @return certificate URL or {@code null} if none was specified
   */
  public URI getCertificateUrl() {
    return certificateUrl;
  }

}

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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.soulwing.jwt.api.exceptions.CertificateException;

/**
 * A {@link CertificateChainLoader} that loads PEM-encoded certificates.
 * s
 * @author Carl Harris
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class PemCertificateChainLoader implements CertificateChainLoader {

  /**
   * Arbitrary limit just to ensure we can't get overwhelmed in loading
   * certificate objects from a URL.
   */
  static final int MAX_CHAIN_LENGTH = 10;

  private static final PemCertificateChainLoader DEFAULT_INSTANCE =
      new PemCertificateChainLoader();

  public static PemCertificateChainLoader getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  @Override
  public List<X509Certificate> load(URI url)
      throws CertificateException, IOException {
    assertIsSecure(url);
    return toCertificates(loadPemObjects(url));
  }

  private void assertIsSecure(URI url) throws CertificateException {
    final String scheme = url.getScheme();
    if (scheme != null && scheme.startsWith("http") && !scheme.equals("https")) {
      throw new CertificateException("certificate URL is not secure: " + url);
    }
  }

  private List<PemObject> loadPemObjects(URI url) throws IOException {
    try (final InputStream inputStream = openStream(url)) {
      return loadPemObjects(inputStream);
    }
  }

  protected InputStream openStream(URI url) throws IOException {
    return url.toURL().openStream();
  }

  private List<PemObject> loadPemObjects(InputStream inputStream)
      throws IOException {
    try (final PemReader reader = new PemReader(new InputStreamReader(
        inputStream, StandardCharsets.US_ASCII))) {
      final List<PemObject> objects = new LinkedList<>();
      PemObject object = reader.readPemObject();
      while (objects.size() < MAX_CHAIN_LENGTH && object != null) {
        objects.add(object);
        object = reader.readPemObject();
      }
      return objects;
    }
  }

  private List<X509Certificate> toCertificates(List<PemObject> objects)
      throws CertificateException  {
    try {
      final List<X509Certificate> certificates = new ArrayList<>();
      final CertificateFactory factory = CertificateFactory.getInstance("X.509");
      for (final PemObject object : objects) {
        final ByteArrayInputStream bos =
            new ByteArrayInputStream(object.getContent());
        certificates.add((X509Certificate) factory.generateCertificate(bos));
      }
      return certificates;
    }
    catch (Exception ex) {
      throw new CertificateException(ex);
    }

  }

}

/*
 * File created on Mar 17, 2019
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.function.Predicate;

import org.jose4j.jws.JsonWebSignature;
import org.soulwing.jwt.api.PublicKeyLocator;
import org.soulwing.jwt.api.exceptions.CertificateException;

/**
 * A {@link PublicKeyLocator.Thumbprint} implementation that delegates to a
 * a {@link JsonWebSignature} to obtain expected thumbprint values.
 *
 * @author Carl Harris
 */
class Jose4jPublicKeyThumbprint implements PublicKeyLocator.Thumbprint {

  private final JsonWebSignature delegate;

  Jose4jPublicKeyThumbprint(JsonWebSignature delegate) {
    this.delegate = delegate;
  }

  @Override
  public Predicate<X509Certificate> matcher() throws CertificateException {
    final List<Predicate<X509Certificate>> matchers = new ArrayList<>();

    final String sha1Thumbprint =
        delegate.getX509CertSha1ThumbprintHeaderValue();
    if (sha1Thumbprint != null) {
      matchers.add(ThumbprintMatcher.newInstance(sha1Thumbprint, "SHA1"));
    }

    final String sha256Thumbprint =
        delegate.getX509CertSha256ThumbprintHeaderValue();
    if (sha256Thumbprint != null) {
      matchers.add(ThumbprintMatcher.newInstance(sha256Thumbprint, "SHA-256"));
    }

    if (matchers.isEmpty()) return (c) -> false;
    return c -> matchers.stream().anyMatch(p -> p.test(c));
  }

  private static class ThumbprintMatcher implements Predicate<X509Certificate> {

    private final MessageDigest messageDigest;
    private final byte[] expected;

    static ThumbprintMatcher newInstance(String thumbprint, String algorithm)
        throws CertificateException {
      try {
        return new ThumbprintMatcher(MessageDigest.getInstance(algorithm),
            Base64.getUrlDecoder().decode(thumbprint));
      }
      catch (NoSuchAlgorithmException ex) {
        throw new CertificateException(ex);
      }
    }

    private ThumbprintMatcher(MessageDigest messageDigest, byte[] expected) {
      this.messageDigest = messageDigest;
      this.expected = expected;
    }

    @Override
    public boolean test(X509Certificate certificate) {
      try {
        final byte[] encoded = certificate.getEncoded();
        final byte[] actual = messageDigest.digest(encoded);
        return Arrays.equals(expected, actual);
      }
      catch (CertificateEncodingException ex) {
        throw new CertificateException(ex);
      }
    }

  }

}

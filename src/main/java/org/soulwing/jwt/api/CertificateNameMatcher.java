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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * A utility for matching certificate subject names.
 *
 * @author Carl Harris
 */
class CertificateNameMatcher {

  private static final String CN = "CN";

  static boolean hasSubjectName(String name, X509Certificate certificate) {
    try {
      final LdapName dn =
          new LdapName(certificate.getSubjectX500Principal().toString());
      for (final Rdn rdn : dn.getRdns()) {
        final Attributes attributes = rdn.toAttributes();
        final String cn = Optional.ofNullable(attributes.get(CN))
            .map(CertificateNameMatcher::getValue).orElse(null);
        if (name.equals(cn)) return true;
      }

      final Collection<List<?>> subjectAlternativeNames =
          certificate.getSubjectAlternativeNames();

      if (subjectAlternativeNames == null) return false;

      return subjectAlternativeNames.stream()
          .map(l -> l.get(1))
          .filter(o -> o instanceof String)
          .anyMatch(name::equals);
    }
    catch (CertificateParsingException | NamingException ex) {
      throw new RuntimeException(ex);
    }
  }

  private static String getValue(Attribute attribute) {
    try {
      return attribute.get().toString();
    }
    catch (NamingException ex) {
      throw new RuntimeException(ex);
    }
  }

}

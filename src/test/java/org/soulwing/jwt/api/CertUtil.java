/*
 * File created on Mar 19, 2019
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

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Utility methods for creating signed certificates.
 *
 * @author Carl Harris
 */
public class CertUtil {

  private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public static List<X509Certificate> createChain(
      int chainLength, Duration lifetime, OutputStream outputStream)
     throws Exception {

    final List<X509Certificate> chain = createChain(chainLength, lifetime);
    final PemWriter writer = new PemWriter(new OutputStreamWriter(outputStream,
        StandardCharsets.US_ASCII));
    for (final X509Certificate certificate : chain) {
      writer.writeObject(
          new PemObject("CERTIFICATE", certificate.getEncoded()));
    }
    writer.flush();
    return chain;
  }

  public static X509Certificate createSelfSignedCert(String subject,
      Duration lifetime, boolean isCA) throws Exception {
    return createSelfSignedCert(subject, (String) null, lifetime, isCA);
  }

  public static X509Certificate createSelfSignedCert(String subject,
      String altName, Duration lifetime, boolean isCA) throws Exception {
    final KeyPair subjectKeyPair = KeyUtil.newRsaKeyPair();
    return createSelfSignedCert(subject, altName, subjectKeyPair, lifetime, isCA);
  }

  public static X509Certificate createSelfSignedCert(String subject,
      KeyPair subjectKeyPair, Duration lifetime, boolean isCA)
      throws Exception {
    return createSelfSignedCert(subject, null, subjectKeyPair, lifetime, isCA);
  }

  public static X509Certificate createSelfSignedCert(String subject,
      String altName, KeyPair subjectKeyPair, Duration lifetime, boolean isCA)
          throws Exception {
    return selfSign(new X500Name("CN=" + subject),
        altName != null ? new GeneralName(GeneralName.dNSName, altName) : null,
        subjectKeyPair, isCA, SIGNATURE_ALGORITHM, lifetime);
  }

  public static List<X509Certificate> createChain(int chainLength,
      Duration... lifetimes) throws Exception {
    if (lifetimes.length == 0 && chainLength > 0) {
      throw new IllegalArgumentException("must provide at least one lifetime");
    }
    final List<X509Certificate> chain = new ArrayList<>();
    if (chainLength > 0) {
      X500Name issuerName = new X500Name("CN=root");
      KeyPair issuerKeyPair = KeyUtil.newRsaKeyPair();
      X509Certificate issuerCertificate = selfSign(issuerName, null,
          issuerKeyPair, chainLength > 1,
          SIGNATURE_ALGORITHM, lifetimes[lifetimes.length - 1]);

      chain.add(issuerCertificate);

      while (--chainLength > 0) {
        final Duration lifetime = chainLength >= lifetimes.length ?
            lifetimes[lifetimes.length - 1] : lifetimes[chainLength - 1];
        final X500Name subjectName = new X500Name("CN=child" + (chain.size() - 1));
        final KeyPair subjectKeyPair = KeyUtil.newRsaKeyPair();
        X509Certificate subjectCertificate = sign(
            subjectName, subjectKeyPair.getPublic(),
            issuerCertificate, issuerKeyPair,
            chainLength > 1, SIGNATURE_ALGORITHM, lifetime);
        chain.add(0, subjectCertificate);
        issuerKeyPair = subjectKeyPair;
        issuerCertificate = subjectCertificate;
      }
    }

    return chain;
  }

  public static X509Certificate selfSign(X500Name subject,
      GeneralName altName, KeyPair subjectKeyPair, boolean isCA,
      String algorithm, Duration lifetime)
      throws OperatorCreationException, CertificateException, IOException {

    final JcaX509v3CertificateBuilder certBuilder =
        newBuilder(subject, subject, subjectKeyPair.getPublic(), isCA, lifetime);

    if (altName != null) {
      certBuilder.addExtension(Extension.subjectAlternativeName, false,
          new GeneralNames(altName));
    }

    final ContentSigner contentSigner =
        new JcaContentSignerBuilder(algorithm).build(subjectKeyPair.getPrivate());

    return new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(certBuilder.build(contentSigner));
  }

  public static X509Certificate sign(X500Name subject, PublicKey subjectKey,
      X509Certificate issuer, KeyPair issuerKeyPair,
      boolean isCA, String algorithm, Duration lifetime)
      throws OperatorCreationException, CertificateException, IOException {

    final JcaX509v3CertificateBuilder certBuilder =
        newBuilder(new X500Name(issuer.getSubjectX500Principal().getName()),
            subject, subjectKey, isCA, lifetime);


    final X509ExtensionUtils extensionUtils = new BcX509ExtensionUtils();
    certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
        extensionUtils.createAuthorityKeyIdentifier(
            SubjectPublicKeyInfo.getInstance(issuerKeyPair.getPublic().getEncoded())));

    final ContentSigner contentSigner =
        new JcaContentSignerBuilder(algorithm).build(issuerKeyPair.getPrivate());

    return new JcaX509CertificateConverter().setProvider("BC")
        .getCertificate(certBuilder.build(contentSigner));
  }

  private static JcaX509v3CertificateBuilder newBuilder(
      X500Name issuer, X500Name subject, PublicKey subjectKey,
      boolean isCA, Duration lifetime) throws IOException {

    final Instant now = Instant.now();
    final Date startDate = new Date(now.toEpochMilli());
    final Date endDate = new Date(now.plus(lifetime).toEpochMilli());

    final BigInteger serialNumber = new BigInteger(Long.toString(now.toEpochMilli()));

    final JcaX509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(issuer, serialNumber, startDate,
            endDate, subject, subjectKey);

    certBuilder.addExtension(Extension.basicConstraints, isCA,
        new BasicConstraints(isCA));

    if (isCA) {
      certBuilder.addExtension(Extension.keyUsage, true, new
          KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
    }

    final X509ExtensionUtils extensionUtils = new BcX509ExtensionUtils();
    certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
        extensionUtils.createSubjectKeyIdentifier(
            SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded())));

    return certBuilder;
  }

}

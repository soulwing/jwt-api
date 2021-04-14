/*
 * File created on Apr 13, 2021
 *
 * Copyright (c) 2021 Carl Harris, Jr
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
package org.soulwing.jwt.api.jca;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.JWK;

/**
 * Unit tests for {@link JcaJsonWebKey}.
 *
 * @author Carl Harris
 */
public class JcaJsonWebKeyTest {

  private static final String KID = "someId";
  private static final JWK.Use USE = JWK.Use.SIGNATURE;
  private static final JWK.KeyOp OP = JWK.KeyOp.SIGN;
  private static final String ALG = "someAlg";

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Test
  public void testAES256() throws Exception {
    final JsonObject expected = loadJwk("aes-256.json");
    final Key key = new SecretKeySpec(
        Base64.getUrlDecoder().decode(expected.getString("k")), "AES");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .id(KID)
        .use(USE)
        .ops(OP)
        .algorithm(ALG)
        .key(key)
        .build().toString());

    validateAESKey(actual, expected);
    assertThat(actual.getString("kid"), is(equalTo(KID)));
    assertThat(actual.getString("use"), is(equalTo(USE.toString())));
    assertThat(actual.getJsonArray("key_ops"),
        is(equalTo(Json.createArrayBuilder().add(OP.toString()).build())));
    assertThat(actual.getString("alg"), is(equalTo(ALG)));
  }

  @Test
  public void testAES384() throws Exception {
    final JsonObject expected = loadJwk("aes-384.json");
    final Key key = new SecretKeySpec(
        Base64.getUrlDecoder().decode(expected.getString("k")), "AES");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(key)
        .build().toString());

    validateAESKey(actual, expected);
  }

  @Test
  public void testAES512() throws Exception {
    final JsonObject expected = loadJwk("aes-512.json");
    final Key key = new SecretKeySpec(
        Base64.getUrlDecoder().decode(expected.getString("k")), "AES");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(key)
        .build().toString());

    validateAESKey(actual, expected);
  }

  @Test
  public void testRSA2048() throws Exception {
    final X509Certificate certificate = loadCertificate("rsa-2048.pem");
    final JsonObject expected = loadJwk("rsa-2048.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(certificate.getPublicKey())
        .build().toString());
    validateRSAKey(actual, expected);
  }

  @Test
  public void testRSA3072() throws Exception {
    final X509Certificate certificate = loadCertificate("rsa-3072.pem");
    final JsonObject expected = loadJwk("rsa-3072.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(certificate.getPublicKey())
        .build().toString());
    validateRSAKey(actual, expected);
  }

  @Test
  public void testRSA4096() throws Exception {
    final X509Certificate certificate = loadCertificate("rsa-4096.pem");
    final JsonObject expected = loadJwk("rsa-4096.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(certificate.getPublicKey())
        .build().toString());
    validateRSAKey(actual, expected);
  }

  @Test
  public void testECsecp256r1() throws Exception {
    final X509Certificate certificate = loadCertificate("ec-p256.pem");
    final JsonObject expected = loadJwk("ec-p256.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(certificate.getPublicKey())
        .build().toString());
    validateECKey(actual, expected);
  }

  @Test
  public void testECsecp384r1() throws Exception {
    final X509Certificate certificate = loadCertificate("ec-p384.pem");
    final JsonObject expected = loadJwk("ec-p384.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(certificate.getPublicKey())
        .build().toString());
    validateECKey(actual, expected);
  }

  @Test
  public void testECsecp521r1() throws Exception {
    final X509Certificate certificate = loadCertificate("ec-p521.pem");
    final JsonObject expected = loadJwk("ec-p521.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(certificate.getPublicKey())
        .build().toString());
    validateECKey(actual, expected);
  }

  @Test
  public void testECsecp256k1() throws Exception {
    final X509Certificate certificate = loadCertificate("ec-secp256k1.pem");
    final JsonObject expected = loadJwk("ec-secp256k1.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .key(certificate.getPublicKey())
        .build().toString());
    validateECKey(actual, expected);
  }

  @Test
  public void testRSACertificates() throws Exception {
    final List<X509Certificate> certificates = Arrays.asList(
        loadCertificate("rsa-2048.pem"),
        loadCertificate("rsa-3072.pem"),
        loadCertificate("rsa-4096.pem"));

    final JsonObject expected = loadJwk("rsa-2048.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .certificates(certificates)
        .build().toString());

    validateRSAKey(actual, expected);
    validateCertificates(certificates, actual);
  }


  @Test
  public void testECCertificates() throws Exception {
    final List<X509Certificate> certificates = Arrays.asList(
        loadCertificate("ec-p256.pem"),
        loadCertificate("ec-p384.pem"),
        loadCertificate("ec-p521.pem"));

    final JsonObject expected = loadJwk("ec-p256.json");
    final JsonObject actual = parseJwk(JcaJsonWebKey.builder()
        .certificates(certificates)
        .build().toString());

    validateECKey(actual, expected);
    validateCertificates(certificates, actual);
  }

  private void validateAESKey(JsonObject actual, JsonObject expected) {
    assertThat(actual.getString("kty"), is(equalTo(expected.getString("kty"))));
    assertThat(actual.getString("k"), is(equalTo(expected.getString("k"))));
  }

  private void validateRSAKey(JsonObject actual, JsonObject expected) {
    assertThat(actual.getString("kty"), is(equalTo(expected.getString("kty"))));
    assertThat(actual.getString("n"), is(equalTo(expected.getString("n"))));
    assertThat(actual.getString("e"), is(equalTo(expected.getString("e"))));
  }

  private void validateECKey(JsonObject actual, JsonObject expected) {
    assertThat(actual.getString("kty"), is(equalTo(expected.getString("kty"))));
    assertThat(actual.getString("crv"), is(equalTo(expected.getString("crv"))));
    assertThat(actual.getString("x"), is(equalTo(expected.getString("x"))));
    assertThat(actual.getString("y"), is(equalTo(expected.getString("y"))));
  }

  private void validateCertificate(X509Certificate expected, JsonObject jwk)
      throws Exception {
    validateCertificates(Collections.singletonList(expected), jwk);
  }

  private void validateCertificates(List<X509Certificate> expected,
      JsonObject jwk) throws Exception {
    Certificate actual = null;
    for (int i = expected.size() - 1; i >= 0; i--) {
      final byte[] encoded = Base64.getDecoder()
          .decode(jwk.getJsonArray("x5c").getString(i));
      actual = validateCertificate(encoded, expected.get(i));
    }
    assertThat(JcaJsonWebKey.certThumbprint(actual, "SHA"),
        is(equalTo(Base64.getUrlDecoder().decode(jwk.getString("x5t")))));
    assertThat(JcaJsonWebKey.certThumbprint(actual, "SHA-256"),
        is(equalTo(Base64.getUrlDecoder().decode(jwk.getString("x5t#s256")))));
  }

  private Certificate validateCertificate(byte[] encoded,
      X509Certificate expected) throws CertificateException {
    final CertificateFactory factory = CertificateFactory.getInstance("X.509");
    final Certificate actual =
        factory.generateCertificate(new ByteArrayInputStream(encoded));
    assertThat(actual, is(equalTo(expected)));
    return actual;
  }

  private JsonObject parseJwk(String jwk) {
    return Json.createReader(new StringReader(jwk)).readObject();
  }

  private X509Certificate loadCertificate(String resourceName) throws Exception {
    final CertificateFactory factory = CertificateFactory.getInstance("X.509");
    try (final InputStream inputStream = resourceInputStream(resourceName)) {
      return (X509Certificate) factory.generateCertificate(inputStream);
    }
  }

  private JsonObject loadJwk(String resourceName) throws Exception {
    try (final InputStream inputStream = resourceInputStream(resourceName)) {
      return Json.createReader(inputStream).readObject();
    }
  }

  private InputStream resourceInputStream(String resourceName) throws IOException {
    final InputStream inputStream =
        getClass().getClassLoader().getResourceAsStream(resourceName);
    if (inputStream == null) {
      throw new FileNotFoundException(resourceName);
    }
    return inputStream;
  }

  @Test
  public void testBitsToOctets() throws Exception {
    assertThat(JcaJsonWebKey.bitsToOctets(0), is(equalTo(0)));
    assertThat(JcaJsonWebKey.bitsToOctets(1), is(equalTo(1)));
    assertThat(JcaJsonWebKey.bitsToOctets(8), is(equalTo(1)));
    assertThat(JcaJsonWebKey.bitsToOctets(9), is(equalTo(2)));
    assertThat(JcaJsonWebKey.bitsToOctets(10), is(equalTo(2)));
  }

  @Test
  public void testEcPad() throws Exception {
    assertThat(JcaJsonWebKey.ecPad(BigInteger.ZERO, 1),
        is(equalTo(new byte[]{ 0 })));
    assertThat(JcaJsonWebKey.ecPad(BigInteger.ZERO, 2),
        is(equalTo(new byte[]{ 0, 0 })));
    assertThat(JcaJsonWebKey.ecPad(BigInteger.ZERO, 3),
        is(equalTo(new byte[]{ 0, 0, 0 })));
    assertThat(JcaJsonWebKey.ecPad(BigInteger.valueOf(0xffffff), 3),
        is(equalTo(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff })));
    assertThat(JcaJsonWebKey.ecPad(BigInteger.valueOf(0xffffff), 4),
        is(equalTo(new byte[] { 0, (byte) 0xff, (byte) 0xff, (byte) 0xff })));
  }

  @Test
  public void testEcCurve() throws Exception {
    validateCurve("secp256r1", "P-256");
    validateCurve("secp384r1", "P-384");
    validateCurve("secp521r1", "P-521");
    validateCurve("secp256k1", "secp256k1");

    // Testing the case of a curve that isn't in the map of OID-to-curve names
    // requires a legitimate JCA curve name. The `secp128r1` curve is rarely
    // used and very unlikely to be added to the map, so it makes a good choice.
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("unsupported EC curve");
    validateCurve("secp128r1", null);
  }

  private void validateCurve(String jcaCurve, String jwtCurve)
      throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec(jcaCurve));
    KeyPair keyPair = kpg.generateKeyPair();
    assertThat(JcaJsonWebKey.ecCurve((ECPublicKey) keyPair.getPublic()),
        is(equalTo(jwtCurve)));
  }

  @Test
  public void testUnsignedRaw() throws Exception {
    // if the high order bit would be set in the most significant byte
    // BigInteger.toByteArray would prepend an extra byte to indicate that
    // the sign bit is zero (since the byte array represents a signed two's
    // complement integer). But since we want to interpret it as an unsigned
    // int, we should truncate the leading zero.

    // test cases where the high order bit is set
    assertThat(JcaJsonWebKey.unsignedRaw(BigInteger.valueOf(0xff)),
        is(equalTo(new byte[]{ (byte) 0xff })));
    assertThat(JcaJsonWebKey.unsignedRaw(BigInteger.valueOf(0xffff)),
        is(equalTo(new byte[]{ (byte) 0xff, (byte) 0xff })));
    assertThat(JcaJsonWebKey.unsignedRaw(BigInteger.valueOf(0xffffff)),
        is(equalTo(new byte[]{ (byte) 0xff, (byte) 0xff, (byte) 0xff })));

    // obviously, if the high order bit isn't set, it still needs to work
    assertThat(JcaJsonWebKey.unsignedRaw(BigInteger.valueOf(0)),
        is(equalTo(new byte[]{ (byte) 0 })));
    assertThat(JcaJsonWebKey.unsignedRaw(BigInteger.valueOf(0x7f)),
        is(equalTo(new byte[]{ (byte) 0x7f })));
    assertThat(JcaJsonWebKey.unsignedRaw(BigInteger.valueOf(0x7fff)),
        is(equalTo(new byte[]{ (byte) 0x7f, (byte) 0xff })));

    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("non-negative");
    JcaJsonWebKey.unsignedRaw(BigInteger.ONE.negate());
  }

}

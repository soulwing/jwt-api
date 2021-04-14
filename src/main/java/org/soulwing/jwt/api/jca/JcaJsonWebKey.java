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

import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.stream.JsonCollectors;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.soulwing.jwt.api.JWK;

/**
 *  A {@link JWK} implemented using the JCA API (with a little Bouncy Castle).
 *
 * @author Carl Harris
 */
public class JcaJsonWebKey implements JWK {

  private static final Map<String, String> OID_TO_CURVE = new HashMap<>();

  /*
   * These are the curves that are identified in the spec, plus another that
   * is commonly used. More could be added as needed, by including the OID
   * used to identify the curve in the public key and specifying the name to
   * use in the `crv:` property of the JWK. When adding, be sure to update
   * the test in JcaJsonWebKeyTest to validate it.
   */
  static {
    OID_TO_CURVE.put("1.2.840.10045.3.1.7", "P-256");
    OID_TO_CURVE.put("1.3.132.0.34", "P-384");
    OID_TO_CURVE.put("1.3.132.0.35", "P-521");
    OID_TO_CURVE.put("1.3.132.0.10", "secp256k1");
  }

  private final Key key;
  private final JsonObject delegate;

  private JcaJsonWebKey(Key key, JsonObject delegate) {
    this.key = key;
    this.delegate = delegate;
  }

  static class Builder implements JWK.Builder {

    private String id;
    private String type;
    private String algorithm;
    private Use use;
    private Set<KeyOp> ops = new HashSet<>();
    private Key key;
    private List<X509Certificate> certificates = new ArrayList<>();

    @Override
    public JWK.Builder id(String id) {
      this.id = id;
      return this;
    }

    @Override
    public JWK.Builder type(String type) {
      this.type = type;
      return this;
    }

    @Override
    public JWK.Builder algorithm(String algorithm) {
      this.algorithm = algorithm;
      return this;
    }

    @Override
    public JWK.Builder use(Use use) {
      this.use = use;
      return this;
    }

    @Override
    public JWK.Builder ops(KeyOp... ops) {
      return ops(Arrays.asList(ops));
    }

    @Override
    public JWK.Builder ops(Collection<KeyOp> ops) {
      this.ops.addAll(ops);
      return this;
    }

    @Override
    public JWK.Builder key(Key key) {
      this.key = key;
      return this;
    }

    @Override
    public JWK.Builder certificates(X509Certificate... certificates) {
      return certificates(Arrays.asList(certificates));
    }

    @Override
    public JWK.Builder certificates(List<X509Certificate> certificates) {
      this.certificates.addAll(certificates);
      return this;
    }

    private void defaultType() {
      if (this.type == null) {
        if (this.key instanceof SecretKey) {
          this.type = "oct";
        }
        else if (this.key instanceof ECPublicKey) {
          this.type = "EC";
        }
        else if (this.key instanceof RSAPublicKey) {
          this.type = "RSA";
        }
        else {
          this.type = this.key.getAlgorithm();
        }
      }
    }

    private void defaultKey() {
      if (this.key == null) {
        this.key = this.certificates.get(0).getPublicKey();
      }
    }

    @Override
    public JWK build() {
      validateKey();
      defaultKey();
      defaultType();
      return new JcaJsonWebKey(key, createJwk());
    }

    private JsonObject createJwk() {
      final JsonObjectBuilder builder = Json.createObjectBuilder();
      if (id != null) {
        builder.add("kid", id);
      }
      if (type != null) {
        builder.add("kty", type);
      }
      final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
      if (key instanceof SecretKey) {
        describeKey((SecretKey) key, encoder, builder);
      }
      else if (key instanceof RSAPublicKey) {
        describeKey((RSAPublicKey) key, encoder, builder);
      }
      else if (key instanceof ECPublicKey) {
        describeKey((ECPublicKey) key, encoder, builder);
      }
      else if (key != null) {
        throw new IllegalArgumentException(
            "unsupported key type: " + key.getAlgorithm());
      }
      if (!certificates.isEmpty()) {
        describeCertificates(certificates, encoder, builder);
      }
      if (algorithm != null) {
        builder.add("alg", algorithm);
      }
      if (use != null) {
        builder.add("use", use.toString());
      }
      if (!ops.isEmpty()) {
        builder.add("key_ops", ops.stream()
            .map(KeyOp::toString)
            .map(Json::createValue)
            .collect(JsonCollectors.toJsonArray()));
      }
      return builder.build();
    }

    private void validateKey() {
      if (this.key == null && this.certificates.isEmpty()) {
        throw new IllegalArgumentException("either a key or certificate is required");
      }
    }

  }

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public Key getKey() {
    return key;
  }

  @Override
  public JsonObject toJson() {
    return delegate;
  }

  @Override
  public String toString() {
    return delegate.toString();
  }

  private static void describeKey(SecretKey secretKey, Base64.Encoder encoder,
      JsonObjectBuilder builder) {
    builder.add("k", encoder.encodeToString(secretKey.getEncoded()));
  }

  private static void describeKey(RSAPublicKey publicKey, Base64.Encoder encoder,
      JsonObjectBuilder builder) {
    final byte[] exponent = unsignedRaw(publicKey.getPublicExponent());
    final byte[] modulus = unsignedRaw(publicKey.getModulus());
    builder.add("n", encoder.encodeToString(modulus));
    builder.add("e", encoder.encodeToString(exponent));
  }

  private static void describeKey(ECPublicKey publicKey, Base64.Encoder urlEncoder,
      JsonObjectBuilder builder) {
    final ECParameterSpec params = publicKey.getParams();

    final int length = bitsToOctets(params.getCurve().getField().getFieldSize());
    final byte[] x = ecPad(publicKey.getW().getAffineX(), length);
    final byte[] y = ecPad(publicKey.getW().getAffineY(), length);

    builder.add("crv", ecCurve(publicKey));
    builder.add("x", urlEncoder.encodeToString(x));
    builder.add("y", urlEncoder.encodeToString(y));
  }

  private static void describeCertificates(List<X509Certificate> certificates,
      Base64.Encoder urlEncoder, JsonObjectBuilder builder) {
    try {
      final X509Certificate certificate = certificates.get(0);
      final JsonArrayBuilder chain = Json.createArrayBuilder();
      for (final X509Certificate cert : certificates) {
        chain.add(Base64.getEncoder().encodeToString(cert.getEncoded()));
      }
      builder.add("x5c", chain);
      builder.add("x5t",
          urlEncoder.encodeToString(certThumbprint(certificate, "SHA")));
      builder.add("x5t#s256",
          urlEncoder.encodeToString(certThumbprint(certificate, "SHA-256")));
    }
    catch (CertificateEncodingException ex) {
      throw new RuntimeException(ex);
    }
  }

  static byte[] certThumbprint(Certificate certificate,
      String algorithm) {
    try {
      final MessageDigest md = MessageDigest.getInstance(algorithm);
      return md.digest(certificate.getEncoded());
    }
    catch (NoSuchAlgorithmException | CertificateEncodingException ex) {
      throw new RuntimeException(ex);
    }
  }

  /**
   * Converts a bit count to an integral number of octets needed to represent
   * that quantity of bits.
   * @param bits number of bits
   * @return corresponding number of bytes
   */
  static int bitsToOctets(int bits) {
    int octets = bits / 8;
    if (bits % 8 != 0) {
      octets++;
    }
    return octets;
  }

  /**
   * Zero pads an EC affine coordinate to an integral number of bytes that
   * correponds to the size of the underlying field in bits as required by
   * RFC 7517.
   *
   * @param value the coordinate to pad
   * @param length the number of bytes needed to represent all possible
   *    coordinates in the underlying field using unsigned two's complement
   *    representation
   * @return zero-padded two's complement representation of the coordinate
   */
  static byte[] ecPad(BigInteger value, int length) {
    byte[] buf = unsignedRaw(value);
    if (buf.length < length) {
      final byte[] pad = new byte[length];
      Arrays.fill(pad, (byte) 0);
      System.arraycopy(buf, 0, pad, length - buf.length, buf.length);
      buf = pad;
    }
    return buf;
  }

  /**
   * Gets the name to use for the JWK {@code crv:} property for a given
   * EC public key. Only named curves are supported by JWK. The OID that
   * identifies the curve in the public key is used to find the corresponding
   * name in the {@link #OID_TO_CURVE} map.
   *
   * @param publicKey the subject EC public key
   * @return curve name
   * @throws IllegalArgumentException if the curve OID is not recognized
   */
  static String ecCurve(ECPublicKey publicKey) {
    final SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
        ASN1Sequence.getInstance(publicKey.getEncoded()));

    final AlgorithmIdentifier algorithmId = spki.getAlgorithm();

    final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)
        algorithmId.getParameters();

    final String curve = OID_TO_CURVE.get(oid.toString());
    if (curve == null) {
      throw new IllegalArgumentException("unsupported EC curve");
    }
    return curve;
  }

  /**
   * Converts a non-negative big integer value to an unsigned two's complement
   * representation in a byte array.
   *
   * @param value the value to convert
   * @return two's complement representation
   * @throws IllegalArgumentException if {@code value} is negative.
   */
  static byte[] unsignedRaw(BigInteger value) {
    if (value.signum() < 0) {
      throw new IllegalArgumentException("value must be non-negative");
    }
    byte[] buf = value.toByteArray();
    if (value.signum() >= 0 && buf.length > 1 && buf[0] == 0) {
      buf = Arrays.copyOfRange(buf, 1, buf.length);
    }
    return buf;
  }


}

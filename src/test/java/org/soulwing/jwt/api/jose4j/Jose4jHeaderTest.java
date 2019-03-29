/*
 * File created on Mar 29, 2019
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.ALG;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.CRIT;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.CTY;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.ENC;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.JKU;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.JWK;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.KID;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.TYP;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.X5C;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.X5T;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.X5T_256;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.X5U;
import static org.soulwing.jwt.api.jose4j.Jose4jHeader.ZIP;

import java.io.StringWriter;
import javax.json.Json;
import javax.json.JsonObject;

import org.jose4j.jwx.Headers;
import org.junit.BeforeClass;
import org.junit.Test;
import org.soulwing.jwt.api.exceptions.JWTParseException;

/**
 * Unit tests for {@link Jose4jHeader}.
 *
 * @author Carl Harris
 */
public class Jose4jHeaderTest {

  private static final String TYPE = "type";
  private static final String CONTENT_TYPE = "contentType";
  private static final String KEY_ID = "keyId";
  private static final String JSON_WEB_KEY = "jsonWebKey";
  private static final String JSON_WEB_KEY_URL = "jsonWebKeyUrl";
  private static final String CERT_CHAIN = "certChain";
  private static final String CERT_CHAIN_URL = "certChainUrl";
  private static final String CERT_SHA_1_FINGERPRINT = "certSha1Fingerprint";
  private static final String CERT_SHA_256_FINGERPRINT = "certSha256Fingerprint";
  private static final String CRITICAL = "critical";
  private static final String ALGORITHM = "algorithm";
  private static final String ENCRYPTION = "encryption";
  private static final String COMPRESSION = "compression";

  private static final JsonObject HEADER = Json.createObjectBuilder()
      .add(TYP, TYPE)
      .add(CTY, CONTENT_TYPE)
      .add(KID, KEY_ID)
      .add(JWK, JSON_WEB_KEY)
      .add(JKU, JSON_WEB_KEY_URL)
      .add(X5C, CERT_CHAIN)
      .add(X5U, CERT_CHAIN_URL)
      .add(X5T, CERT_SHA_1_FINGERPRINT)
      .add(X5T_256, CERT_SHA_256_FINGERPRINT)
      .add(CRIT, CRITICAL)
      .add(ALG, ALGORITHM)
      .add(ENC, ENCRYPTION)
      .add(ZIP, COMPRESSION)
      .build();

  private static String encoded;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    final StringWriter writer = new StringWriter();
    Json.createWriter(writer).writeObject(HEADER);
    final Headers headers = new Headers();
    headers.setFullHeaderAsJsonString(writer.toString());
    encoded = headers.getEncodedHeader();
  }

  @Test
  public void testNewInstance() throws Exception {
    final Jose4jHeader header = Jose4jHeader.newInstance(encoded);
    assertThat(header.getType(), is(equalTo(TYPE)));
    assertThat(header.getContentType(), is(equalTo(CONTENT_TYPE)));
    assertThat(header.getKeyId(), is(equalTo(KEY_ID)));
    assertThat(header.getJsonWebKey(), is(equalTo(JSON_WEB_KEY)));
    assertThat(header.getJsonWebKeyUrl(), is(equalTo(JSON_WEB_KEY_URL)));
    assertThat(header.getCertificateChain(), is(equalTo(CERT_CHAIN)));
    assertThat(header.getCertificateChainUrl(), is(equalTo(CERT_CHAIN_URL)));
    assertThat(header.getCertificateSha1Fingerprint(), is(equalTo(CERT_SHA_1_FINGERPRINT)));
    assertThat(header.getCertificateSha256Fingerprint(), is(equalTo(CERT_SHA_256_FINGERPRINT)));
    assertThat(header.getCritical(), is(equalTo(CRITICAL)));
    assertThat(header.getAlgorithm(), is(equalTo(ALGORITHM)));
    assertThat(header.getKeyManagementAlgorithm(), is(equalTo(ALGORITHM)));
    assertThat(header.getContentEncryptionAlgorithm(), is(equalTo(ENCRYPTION)));
    assertThat(header.getCompressionAlgorithm(), is(equalTo(COMPRESSION)));
  }

  @Test(expected = JWTParseException.class)
  public void testNewInstanceWhenNullHeader() throws Exception {
    Jose4jHeader.newInstance(null);
  }

  @Test(expected = JWTParseException.class)
  public void testNewInstanceWhenEmptyHeader() throws Exception {
    Jose4jHeader.newInstance("");
  }

  @Test(expected = JWTParseException.class)
  public void testNewInstanceWhenParseError() throws Exception {
    Jose4jHeader.newInstance("foobar");
  }

  @Test(expected = JWTParseException.class)
  public void testNewInstanceWhenEncodingError() throws Exception {
    Jose4jHeader.newInstance("+");
  }


}
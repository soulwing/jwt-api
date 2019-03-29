/*
 * File created on Mar 8, 2019
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwx.CompactSerializer;
import org.soulwing.jwt.api.Assertions;
import org.soulwing.jwt.api.BiPredicateAssertions;
import org.soulwing.jwt.api.Claims;
import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.JWS;
import org.soulwing.jwt.api.JWTGenerator;
import org.soulwing.jwt.api.JWTProvider;
import org.soulwing.jwt.api.JWTValidator;
import org.soulwing.jwt.api.JoseHeader;
import org.soulwing.jwt.api.exceptions.JWTParseException;

/**
 * A {@link JWTProvider} implemented using Jose4j.
 *
 * @author Carl Harris
 */
public class Jose4jProvider implements JWTProvider {

  @Override
  public Claims.Builder claims() {
    return new Jose4jClaimsBuilder();
  }

  @Override
  public Claims parse(String json) throws JWTParseException {
    try {
      return new Jose4jClaims(JwtClaims.parse(json));
    }
    catch (InvalidJwtException ex) {
      throw new JWTParseException(ex);
    }
  }

  @Override
  public JoseHeader header(String encoded) throws JWTParseException {
    return Jose4jHeader.newInstance(encoded);
  }

  @Override
  public Assertions.Builder assertions() {
    return BiPredicateAssertions.builder();
  }

  @Override
  public JWS.Builder signatureOperator() {
    return Jose4jSignatureOperator.builder();
  }

  @Override
  public JWE.Builder encryptionOperator() {
    return Jose4jEncryptionOperator.builder();
  }

  @Override
  public JWTGenerator.Builder generator() {
    return Jose4jGenerator.builder();
  }

  @Override
  public JWTValidator.Builder validator() {
    return Jose4jValidator.builder(this);
  }

}

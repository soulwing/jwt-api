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
package org.soulwing.jwt.api;


import org.soulwing.jwt.api.exceptions.JWTParseException;

/**
 * A JWT provider.
 *
 * @author Carl Harris
 */
@SuppressWarnings("unused")
public interface JWTProvider {

  /**
   * Gets a builder that will produce a {@link Claims} instance.
   * @return claims builder
   */
  Claims.Builder claims();

  /**
   * Parses a JSON string to create a {@link Claims} instance.
   * @param json JSON in a string serialization
   * @return resulting claims object
   * @throws JWTParseException if the JSON cannot be parsed successfully
   */
  Claims parse(String json) throws JWTParseException;

  /**
   * Gets a builder that will produce an {@link Assertions} instance.
   * @return assertions builder
   */
  Assertions.Builder assertions();

  /**
   * Gets a builder that will produce a {@link JWS} operator instance.
   * @return signature operator builder
   */
  JWS.Builder signatureOperator();

  /**
   * Gets a builder that will produce a {@link JWE} operator instance.
   * @return encryption operator builder
   */
  JWE.Builder encryptionOperator();

  /**
   * Gets a builder that will produce a {@link JWTGenerator} instance.
   * @return validator builder
   */
  JWTGenerator.Builder generator();

  /**
   * Gets a builder that will produce a {@link JWTValidator} instance.
   * @return validator builder
   */
  JWTValidator.Builder validator();


}

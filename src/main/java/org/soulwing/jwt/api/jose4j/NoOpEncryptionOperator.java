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

import org.soulwing.jwt.api.JWE;
import org.soulwing.jwt.api.exceptions.JWTEncryptionException;

/**
 * A {@link JWE} encryption provider whose operations are no-op; they simply
 * return the input argument.
 *
 * @author Carl Harris
 */
class NoOpEncryptionOperator implements JWE {

  static final NoOpEncryptionOperator INSTANCE = new NoOpEncryptionOperator();

  private NoOpEncryptionOperator() {
  }

  @Override
  public String encrypt(String payload) throws JWTEncryptionException {
    return payload;
  }

  @Override
  public String decrypt(String encoded) throws JWTEncryptionException {
    return encoded;
  }

}

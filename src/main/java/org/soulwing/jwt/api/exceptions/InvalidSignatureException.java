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
package org.soulwing.jwt.api.exceptions;

import org.soulwing.jwt.api.JWS;

/**
 * An exception thrown when a signature validation fails.
 *
 * @author Carl Harris
 */
public class InvalidSignatureException extends JWTSignatureException {

  public InvalidSignatureException(JWS.Algorithm algorithm, String keyId) {
    super(algorithm.toToken() + " signature invalid"
        + (keyId != null ? "using '" + keyId + "'" : ""));
  }

}

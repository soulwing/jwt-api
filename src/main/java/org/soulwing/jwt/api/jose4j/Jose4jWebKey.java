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

import java.security.Key;
import javax.json.JsonObject;

import org.jose4j.jwk.JsonWebKey;
import org.soulwing.jwt.api.JWK;

/**
 * A {@link JWK} implemented using Jose4j.
 *
 * @author Carl Harris
 */
class Jose4jWebKey implements JWK {

  private final JsonWebKey delegate;

  Jose4jWebKey(JsonWebKey delegate) {
    this.delegate = delegate;
  }

  @Override
  public Key getKey() {
    return delegate.getKey();
  }

  @Override
  public JsonObject toJson() {
    throw new UnsupportedOperationException();
  }
}

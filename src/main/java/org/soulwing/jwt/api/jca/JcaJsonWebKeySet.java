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

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;

import org.soulwing.jwt.api.JWK;
import org.soulwing.jwt.api.JWKS;

/**
 * A simple and obvious {@link JWKS} implementation that wraps a JSON-P
 * link {@link JsonObject}.
 * <p>
 * Not really any JCA at work here.
 *
 * @author Carl Harris
 */
public class JcaJsonWebKeySet implements JWKS {

  private final JsonObject delegate;

  private JcaJsonWebKeySet(JsonObject delegate) {
    this.delegate = delegate;
  }

  /**
   * A {@link JWKS.Builder} that builds an instance of {@link JcaJsonWebKeySet}.
   */
  static class Builder implements JWKS.Builder {

    private final JsonArrayBuilder delegate = Json.createArrayBuilder();

    @Override
    public JWKS.Builder add(JWK key) {
      delegate.add(key.toJson());
      return this;
    }

    @Override
    public JWKS.Builder add(JWK.Builder builder) {
      delegate.add(builder.build().toJson());
      return this;
    }

    @Override
    public JWKS build() {
      return new JcaJsonWebKeySet(Json.createObjectBuilder()
          .add("keys", delegate.build())
          .build());
    }

  }

  /**
   * Gets a new builder instance.
   * @return builder instance
   */
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public JsonObject toJson() {
    return delegate;
  }

  @Override
  public String toString() {
    return delegate.toString();
  }

}

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
package org.soulwing.jwt.api.exceptions;

import java.time.Duration;
import java.time.Instant;

/**
 * An exception thrown when an assertion about the lifetime of a token has
 * failed.
 *
 * @author Carl Harris
 */
public class LifetimeAssertionException
    extends JWTAssertionFailedException {

  public LifetimeAssertionException(Instant instant, Instant issuedAt,
      Duration lifetime) {
    super(message(instant, issuedAt, lifetime));
  }

  private static String message(Instant instant, Instant issuedAt,
      Duration lifetime) {
    final StringBuilder sb = new StringBuilder();
    sb.append("issue time of ");
    sb.append(issuedAt);
    sb.append(" with lifetime of ");
    sb.append(lifetime);
    sb.append(" is before current time of ");
    sb.append(instant);
    return sb.toString();
  }
  
}

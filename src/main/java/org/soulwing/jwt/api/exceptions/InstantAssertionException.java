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
import java.util.function.BiFunction;

/**
 * An exception thrown when an assertion about an instant in time is not
 * satisfied.
 *
 * @author Carl Harris
 */
public class InstantAssertionException extends JWTAssertionFailedException {

  public InstantAssertionException(Instant now, Instant other,
      BiFunction<Instant, Instant, String> messageSupplier) {
    super(messageSupplier.apply(now, other));
  }

}

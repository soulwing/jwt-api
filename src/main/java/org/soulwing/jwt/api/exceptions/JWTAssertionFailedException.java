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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.soulwing.jwt.api.Assertions;

/**
 * An exception thrown by an {@link Assertions} when an assertion is not
 * satisfied.
 *
 * @author Carl Harris
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class JWTAssertionFailedException extends RuntimeException {

  public JWTAssertionFailedException(String message) {
    super(message);
  }

  public JWTAssertionFailedException(String message, Throwable cause) {
    super(message, cause);
  }

  public JWTAssertionFailedException(Throwable cause) {
    super(cause);
  }

  static String join(Object value, Object... values) {
    final StringBuilder sb = new StringBuilder();
    sb.append("`").append(value).append("`");
    if (values != null && values.length > 0) {
      sb.append(", ");
      sb.append(Arrays.stream(values)
          .map(s -> "`" + s + "`")
          .collect(Collectors.joining(", ")));
    }
    return sb.toString();
  }

  static String join(List<?> values) {
    return values.stream().map(Object::toString)
        .map(s -> "`" + s + "`")
        .collect(Collectors.joining(", "));
  }

}

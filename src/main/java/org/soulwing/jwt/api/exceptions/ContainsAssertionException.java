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

import java.util.List;

/**
 * An exception thrown when assertion about a multi-valued claim containing
 * a particular value is not satisfied.
 *
 * @author Carl Harris
 */
public class ContainsAssertionException extends JWTAssertionFailedException {

  public ContainsAssertionException(String name, List<?> actual, Object expected,
      Object... moreExpected) {
    super(message(name, actual, expected, moreExpected));
  }

  private static String message(String name, List<?> actual, Object expected,
      Object... moreExpected) {
    final StringBuilder sb = new StringBuilder();
    sb.append(name).append("=[").append(join(actual)).append("] ");
    if (moreExpected == null) {
      sb.append("does not contain `").append(expected).append("`");
    }
    else {
      sb.append("does not contain any of [")
          .append(join(expected, moreExpected)).append("]");
    }
    return sb.toString();
  }

}

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

/**
 * An exception thrown when a JWT provider encounters an error while performing
 * a JWT generation operation.
 *
 * @author Carl Harris
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class JWTGeneratorException extends JWTException {

  public JWTGeneratorException(String message) {
    super(message);
  }

  public JWTGeneratorException(String message, Throwable cause) {
    super(message, cause);
  }

  public JWTGeneratorException(Throwable cause) {
    super(cause);
  }

}

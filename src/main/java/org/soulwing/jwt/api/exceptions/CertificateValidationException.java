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
package org.soulwing.jwt.api.exceptions;

/**
 * An exception thrown by a {@link org.soulwing.jwt.api.PublicKeyLocator} if
 * the certificate to be used in validating a signature fails validation;
 * e.g. expired, revoked, untrusted, etc.
 *
 * @author Carl Harris
 */
public class CertificateValidationException extends JWTSignatureException {

  public CertificateValidationException(String message) {
    this(message, null);
  }

  public CertificateValidationException(String message, Throwable cause) {
    super(message, cause);
  }

}

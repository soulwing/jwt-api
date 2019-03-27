/*
 * File created on Mar 27, 2019
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

import java.time.Clock;

import org.soulwing.jwt.api.Assertions;
import org.soulwing.jwt.api.PublicKeyInfo;

/**
 * A {@link Assertions.Context} for Jose4j.
 *
 * @author Carl Harris
 */
class Jose4jAssertionContext implements Assertions.Context {

  private final Clock clock;
  private final PublicKeyInfo publicKeyInfo;

  public Jose4jAssertionContext(Clock clock, PublicKeyInfo publicKeyInfo) {
    this.clock = clock;
    this.publicKeyInfo = publicKeyInfo;
  }

  @Override
  public Clock getClock() {
    return clock;
  }

  @Override
  public PublicKeyInfo getPublicKeyInfo() {
    return publicKeyInfo;
  }

}

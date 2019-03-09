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
package org.soulwing.jwt.api;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

/**
 * A mock {@link Clock} for use in tests.
 *
 * @author Carl Harris
 */
@SuppressWarnings({ "WeakerAccess", "unused" })
public class MockClock extends Clock {

  private final Instant instant;

  /**
   * Creates a mock clock whose time is {@link Instant#EPOCH}.
   */
  public MockClock() {
    this(Instant.EPOCH);
  }

  /**
   * Creates a mock clock whose time is the given instant.
   */
  public MockClock(Instant instant) {
    this.instant = instant;
  }

  @Override
  public ZoneId getZone() {
    throw new UnsupportedOperationException();
  }

  @Override
  public Clock withZone(ZoneId zone) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Instant instant() {
    return instant;
  }

}

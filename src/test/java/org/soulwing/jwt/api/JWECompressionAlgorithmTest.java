/*
 * File created on Mar 10, 2019
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import org.junit.Test;

/**
 * Unit tests for {@link JWE.CompressionAlgorithm}.
 *
 * @author Carl Harris
 */
public class JWECompressionAlgorithmTest {

  @Test
  public void testOfToken() throws Exception {
    for (JWE.CompressionAlgorithm algorithm :
        JWE.CompressionAlgorithm.values()) {
      assertThat(JWE.CompressionAlgorithm.of(algorithm.toToken()),
          is(sameInstance(algorithm)));
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testOfTokenWhenUnrecognized() throws Exception {
    JWE.CompressionAlgorithm.of("undefined");
  }

}
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

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.security.Key;

import org.junit.Test;

/**
 * Unit tests for {@link KeyProvider.Tuple}.
 *
 * @author Carl Harris
 */
public class KeyProviderTupleTest {

  private static final Key KEY = KeyUtil.newAesKey(128);
  private static final String ID = "id";

  @Test(expected = NullPointerException.class)
  public void testWhenKeyIsNull() throws Exception {
    new KeyProvider.Tuple(null, null);
  }

  @Test
  public void testWhenIdIsNull() throws Exception {
    final KeyProvider.Tuple tuple = new KeyProvider.Tuple(null, KEY);
    assertThat(tuple.getId(), is(nullValue()));
    assertThat(tuple.getKey(), is(not(nullValue())));
  }

  @Test
  public void testAllProperties() throws Exception {
    final KeyProvider.Tuple tuple = new KeyProvider.Tuple(ID, KEY);
    assertThat(tuple.getId(), is(not(nullValue())));
    assertThat(tuple.getKey(), is(not(nullValue())));
  }

}
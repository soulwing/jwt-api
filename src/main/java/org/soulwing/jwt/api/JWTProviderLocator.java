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

import java.util.Iterator;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.soulwing.jwt.api.exceptions.JWTException;

/**
 * A locator for a {@link JWTProvider}.
 *
 * @author Carl Harris
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class JWTProviderLocator {

  private static final Lock lock = new ReentrantLock();
  
  private static volatile JWTProvider provider;

  /**
   * Gets the default JWT provider using the current thread's context class
   * loader (lazy loading as necessary).
   * @return provider
   * @throws JWTException if no provider can be located
   */
  public static JWTProvider getProvider() throws JWTException {
    if (provider == null) {
      lock.lock();
      try {
        if (provider == null) {
          provider = newProvider(
              Optional.ofNullable(Thread.currentThread().getContextClassLoader())
                  .orElse(JWTProviderLocator.class.getClassLoader()));
        }
      }
      finally {
        lock.unlock();
      }
    }
    return provider;

  }

  /**
   * Gets a JWT provider.
   * @param classLoader to use for service loading
   * @return provider
   * @throws JWTException if no provider can be located
   */
  public static JWTProvider newProvider(ClassLoader classLoader)
      throws JWTException {
    final Iterator<JWTProvider> i = ServiceLoader.load(
        JWTProvider.class, classLoader).iterator();
    if (!i.hasNext()) {
      throw new JWTException("cannot locate a provider");
    }
    return i.next();
  }

}

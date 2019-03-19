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

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Utility methods for cryptographic keys.
 *
 * @author Carl Harris
 */
public class KeyUtil {

  private static final SecureRandom secureRandom = new SecureRandom();

  private static final KeyPairGenerator rsaKeyGenerator;

  static {
    try {
      rsaKeyGenerator = KeyPairGenerator.getInstance("RSA");
      rsaKeyGenerator.initialize(2048);
    }
    catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

  /**
   * Generates a new AES key of the specified bit length.
   * @param bitLength bit length (must be a multiple of 8)
   * @return key
   */
  public static Key newAesKey(int bitLength) {
    byte[] secret = new byte[bitLength / Byte.SIZE];
    secureRandom.nextBytes(secret);
    return new SecretKeySpec(secret, "AES");
  }

  /**
   * Generates a new RSA key pair
   * @return key pair
   */
  public static KeyPair newRsaKeyPair() {
    return rsaKeyGenerator.generateKeyPair();
  }

}

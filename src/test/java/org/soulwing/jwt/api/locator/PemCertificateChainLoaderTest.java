/*
 * File created on Mar 18, 2019
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
package org.soulwing.jwt.api.locator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Random;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.soulwing.jwt.api.CertUtil;
import org.soulwing.jwt.api.exceptions.CertificateException;

/**
 * Unit tests for {@link PemCertificateChainLoader}.
 *
 * @author Carl Harris
 */
public class PemCertificateChainLoaderTest {

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  private Random random = new Random();

  private Path path;

  @Before
  public void setUp() throws Exception {
    path = Files.createTempFile("certs", ".pem");
  }

  @After
  public void tearDown() throws Exception {
    if (path != null) {
      Files.deleteIfExists(path);
    }
  }

  @Test
  public void testLoadWhenUnsecureHttpUri() throws Exception {
    expectedException.expect(CertificateException.class);
    expectedException.expectMessage("not secure");
    PemCertificateChainLoader.getDefaultInstance().load(
        URI.create("http://localhost/test"));
  }

  @Test
  public void testLoadChainFromFileUri() throws Exception {
    try (final OutputStream outputStream =
        new FileOutputStream(path.toFile())) {
      final List<X509Certificate> chain =
          CertUtil.createChain(3, Duration.ZERO, outputStream);
      outputStream.flush();
      final List<X509Certificate> actual =
          PemCertificateChainLoader.getDefaultInstance().load(path.toUri());
      assertThat(actual, is(equalTo(chain)));
    }
  }

  @Test
  public void testLoadExcessivelyLongChain() throws Exception {
    final X509Certificate certificate =
        CertUtil.createChain(1, Duration.ZERO).get(0);
    try (final PemWriter writer = new PemWriter(
        new OutputStreamWriter(new FileOutputStream(path.toFile()),
            StandardCharsets.US_ASCII))) {
      int count = PemCertificateChainLoader.MAX_CHAIN_LENGTH + 1;
      while (count-- > 0) {
        writer.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
      }
    }
    assertThat(
        PemCertificateChainLoader.getDefaultInstance().load(path.toUri()).size(),
        is(equalTo(10)));
  }

}
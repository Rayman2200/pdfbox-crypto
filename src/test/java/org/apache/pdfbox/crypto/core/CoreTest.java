/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.pdfbox.crypto.core;

import static org.apache.pdfbox.crypto.core.CoreHelper.requireNonNullOrEmpty;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Random;

import org.apache.pdfbox.crypto.sign.KeyStoreHelper;
import org.apache.pdfbox.pdfwriter.COSFilterInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class CoreTest
{

  protected static KeyStore keyStore;

  @BeforeClass
  public static void prepareTestClass() throws Exception
  {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
    {
      Security.addProvider(new BouncyCastleProvider());
    }
    keyStore = KeyStoreHelper.generateKeyStore();
  }

  @Test
  public void testKeyProviderEquality() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
  {
    KeyProvider kp1 = KeyProvider.getInstance(keyStore);
    KeyProvider kp2 = KeyProvider.getInstance(keyStore);
    assertEquals("Both keyprovider should be equal", kp1, kp2);
  }

  @Test
  public void testRangeInputStream() throws IOException
  {
    byte[] byteArray = new byte[100];
    new Random().nextBytes(byteArray);

    int[] byteRange = new int[] { 0, 20, 80, 20 };

    byte[] full = Arrays.copyOfRange(byteArray, 80, byteArray.length);

//    int a =byteRange[0] + byteRange[1];
//    int b2 = byteRange[2] + byteRange[3];
//    System.out.println(a);
//    System.out.println(b2);
    
    byte[] part1_arrayCopy = Arrays.copyOfRange(byteArray, byteRange[0], byteRange[0] + byteRange[1]);
    byte[] part2_arrayCopy = Arrays.copyOfRange(byteArray, byteRange[2], byteRange[2] + byteRange[3]);

    COSFilterInputStream cosFilterInputStream = new COSFilterInputStream(byteArray, byteRange);
    byte[] byteArray2 = cosFilterInputStream.toByteArray();
    
    assertEquals(byteRange[3], part1_arrayCopy.length);
    
  }

  @Test
  public void testCertificateHelper() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
  {
    KeyProvider kp1 = KeyProvider.getInstance(keyStore);
    CertificateHelper certHelper = new CertificateHelper(requireNonNullOrEmpty(kp1.getCertificateChain())[0]);
    System.out.println(certHelper);
  }

}

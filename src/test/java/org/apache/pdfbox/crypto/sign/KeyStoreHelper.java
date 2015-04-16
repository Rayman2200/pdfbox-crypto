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
package org.apache.pdfbox.crypto.sign;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.Random;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.BeforeClass;
import org.junit.Test;

public class KeyStoreHelper
{
  protected static KeyStore keystore;

  protected final static String ALIAS = "mykey";

  /*
   * Original keystore generator example from 
   * http://stackoverflow.com/q/13207378/3928975
   * 
   * Stronger algorithms are limited per default in oracle java. To override this limit, you need to install 
   * "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy" for your specific java version
   * 
   * Java 6: http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html
   * Java 7: http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
   * Java 8: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
   * 
   */
  public static KeyStore generateKeyStore() throws Exception
  {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(1024);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    PublicKey publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();
    Certificate trustCert = createCertificate("CN=CA", "CN=CA", publicKey, privateKey);
    Certificate[] outChain = { createCertificate("CN=Client", "CN=CA", publicKey, privateKey), trustCert };

    KeyStore keystore = KeyStore.getInstance("PKCS12","BC");
    keystore.load(null, "secret".toCharArray());
    keystore.setKeyEntry(ALIAS, privateKey, "".toCharArray(), outChain);
    return keystore;
  }

  public static X509Certificate createCertificate(String dn, String issuer, PublicKey publicKey, PrivateKey privateKey) throws Exception
  {
    X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
    certGenerator.setSerialNumber(BigInteger.valueOf(Math.abs(new Random().nextLong())));
    certGenerator.setIssuerDN(new X509Name(dn));
    certGenerator.setSubjectDN(new X509Name(dn));
    certGenerator.setIssuerDN(new X509Name(issuer));
    certGenerator.setNotBefore(Calendar.getInstance().getTime());
    certGenerator.setNotAfter(Calendar.getInstance().getTime());
    certGenerator.setPublicKey(publicKey);
    certGenerator.setSignatureAlgorithm("SHA1withRSA");
    X509Certificate certificate = certGenerator.generate(privateKey, BouncyCastleProvider.PROVIDER_NAME);
    return certificate;
  }

  /*
   * UNIT TESTS
   */

  @BeforeClass
  public static void prepareTestClass() throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());
    keystore = KeyStoreHelper.generateKeyStore();
  }

  @Test
  public void testKeystore() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
  {
    for (Enumeration<String> aliases = keystore.aliases(); aliases.hasMoreElements();)
    {
      assertEquals("Alias does not have the default name", KeyStoreHelper.ALIAS, aliases.nextElement());
    }

    assertNotNull("At least one key should be returned", keystore.getKey(ALIAS, "".toCharArray()));
  }
}

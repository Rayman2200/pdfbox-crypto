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

import static org.apache.pdfbox.crypto.core.CoreHelper.closeStream;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;

import org.apache.pdfbox.crypto.PDCrypto;
import org.apache.pdfbox.crypto.core.KeyProvider;
import org.apache.pdfbox.crypto.core.SignatureProvider;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class SignTest
{

  protected static KeyStore keystore;

  @BeforeClass
  public static void prepareTestClass() throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());
    keystore = KeyStoreHelper.generateKeyStore();
  }

  @Before
  public void prepareTest()
  {

  }

  @Test
  public void testSimpleSignature() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, IOException,
      IllegalArgumentException, COSVisitorException, SignatureException
  {
    KeyProvider keyProvider = KeyProvider.getInstance(keystore);
    SignatureProvider signatureProvider = SignatureProvider.getInstance("SHA256withRSA");
    SignatureOptions options;
    InputStream stream = SignTest.class.getResourceAsStream("/unsignedPDF/LibreOffice_4_3_Sample.pdf");

    File outputDir = new File("target/test/output/");
    outputDir.mkdirs();

    PDCrypto cryptoEngine = null;
    try
    {
      cryptoEngine = PDCrypto.load(stream);
      cryptoEngine.createSignatureBuilder().
                   setKeyProvider(keyProvider).
                   setSignatureProvider(signatureProvider).
                   setSigernName("SignerName").
                   sign(new File(outputDir, "Sample_signed.pdf"));;
    }
    finally
    {
      closeStream(stream);
    }

  }
}

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
package org.apache.pdfbox.crypto.verify;

import static org.apache.pdfbox.crypto.core.CoreHelper.closeStream;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;

import org.apache.pdfbox.crypto.PDCrypto;
import org.apache.pdfbox.crypto.exceptions.ReportInitializationException;
import org.apache.pdfbox.crypto.sign.SignTest;
import org.apache.pdfbox.crypto.vr.SimpleReport;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.schema.vr.simple_report.SignatureType;
import org.apache.pdfbox.schema.vr.simple_report.Signatures;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class VerifyTest
{

  @BeforeClass
  public static void prepareTestClass() throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void testPAdES_B_Signature() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, IOException,
      IllegalArgumentException, COSVisitorException, SignatureException, ReportInitializationException
  {

    InputStream stream = SignTest.class.getResourceAsStream("/signedPDF/LibreOffice_4_3_Sample_PAdES_B_signed.pdf");

    PDCrypto cryptoEngine = null;
    try
    {
      cryptoEngine = PDCrypto.load(stream);
      SimpleReport vr = (SimpleReport) cryptoEngine.createVerificationBuilder().setReportType(SimpleReport.class).createVerificationReport();
      System.out.println(vr);
      Signatures signatures = vr.getDocument().getSignatures();
      for (SignatureType signature : signatures.getSignature())
      {
        assertTrue("Signatures should be valid", signature.isMathematicalyValid());
      }
    }
    finally
    {
      closeStream(stream);
    }

  }
}

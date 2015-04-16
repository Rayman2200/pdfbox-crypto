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
package org.apache.pdfbox.crypto;

import static org.apache.pdfbox.crypto.core.CoreHelper.copy;
import static org.apache.pdfbox.crypto.core.CoreHelper.requireNonNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * Crypto engine for pdf signature creation and verification. It builds up on several builders that prepare the
 * pdf document and sign it.
 * 
 * @author Thomas Chojecki
 */
public class PDCrypto
{
  protected File pdfFile;

  protected PDDocument doc;

  protected File tempFolder = new File(System.getProperty("java.io.tmpdir"));

  private PDCrypto()
  {}

  /*
   * Load document
   */

  public static PDCrypto load(File pdf)
  {
    requireNonNull(pdf);

    PDCrypto pdCrypto = new PDCrypto();
    pdCrypto.pdfFile = pdf;

    return pdCrypto;
  }

  public static PDCrypto load(InputStream pdf) throws IOException
  {
    requireNonNull(pdf);
    PDCrypto pdCrypto = new PDCrypto();
    pdCrypto.pdfFile = File.createTempFile("PDF", ".pdf");

    copy(pdf, new FileOutputStream(pdCrypto.pdfFile));

    return pdCrypto;
  }

  public static PDCrypto load(PDDocument pdf)
  {
    requireNonNull(pdf);
    throw new UnsupportedOperationException("Not yet implemented.");
  }

  /*
   * Builder
   */

  public SignatureBuilder createSignatureBuilder()
  {
    return new SignatureBuilder(this);
  }

  public VerificationBuilder createVerificationBuilder()
  {
    return new VerificationBuilder(this);
  }

  /*
   * Global setter
   */

  public void setTempFolder(File tempFolder)
  {
    this.tempFolder = tempFolder;
  }

  /*
   * Getter / Setter
   */
}

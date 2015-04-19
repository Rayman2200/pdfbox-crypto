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

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.apache.pdfbox.pdfwriter.COSFilterInputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

/**
 * @author Thomas Chojecki
 */
public class VerificationReportBuilder
{

  private final PDCrypto crypto;

  private final PDDocument doc;

  protected VerificationReportBuilder(PDCrypto crypto)
  {
    this.crypto = crypto;
    doc = crypto.doc;
  }

  public static VerificationReportBuilder getInstance(PDCrypto crypto)
  {
    return new VerificationReportBuilder(crypto);
  }

  public String getFilename()
  {
    return crypto.pdfFile.getName();
  }

  public long getFileSize()
  {
    return crypto.pdfFile.length();
  }

  public List<PDSignature> getSignatures() throws IOException
  {
    return doc.getSignatureDictionaries();
  }

  public InputStream getContentForSignature(PDSignature signature) throws IOException
  {
    BufferedInputStream is = new BufferedInputStream(new FileInputStream(crypto.pdfFile));
    return new COSFilterInputStream(is, signature.getByteRange());
  }

  public byte[] getCMSSignature(PDSignature signature) throws IOException
  {
    BufferedInputStream is = new BufferedInputStream(new FileInputStream(crypto.pdfFile));
    return signature.getContents(is);
  }

}

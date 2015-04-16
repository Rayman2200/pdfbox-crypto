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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Calendar;

import org.apache.pdfbox.crypto.bc.BC14x_SignatureInterface;
import org.apache.pdfbox.crypto.core.KeyProvider;
import org.apache.pdfbox.crypto.core.SignatureProvider;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.io.RandomAccessFile;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

public class SignatureBuilder
{

  protected PDCrypto crypto;

  private KeyProvider keyProvider;

  private SignatureProvider signatureProvider;

  private String signerName;

  private String signerLocation;

  private String signerReason;

  private SignatureOptions options;

  private Calendar cal;

  SignatureBuilder(PDCrypto crypto)
  {
    this.crypto = crypto;
  }

  public SignatureBuilder setKeyProvider(KeyProvider keyProvider)
  {
    this.keyProvider = keyProvider;
    return this;
  }

  public SignatureBuilder setSignatureProvider(SignatureProvider signatureProvider)
  {
    this.signatureProvider = signatureProvider;
    return this;
  }

  public SignatureBuilder setSigernName(String name)
  {
    this.signerName = name;
    return this;
  }

  public SignatureBuilder setSigernLocation(String location)
  {
    this.signerLocation = location;
    return this;
  }

  public SignatureBuilder setSigernReason(String reason)
  {
    this.signerReason = reason;
    return this;
  }

  public SignatureBuilder setSignatureTime(Calendar cal)
  {
    this.cal = cal;
    return this;
  }

  public SignatureBuilder setSignatureOptions(SignatureOptions options)
  {
    this.options = options;
    return this;
  }

  public void sign(File outputDocument) throws IllegalArgumentException, COSVisitorException, IOException, SignatureException
  {
    SignatureInterface sigInterface = new BC14x_SignatureInterface(keyProvider, signatureProvider);

    byte[] buffer = new byte[8 * 1024];
    if (!crypto.pdfFile.exists())
    {
      throw new IllegalArgumentException("Document for signing does not exist");
    }

    // creating output document and prepare the IO streams.
    FileInputStream fis = new FileInputStream(crypto.pdfFile);
    FileOutputStream fos = new FileOutputStream(outputDocument);

    int c;
    while ((c = fis.read(buffer)) != -1)
    {
      fos.write(buffer, 0, c);
    }
    fis.close();
    fis = new FileInputStream(outputDocument);

    File scratchFile = File.createTempFile("pdfbox_scratch", ".bin", crypto.tempFolder);
    RandomAccessFile randomAccessFile = new RandomAccessFile(scratchFile, "rw");

    try
    {
      // load document
      PDDocument doc = PDDocument.load(crypto.pdfFile, randomAccessFile);

      // create signature dictionary
      PDSignature signature = new PDSignature();
      signature.setFilter(signatureProvider.getFilter());
      signature.setSubFilter(signatureProvider.getSubfilter());
      signature.setName(signerName);
      signature.setLocation(signerLocation);
      signature.setReason(signerReason);

      // the signing date, needed for valid signature
      signature.setSignDate(cal == null ? Calendar.getInstance() : cal);

      // register signature dictionary and sign interface
      if (options == null)
      {
        doc.addSignature(signature, sigInterface);
      }
      else
      {
        doc.addSignature(signature, sigInterface, options);
      }

      // write incremental (only for signing purpose)
      doc.saveIncremental(fis, fos);
    }
    finally
    {
      if (randomAccessFile != null)
      {
        randomAccessFile.close();
      }
      if (scratchFile != null && scratchFile.exists() && !scratchFile.delete())
      {
        scratchFile.deleteOnExit();
      }
    }
  }

}

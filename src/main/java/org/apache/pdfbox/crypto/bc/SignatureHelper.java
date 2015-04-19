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
package org.apache.pdfbox.crypto.bc;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

/**
 * @author Thomas Chojecki
 */
public class SignatureHelper
{

  private final static Log LOG = LogFactory.getLog(SignatureHelper.class);

  private final PDSignature signature;
  protected final CMSSignedData signedData;
  protected final SignerInformation signer;
  protected final CertStore cs;
  protected final X509Certificate signerCertificate;
  protected final ArrayList<Certificate> certificateChain;

  public SignatureHelper(PDSignature signature, InputStream in) throws CMSException, NoSuchAlgorithmException, NoSuchProviderException, CertStoreException, FileNotFoundException
  {
    this.signature = signature;
    
    COSString cosString = (COSString) signature.getDictionary().getDictionaryObject(COSName.CONTENTS);
    byte[] signatureBytes = cosString.getBytes();

    signedData = new CMSSignedData(new CMSProcessableInputStream(in),signatureBytes);
    signer = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
    cs = signedData.getCertificatesAndCRLs("Collection", "BC");
    Iterator iter = cs.getCertificates(signer.getSID()).iterator();

    // grab the first certificate (signer certificate)
    signerCertificate = (X509Certificate) iter.next();

    certificateChain = new ArrayList<Certificate>();
    // iterate through the rest of the store
    while (iter.hasNext())
    {
      certificateChain.add((Certificate) iter.next());
    }
  }

  public Calendar getSigningTime()
  {
    return signature.getSignDate();
  }

  public Certificate getSignerCertificate()
  {
    return signerCertificate;
  }

  public Certificate[] getCertificateChain()
  {
    return certificateChain.toArray(new Certificate[0]);
  }

  public boolean isMathematicalyValid()
  {
    try
    {
      return signer.verify(signerCertificate, "BC");
    }
    catch (NoSuchAlgorithmException e)
    {
      LOG.warn(e.getMessage());
    }
    catch (NoSuchProviderException e)
    {
      LOG.warn(e.getMessage());
    }
    catch (CMSException e)
    {
      LOG.warn(e.getMessage());
    }
    catch (CertificateExpiredException e)
    {
      LOG.warn(e.getMessage());
    }
    catch (CertificateNotYetValidException e)
    {
      LOG.warn(e.getMessage());
    }
    return false;
  }

  @Override
  public String toString()
  {
    return super.toString();
  }
}

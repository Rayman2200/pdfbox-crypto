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

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.crypto.bc.AttributeContainer;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSSignedGenerator;

/**
 * The provides hold all necessary elements that are needed for signature creation.
 * 
 * It is based on the lowest level of signature creation and will complaint to the ISO 32000-1:2008 spezification.
 * 
 * @author Thomas Chojecki
 */
public class SignatureProvider
{
  protected final static String DEFAULT_KEY_CRYPTO_PROVIDER = "BC"; // BouncyCastleProvider.PROVIDER_NAME

  /** Provider that should be used for computing cryptographic operations like digesting */
  protected String crypoProvider;
  protected String signatureAlgorithm;
  protected String digestAlgorithm;
  protected COSName filter;
  protected COSName subfilter;
  protected AttributeContainer attributeContainer;

  protected SignatureProvider()
  {
    // Set some default values
    setDigestAlgorithm(CMSSignedGenerator.DIGEST_SHA256);
    setCrypoProvider(DEFAULT_KEY_CRYPTO_PROVIDER);
    setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
    setSubfilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
    setAttributeContainer(new AttributeContainer(this));
  }

  public static SignatureProvider getInstance()
  {
    return new SignatureProvider();
  }

  public String getCrypoProvider()
  {
    return crypoProvider;
  }

  public void setCrypoProvider(String crypoProvider)
  {
    this.crypoProvider = crypoProvider;
  }

  public String getSignatureAlgorithm()
  {
    return signatureAlgorithm;
  }

  public void setSignatureAlgorithm(String signatureAlgorithm)
  {
    this.signatureAlgorithm = signatureAlgorithm;
  }

  public String getDigestAlgorithm()
  {
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(String digestAlgorithm)
  {
    this.digestAlgorithm = digestAlgorithm;
  }

  public AttributeContainer getAttributeContainer()
  {
    return attributeContainer;
  }

  public void setAttributeContainer(AttributeContainer attributeContainer)
  {
    this.attributeContainer = attributeContainer;
  }

  public COSName getFilter()
  {
    return filter;
  }

  public void setFilter(COSName filter)
  {
    this.filter = filter;
  }

  public COSName getSubfilter()
  {
    return subfilter;
  }

  public void setSubfilter(COSName subfilter)
  {
    this.subfilter = subfilter;
  }

}

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

/**
 * The provides hold all necessary elements that are needed for signature verification.
 * It is based on the lowest level of signature creation and will complaint to the ISO 32000-1:2008 spezification.
 * 
 * @author Thomas Chojecki
 */
public class VerificationProvider
{
  protected final static String DEFAULT_KEY_CRYPTO_PROVIDER = "BC"; // BouncyCastleProvider.PROVIDER_NAME

  protected String crypoProvider;

  protected VerificationProvider()
  {
    // Set some default values
    setCrypoProvider(DEFAULT_KEY_CRYPTO_PROVIDER);
  }

  public static VerificationProvider getInstance()
  {
    return new VerificationProvider();
  }

  public String getCrypoProvider()
  {
    return crypoProvider;
  }

  public void setCrypoProvider(String crypoProvider)
  {
    this.crypoProvider = crypoProvider;
  }
}

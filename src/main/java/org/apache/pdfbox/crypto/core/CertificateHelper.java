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

import static org.apache.pdfbox.crypto.core.CoreHelper.requireNonNull;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * The helper parse and extract common informations from a certificate and provide them the verification engine.
 * 
 * @author Thomas Chojecki
 */
public class CertificateHelper
{
  private final X509Certificate cert;

  private Principal subjectDN;

  private Principal issuerDN;

  public CertificateHelper(Certificate certificate)
  {
    requireNonNull(certificate);
    if (certificate instanceof X509Certificate)
    {
      this.cert = (X509Certificate) certificate;
      subjectDN = cert.getSubjectDN();
      issuerDN = cert.getIssuerDN();
    }
    else
    {
      throw new IllegalArgumentException(certificate.getClass().getSimpleName() + " is not supported. Try " + X509Certificate.class.getName());
    }
  }

  @Override
  public String toString()
  {
    return cert.toString();
  }
}

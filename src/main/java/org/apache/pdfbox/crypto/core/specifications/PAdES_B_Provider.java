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
package org.apache.pdfbox.crypto.core.specifications;

import java.security.cert.Certificate;

import org.apache.pdfbox.crypto.core.KeyProvider;
import org.apache.pdfbox.crypto.core.SignatureProvider;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

/**
 * ETSI PAdES Baseline Profile - Conformance Level B
 * 
 * http://www.etsi.org/deliver/etsi_ts/103100_103199/103172/02.01.01_60/ts_103172v020101p.pdf
 * 
 * The Conformance Level B signature describe the lowest signature level from the PAdES Baseline Profile.
 * 
 * @author Thomas Chojecki
 */
public class PAdES_B_Provider extends SignatureProvider
{
  protected KeyProvider keyProvider;
  
  public PAdES_B_Provider(KeyProvider keyProvider)
  {
    setSubfilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
    Certificate[] certificateChain = keyProvider.getCertificateChain();
    attributeContainer.setSigningCertificate(certificateChain);
  }
  
  public static PAdES_B_Provider getInstance(KeyProvider keyProvider)
  {
    return new PAdES_B_Provider(keyProvider);
  }

  
}

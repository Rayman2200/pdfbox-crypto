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

import java.io.InputStream;
import java.util.HashMap;

import org.apache.pdfbox.pdfwriter.COSFilterInputStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSProcessable;

/**
 * @author Thomas Chojecki
 */
public class CryptoHelper
{
  public final static HashMap<DERObjectIdentifier, AlgorithmIdentifier> algorithms = new HashMap<DERObjectIdentifier, AlgorithmIdentifier>();

  /**
   * Caches the AlgorithmIdentifier for ObjectIdentifier
   * 
   * @param oid is the requesting ObjectIdentifier
   * @return an AlgorithmIdentfier for an ObjectIndentifier
   */
  public static AlgorithmIdentifier getAlgorithmIdentifierForOID(DERObjectIdentifier oid)
  {
    AlgorithmIdentifier algorithmIdentifier = algorithms.get(oid);
    if (algorithmIdentifier == null)
    {
      algorithmIdentifier = new AlgorithmIdentifier(oid);
      algorithms.put(oid, algorithmIdentifier);
    }
    return algorithmIdentifier;
  }

  public static CMSProcessable getContent(PDSignature signature, InputStream input)
  {
    return new CMSProcessableInputStream(new COSFilterInputStream(input, signature.getByteRange()));
  }
}

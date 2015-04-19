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

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.apache.pdfbox.crypto.core.KeyProvider;
import org.apache.pdfbox.crypto.core.SignatureProvider;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A BouncyCastle 1.4x implementation of the SignatureInterface. It is guaranteed compatible up to BouncyCastle 1.46.
 * Higher versions will get an own implementation.
 * 
 * @author Thomas Chojecki
 */
public class BC14x_SignatureInterface implements SignatureInterface
{
  private final KeyProvider keyProvider;

  private final SignatureProvider signatureProvider;

  protected static String cryptoProvider = BouncyCastleProvider.PROVIDER_NAME;

  public BC14x_SignatureInterface(KeyProvider keyProvider, SignatureProvider signatureProvider)
  {
    this.keyProvider = keyProvider;
    this.signatureProvider = signatureProvider;
  }

  public byte[] sign(InputStream content) throws SignatureException, IOException
  {
    CMSProcessableInputStream input = new CMSProcessableInputStream(content);
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    List<Certificate> certChainAsList = Arrays.asList(keyProvider.getCertificateChain());

    CertStore certStore = null;
    try
    {
      certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certChainAsList), cryptoProvider);
      gen.addSigner(keyProvider.getPrivKey(), 
          (X509Certificate) keyProvider.getCertificateChain()[0], 
          signatureProvider.getDigestAlgorithm(),
          signatureProvider.getAttributeContainer().getSignedAttributes(), 
          signatureProvider.getAttributeContainer().getUnsignedAttributes());
      gen.addCertificatesAndCRLs(certStore);
      
      CMSSignedData signedData = gen.generate(input, false, keyProvider.getKeyCrypoProvider());
      return signedData.getEncoded();
    }
    catch (InvalidAlgorithmParameterException e)
    {
      throw new SignatureException(e);
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new SignatureException(e);
    }
    catch (NoSuchProviderException e)
    {
      throw new SignatureException(e);
    }
    catch (CertStoreException e)
    {
      throw new SignatureException(e);
    }
    catch (CMSException e)
    {
      throw new SignatureException(e);
    }
  }
}

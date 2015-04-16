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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Objects;

/**
 * The provides hold all necessary elements like the private key, certificates etc. for the sign engine.
 * 
 * @author Thomas Chojecki
 */
public class KeyProvider
{

  protected final static String DEFAULT_KEY_CRYPTO_PROVIDER = "BC"; // BouncyCastleProvider.PROVIDER_NAME

  protected PrivateKey privKey;
  protected Certificate[] certificateChain;
  protected String keyCrypoProvider;

  protected KeyProvider()
  {}

  public static KeyProvider getInstance(KeyStore keyStore) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
  {
    for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();)
    {
      return getInstance(keyStore, aliases.nextElement(), new char[0], null);
    }

    throw new IllegalArgumentException("No alias found in keystore");
  }

  public static KeyProvider getInstance(KeyStore keyStore, String alias, char[] privateKeyPin, String keyCryptoProvider)
      throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
  {
    return getInstance((PrivateKey) keyStore.getKey(alias, privateKeyPin), keyStore.getCertificateChain(alias), keyCryptoProvider);
  }

  public static KeyProvider getInstance(PrivateKey privKey, Certificate[] certificateChain, final String keyCryptoProvider)
  {
    requireNonNull(certificateChain);
    requireNonNull(privKey);

    KeyProvider kp = new KeyProvider();
    kp.setCertificateChain(certificateChain);
    kp.setPrivKey(privKey);
    kp.setKeyCrypoProvider(keyCryptoProvider == null ? DEFAULT_KEY_CRYPTO_PROVIDER : keyCryptoProvider);

    return kp;
  }

  public PrivateKey getPrivKey()
  {
    return privKey;
  }

  protected void setPrivKey(PrivateKey privKey)
  {
    this.privKey = privKey;
  }

  public Certificate[] getCertificateChain()
  {
    return certificateChain;
  }

  protected void setCertificateChain(Certificate[] certificateChain)
  {
    this.certificateChain = certificateChain;
  }

  public String getKeyCrypoProvider()
  {
    return keyCrypoProvider;
  }

  protected void setKeyCrypoProvider(String keyCrypoProvider)
  {
    this.keyCrypoProvider = keyCrypoProvider;
  }

  @Override
  public int hashCode()
  {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(certificateChain);
    result = prime * result + ((keyCrypoProvider == null) ? 0 : keyCrypoProvider.hashCode());
    result = prime * result + ((privKey == null) ? 0 : privKey.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }
    if (obj == null)
    {
      return false;
    }
    if (getClass() != obj.getClass())
    {
      return false;
    }

    KeyProvider other = (KeyProvider) obj;
    if (!Arrays.equals(certificateChain, other.certificateChain))
    {
      return false;
    }
    if (keyCrypoProvider == null)
    {
      if (other.keyCrypoProvider != null)
      {
        return false;
      }
    }
    else if (!keyCrypoProvider.equals(other.keyCrypoProvider))
    {
      return false;
    }
    if (privKey == null)
    {
      if (other.privKey != null)
      {
        return false;
      }
    }
    else if (!Arrays.equals(privKey.getEncoded(), other.privKey.getEncoded()))
    {
      return false;
    }
    return true;
  }

}

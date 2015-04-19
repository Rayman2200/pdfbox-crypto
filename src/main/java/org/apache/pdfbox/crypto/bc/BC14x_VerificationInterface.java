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

import org.apache.pdfbox.crypto.PDCrypto;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A BouncyCastle 1.4x implementation of the SignatureInterface. It is guaranteed compatible up to BouncyCastle 1.46.
 * Higher versions will get an own implementation.
 * 
 * @author Thomas Chojecki
 */
public class BC14x_VerificationInterface
{
  protected static String cryptoProvider = BouncyCastleProvider.PROVIDER_NAME;

  private PDCrypto crypto;
  
  
  public BC14x_VerificationInterface(PDCrypto crypto)
  {
    this.crypto = crypto;
  }

  
}

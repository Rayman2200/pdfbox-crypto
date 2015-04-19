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
 * <p>
 * The interface bundle all needed interfaces and abstract classes so the crypto engine can be replaced at any time. It
 * help supporting a wide range crypto libraries and different versions of them.
 * </p>
 * <p>
 * E.g. BouncyCastle do heavy interface changes, so newer versions can break the implementation, so we try to support
 * one older version for the pdfbox 1.8.x and a newer one for pdfbox 2.x.
 * </p>
 * <p>
 * Other crypto libraries can also be provided through this interface but need to be implemented.
 * </p>
 * 
 * @author Thomas Chojecki
 */
public interface CryptoEngine
{
  // TODO
}

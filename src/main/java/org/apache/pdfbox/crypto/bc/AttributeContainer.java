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

import static org.apache.pdfbox.crypto.bc.CryptoHelper.getAlgorithmIdentifierForOID;
import static org.apache.pdfbox.crypto.core.CoreHelper.requireNonNull;
import static org.apache.pdfbox.crypto.core.CoreHelper.requireNonNullOrEmpty;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Map;

import org.apache.pdfbox.crypto.core.SignatureProvider;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;

/**
 * Provide a central point for configuring the cms signed and unsigned attributes. Uses BouncyCastle as backend.
 * 
 * @author Thomas Chojecki
 */
public class AttributeContainer
{

  private Hashtable<DERObjectIdentifier, Attribute> signedAttributes;

  private Hashtable<DERObjectIdentifier, Attribute> unsignedAttributes;

  private SignatureProvider signatureProvider;

  public AttributeContainer()
  {
    signedAttributes = new Hashtable<DERObjectIdentifier, Attribute>();
    unsignedAttributes = new Hashtable<DERObjectIdentifier, Attribute>();
  }

  public AttributeContainer(SignatureProvider signatureProvider)
  {
    this();
    this.signatureProvider = signatureProvider;
  }

  @SuppressWarnings({ "rawtypes", "unchecked" })
  public CMSAttributeTableGenerator getSignedAttributes()
  {
    return new DefaultSignedAttributeTableGenerator()
    {

      @Override
      protected Hashtable createStandardAttributeTable(Map parameters)
      {
        // create a hashtable with some default attributes
        Hashtable tmp = super.createStandardAttributeTable(parameters);

        // remove the signing time from cms, it shall be set as M Entry inside the pdf structure.
        tmp.remove(CMSAttributes.signingTime);

        // add all our attributes to the hashtable
        tmp.putAll(signedAttributes);
        return tmp;
      }
    };
  }

  @SuppressWarnings("rawtypes")
  public CMSAttributeTableGenerator getUnsignedAttributes()
  {
    if ((unsignedAttributes.size() > 0))
    {
      return new CMSAttributeTableGenerator()
      {
        public AttributeTable getAttributes(Map parameters) throws CMSAttributeTableGenerationException
        {
          return new AttributeTable(unsignedAttributes);
        }
      };
    }
    return null;
  }

  public void setSignedAttributes(Hashtable<DERObjectIdentifier, Attribute> signedAttributes)
  {
    this.signedAttributes = signedAttributes;
  }

  public void setUnsignedAttributes(Hashtable<DERObjectIdentifier, Attribute> unsignedAttributes)
  {
    this.unsignedAttributes = unsignedAttributes;
  }

  /**
   * Add a additional signed attribute to the container. For common signed attributes this container provide convenience
   * methods.
   * 
   * @param attribute is the signed attribute that should be added to the signed attributes store.
   * @return the AttributeContainer for method chaining
   */
  public AttributeContainer addSignedAttribute(Attribute attribute)
  {
    requireNonNull(attribute);
    signedAttributes.put(attribute.getAttrType(), attribute);
    return this;
  }

  /**
   * Add a additional SignedAttribute to the container. For common unsigned attributes this container provide
   * convenience methods.
   * 
   * @param attribute is the unsigned attribute that should be added for the unsigned attributes store.
   * @return the AttributeContainer for method chaining
   */
  public AttributeContainer addUnsignedAttribute(Attribute attribute)
  {
    requireNonNull(attribute);
    unsignedAttributes.put(attribute.getAttrType(), attribute);
    return this;
  }

  /**
   * Set one or more signing certificates. Each call will overwrite the previous added certificates.
   * 
   * @param x509cert one or more X509Certificates that should be add to signed attributes.
   * @return the AttributeContainer for method chaining
   */
  public AttributeContainer setSigningCertificate(Certificate... x509cert)
  {
    requireNonNullOrEmpty(x509cert);

    try
    {
      MessageDigest md = MessageDigest.getInstance("SHA-256", signatureProvider.getCrypoProvider());

      ESSCertIDv2[] essCertIds = new ESSCertIDv2[x509cert.length];
      for (int i = 0; i < x509cert.length; i++)
      {
        if ((x509cert[i] instanceof X509Certificate))
        {
          X509Certificate x509Certificate = (X509Certificate) x509cert[i];
          byte[] cert = x509Certificate.getEncoded();
          byte[] digest = md.digest(cert);
          md.reset();

          essCertIds[i] = new ESSCertIDv2(getAlgorithmIdentifierForOID(NISTObjectIdentifiers.id_sha256), digest);
        }
        else
        {
          // no X509Certificate
        }
      }
      SigningCertificateV2 sCV2 = new SigningCertificateV2(essCertIds);
      addSignedAttribute(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(sCV2)));
    }
    catch (CertificateEncodingException e)
    {
      // Certificate parsing problem
    }
    catch (NoSuchAlgorithmException e)
    {
      // unknown algorithm
    }
    catch (NoSuchProviderException e)
    {
      // unknown provider
    }
    return this;
  }

}

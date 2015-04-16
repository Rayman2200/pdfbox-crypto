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

import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;

/**
 * Provide a central point for configuring the cms signed and unsigned attributes.
 * 
 * @author Thomas Chojecki
 */
public class AttributeContainer
{

  private Hashtable<DERObjectIdentifier, Attribute> signedAttributes;

  private Hashtable<DERObjectIdentifier, Attribute> unsignedAttributes;

  public AttributeContainer()
  {
    signedAttributes = new Hashtable<DERObjectIdentifier, Attribute>();
    unsignedAttributes = new Hashtable<DERObjectIdentifier, Attribute>();
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
   * @param objectIdentifier the identifier for the attribute
   * @param attribute is the attribute that should be added for the given object identifier.
   * @return the AttributeContainer for method chaining
   */
  public AttributeContainer addSignedAttribute(DERObjectIdentifier objectIdentifier, Attribute attribute)
  {
    signedAttributes.put(objectIdentifier, attribute);
    return this;
  }

  /**
   * Add a additional SignedAttribute to the container. For common unsigned attributes this container provide
   * convenience methods.
   * 
   * @param objectIdentifier the identifier for the attribute
   * @param attribute is the attribute that should be added for the given object identifier.
   * @return the AttributeContainer for method chaining
   */
  public AttributeContainer addUnsignedAttribute(DERObjectIdentifier objectIdentifier, Attribute attribute)
  {
    unsignedAttributes.put(objectIdentifier, attribute);
    return this;
  }

}

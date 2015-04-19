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
package org.apache.pdfbox.crypto.vr;

import java.io.IOException;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.util.GregorianCalendar;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import org.apache.pdfbox.crypto.VerificationReportBuilder;
import org.apache.pdfbox.crypto.bc.SignatureHelper;
import org.apache.pdfbox.crypto.core.CertificateHelper;
import org.apache.pdfbox.crypto.exceptions.ReportInitializationException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.schema.vr.simple_report.Certificates;
import org.apache.pdfbox.schema.vr.simple_report.Document;
import org.apache.pdfbox.schema.vr.simple_report.ObjectFactory;
import org.apache.pdfbox.schema.vr.simple_report.SignatureType;
import org.apache.pdfbox.schema.vr.simple_report.Signatures;
import org.bouncycastle.cms.CMSException;

/**
 * This verification report shows some essentials verification results. It act as a demo report and is not suitable for
 * productive use.
 * 
 * @author Thomas Chojecki
 */
public class SimpleReport implements VerificationReport
{
  private ObjectFactory factory;
  private Marshaller marshaller;

  private VerificationReportBuilder builder;

  private Document document;

  private String report;

  public void initReport() throws ReportInitializationException
  {
    try
    {
      JAXBContext context = JAXBContext.newInstance(Document.class);
      marshaller = context.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
      factory = new ObjectFactory();
    }
    catch (JAXBException e)
    {
      throw new RuntimeException("Could not create JAXB context.");
    }
  }

  public Document getDocument()
  {
    return document;
  }

  public VerificationReport generateVerificationReport()
  {
    DatatypeFactory dtf = null;
    try
    {
      dtf = DatatypeFactory.newInstance();

      document = factory.createDocument();
      document.setFileName(builder.getFilename());
      document.setFileSize(builder.getFileSize());
      Signatures signatures = factory.createSignatures();
      document.setSignatures(signatures);

      List<SignatureType> signatureList = signatures.getSignature();

      for (PDSignature pdSignature : builder.getSignatures())
      {
        try
        {
          SignatureHelper signatureHelper = new SignatureHelper(pdSignature,builder.getContentForSignature(pdSignature));
          SignatureType signature = factory.createSignatureType();
          signature.setSignerName(pdSignature.getName());
          signature.setSignerLocation(pdSignature.getLocation());
          signature.setSignerReason(pdSignature.getReason());
          signature.setSigningTime(dtf.newXMLGregorianCalendar((GregorianCalendar) pdSignature.getSignDate()));
          signature.setMathematicalyValid(signatureHelper.isMathematicalyValid());

          Certificates certificates = factory.createCertificates();
          signature.setCertificates(certificates);
          List<String> certificateList = certificates.getCertificate();
          certificateList.add(new CertificateHelper(signatureHelper.getSignerCertificate()).toString());
          Certificate[] certificateChain = signatureHelper.getCertificateChain();
          for (Certificate certificate : certificateChain)
          {
            certificateList.add(new CertificateHelper(certificate).toString());
          }
          signatureList.add(signature);
        }
        catch (CMSException e)
        {
          e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e)
        {
          e.printStackTrace();
        }
        catch (NoSuchProviderException e)
        {
          e.printStackTrace();
        }
        catch (CertStoreException e)
        {
          e.printStackTrace();
        }
      }

      StringWriter writer = new StringWriter();
      marshaller.marshal(document, writer);
      report = writer.toString();
    }
    catch (DatatypeConfigurationException e1)
    {
      throw new IllegalStateException(e1);
    }
    catch (JAXBException e2)
    {
      throw new IllegalStateException(e2);
    }
    catch (IOException e)
    {
      e.printStackTrace();
    }
    return this;
  }

  public void setVerificationReportBuilder(VerificationReportBuilder builder)
  {
    this.builder = builder;
  }

  @Override
  public String toString()
  {
    return report == null ? super.toString() : report;
  }

}

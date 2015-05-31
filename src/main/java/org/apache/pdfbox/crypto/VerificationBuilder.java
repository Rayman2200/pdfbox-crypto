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
package org.apache.pdfbox.crypto;

import org.apache.pdfbox.crypto.bc.VerificationResult;
import org.apache.pdfbox.crypto.exceptions.ReportInitializationException;
import org.apache.pdfbox.crypto.vr.VerificationReport;
import org.apache.pdfbox.crypto.vr.VerificationReportFactory;

/**
 * @author Thomas Chojecki
 */
public class VerificationBuilder
{

  private VerificationReport report;
  
  private final VerificationReportBuilder reportBuilder;

  private final PDCrypto crypo;

  private Class<? extends VerificationReport> reportClass;

  VerificationBuilder(PDCrypto crypto)
  {
    this.crypo = crypto;
    this.reportBuilder = new VerificationReportBuilder(crypto);
  }

  protected void prepareDocument()
  {

  }

  public VerificationResult verify() {
    return null;
  }
  
  public VerificationReport createVerificationReport() throws ReportInitializationException
  {
    return VerificationReportFactory.createReportForClass(reportClass, reportBuilder);
  }

  public VerificationBuilder setReportType(Class<? extends VerificationReport> report)
  {
    this.reportClass = report;
    return this;
  }
}

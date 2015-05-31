package org.apache.pdfbox.crypto.bc;

import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.crypto.exceptions.CMSInitializationException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CMSHelper
{
  protected CMSSignedData signedData;
  protected SignerInformation signer;
  protected CertStore cs;
  protected X509Certificate signerCertificate;
  protected ArrayList<Certificate> certificateChain;

  private final static Log LOG = LogFactory.getLog(CMSHelper.class);

  public CMSHelper(CMSProcessable content, byte[] signature) throws CMSInitializationException, CMSException
  {
    signedData = new CMSSignedData(content, signature);
  }

  public CMSHelper(CMSProcessable content, InputStream signature) throws CMSInitializationException, CMSException
  {
    signedData = new CMSSignedData(content, signature);
  }

  public CMSHelper(CMSSignedData signature)
  {
    signedData = signature;
  }

  protected void prepare() throws CMSInitializationException, CMSException
  {
    try
    {
      signer = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
      cs = signedData.getCertificatesAndCRLs("Collection", BouncyCastleProvider.PROVIDER_NAME);
      Iterator iter = cs.getCertificates(signer.getSID()).iterator();

      // grab the first certificate (signer certificate)
      signerCertificate = (X509Certificate) iter.next();

      certificateChain = new ArrayList<Certificate>();
      // iterate through the rest of the store
      while (iter.hasNext())
      {
        certificateChain.add((Certificate) iter.next());
      }
    }
    catch (NoSuchAlgorithmException e)
    {
      LOG.error(e);
      throw new CMSInitializationException(e);
    }
    catch (NoSuchProviderException e)
    {
      LOG.error(e);
      throw new CMSInitializationException(e);
    }
    catch (CertStoreException e)
    {
      LOG.error(e);
      throw new CMSInitializationException(e);
    }
  }

  public boolean isMathematicalyValid()
  {
    // TODO
    return false;
  }

  public boolean isMathematicalyValid(Certificate cert)
  {
    // TODO
    return false;
  }

}

package com.trodix.demo.sslbundlemanage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ssl.JksSslBundleProperties;
import org.springframework.boot.autoconfigure.ssl.SslProperties;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@Component
public class CertificateUtils {

    @Autowired
    private SslProperties sslProperties;

    @Autowired
    private ResourceLoader resourceLoader;

    public Map<String, List<CertInfo>> getBundlesCertificates() {
        Map<String, List<X509Certificate>> data = iterateBundles(sslProperties.getBundle().getJks());

        Map<String, List<CertInfo>> res = new HashMap<>();
        for (Map.Entry<String, List<X509Certificate>> entry : data.entrySet()) {
            List<CertInfo> subs = new ArrayList<>();
            for (X509Certificate certificate : entry.getValue()) {
                CertInfo sub = new CertInfo(
                        certificate.getSerialNumber(),
                        certificate.getSubjectX500Principal().getName(),
                        certificate.getIssuerX500Principal().getName(),
                        certificate.getNotBefore(),
                        certificate.getNotAfter()
                );
                subs.add(sub);
            }
            Collections.sort(subs);
            res.put(entry.getKey(), subs);
        }

        return res;
    }

    public Map<String, List<X509Certificate>> iterateBundles(Map<String, JksSslBundleProperties> bundlePropertiesMap) {
        Map<String, List<X509Certificate>> certsMap = new HashMap<>();

        for (Map.Entry<String, JksSslBundleProperties> entry : bundlePropertiesMap.entrySet()) {
            String locationKeystore = entry.getValue().getKeystore().getLocation();
            if (locationKeystore != null) {
                try {
                    List<X509Certificate> keystoreCerts = listCertificates(entry.getValue().getKeystore());
                    certsMap.put(locationKeystore, keystoreCerts);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            String locationTruststore = entry.getValue().getTruststore().getLocation();
            if (locationTruststore != null) {
                try {
                    List<X509Certificate> truststoreCerts = listCertificates(entry.getValue().getTruststore());
                    certsMap.put(locationTruststore, truststoreCerts);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        return certsMap;
    }

    public List<X509Certificate> listCertificates(JksSslBundleProperties.Store store) throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {

        TrustManagerFactory trustManagerFactory=TrustManagerFactory
                .getInstance(TrustManagerFactory
                        .getDefaultAlgorithm());

        ;
        try(InputStream fis = resourceLoader.getResource(store.getLocation()).getInputStream()) {

            KeyStore keyStore=KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(fis, store.getPassword().toCharArray());
            trustManagerFactory.init(keyStore);
        }

        TrustManager[] truestManagers=trustManagerFactory.getTrustManagers();
        List<X509Certificate> certs = new ArrayList<>();
        for(TrustManager t:truestManagers) {
            for(X509Certificate c:((X509TrustManager)t).getAcceptedIssuers()) {
                certs.add(c);
            }
        }

        return certs;

    }

    public class CertInfo implements Comparable<CertInfo> {
        private BigInteger serialNumber;
        private String commonName;
        private String issuer;
        private Date validNotBefore;
        private Date validNotAfter;

        public CertInfo(BigInteger serialNumber, String commonName, String issuer, Date validNotBefore, Date validNotAfter) {
            this.serialNumber = serialNumber;
            this.commonName = commonName;
            this.issuer = issuer;
            this.validNotBefore = validNotBefore;
            this.validNotAfter = validNotAfter;
        }

        @Override
        public int compareTo(CertInfo other) {
            Date now = new Date();
            long diff1 = Math.abs(this.validNotBefore.getTime() - now.getTime());
            long diff2 = Math.abs(other.validNotBefore.getTime() - now.getTime());
            return Long.compare(diff1, diff2);
        }

        public BigInteger getSerialNumber() {
            return serialNumber;
        }

        public void setSerialNumber(BigInteger serialNumber) {
            this.serialNumber = serialNumber;
        }

        public String getCommonName() {
            return commonName;
        }

        public void setCommonName(String commonName) {
            this.commonName = commonName;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public Date getValidNotBefore() {
            return validNotBefore;
        }

        public void setValidNotBefore(Date validNotBefore) {
            this.validNotBefore = validNotBefore;
        }

        public Date getValidNotAfter() {
            return validNotAfter;
        }

        public void setValidNotAfter(Date validNotAfter) {
            this.validNotAfter = validNotAfter;
        }
    }
}

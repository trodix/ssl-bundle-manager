package com.trodix.demo.sslbundlemanage;

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

    private final SslProperties sslProperties;

    private final ResourceLoader resourceLoader;

    public CertificateUtils(SslProperties sslProperties, ResourceLoader resourceLoader) {
        this.sslProperties = sslProperties;
        this.resourceLoader = resourceLoader;
    }

    public Map<String, List<CertInfo>> getAllCertificates() {
        Map<String, List<X509Certificate>> data = new HashMap<>();

        data.putAll(listCertificatesFromSSLBundles());
        data.putAll(listCertificatesJvmTruststore());
        data.putAll(listCertificatesJvmKeystore());

        Map<String, List<CertInfo>> res = new HashMap<>();
        for (Map.Entry<String, List<X509Certificate>> entry : data.entrySet()) {
            List<CertInfo> subs = getCertInfos(entry);
            Collections.sort(subs);
            res.put(entry.getKey(), subs);
        }

        return res;
    }

    private List<CertInfo> getCertInfos(Map.Entry<String, List<X509Certificate>> entry) {
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
        return subs;
    }

    public Map<String, List<X509Certificate>> listCertificatesFromSSLBundles() {
        Map<String, List<X509Certificate>> certsMap = new HashMap<>();

        for (Map.Entry<String, JksSslBundleProperties> entry : sslProperties.getBundle().getJks().entrySet()) {
            String locationKeystore = entry.getValue().getKeystore().getLocation();
            if (locationKeystore != null) {
                try {
                    certsMap.putAll(listCertificatesFromSSLBundlesStore(entry.getValue().getKeystore()));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            String locationTruststore = entry.getValue().getTruststore().getLocation();
            if (locationTruststore != null) {
                try {
                    certsMap.putAll(listCertificatesFromSSLBundlesStore(entry.getValue().getTruststore()));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        return certsMap;
    }

    public Map<String, List<X509Certificate>> listCertificatesFromSSLBundlesStore(JksSslBundleProperties.Store store) throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {

        Map<String, List<X509Certificate>> res = new HashMap<>();

        try {
            res.put(store.getLocation(), listCertificates(store.getLocation(), store.getPassword()));
        } catch (Exception e) {
            e.printStackTrace();
            return res;
        }

        return res;
    }

    public Map<String, List<X509Certificate>> listCertificatesJvmTruststore() {
        String trustStorePath = System.getProperty("javax.net.ssl.trustStore");
        String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");

        Map<String, List<X509Certificate>> res = new HashMap<>();

        if (trustStorePath == null || trustStorePassword == null) {
            return res;
        }

        try {
            res.put(trustStorePath, listCertificates(trustStorePath, trustStorePassword));
        } catch (Exception e) {
            e.printStackTrace();
            return res;
        }

        return res;
    }

    public Map<String, List<X509Certificate>> listCertificatesJvmKeystore() {
        String keysStorePath = System.getProperty("javax.net.ssl.keyStore");
        String keysStorePassword = System.getProperty("javax.net.ssl.keyStorePassword");

        Map<String, List<X509Certificate>> res = new HashMap<>();

        if (keysStorePath == null || keysStorePassword == null) {
            return res;
        }

        try {
            res.put(keysStorePath, listCertificates(keysStorePath, keysStorePassword));
        } catch (Exception e) {
            e.printStackTrace();
            return res;
        }

        return res;
    }

    public List<X509Certificate> listCertificates(String filePath, String password) throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        try(InputStream fis = resourceLoader.getResource(filePath).getInputStream()) {

            KeyStore keyStore=KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(fis, password.toCharArray());
            trustManagerFactory.init(keyStore);
        }

        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        List<X509Certificate> certs = new ArrayList<>();
        for (TrustManager t : trustManagers) {
            for (X509Certificate c:((X509TrustManager)t).getAcceptedIssuers()) {
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

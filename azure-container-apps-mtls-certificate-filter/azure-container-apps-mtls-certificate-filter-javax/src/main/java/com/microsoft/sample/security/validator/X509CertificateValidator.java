package com.microsoft.sample.security.validator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

@Service
public class X509CertificateValidator {

    private X509TrustManager trustManager;

    public X509CertificateValidator(@Value("${trust-store.path}") String trustStorePath,
                                    @Value("${trust-store.password}") String trustStorePassword) throws Exception {
        // Load the trust store
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream trustStoreStream = new FileInputStream(trustStorePath)) {
            trustStore.load(trustStoreStream, trustStorePassword.toCharArray());
        }

        // Initialize the TrustManagerFactory with the trust store
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        // Get the X509TrustManager from the factory
        for (javax.net.ssl.TrustManager tm : trustManagerFactory.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                this.trustManager = (X509TrustManager) tm;
                break;
            }
        }

        if (this.trustManager == null) {
            throw new IllegalStateException("No X509TrustManager found");
        }
    }

    /**
     * Validates the provided X.509 certificate chain.
     * <p>
     * This method performs the following checks:
     * 1. Ensures the certificate chain is not empty.
     * 2. Validates that the subject DN of the first certificate ends with "@contoso.com".
     * 3. Validates that the issuer DN of the first certificate ends with "@contoso.com".
     * 4. Uses the trust manager to check the certificate chain.
     * <p>
     * Note: This is a basic reference implementation. Customers need to modify the logic according to their specific requirements.
     */
    public void validate(X509Certificate[] certificateChain) throws CertificateException {
        if (certificateChain == null || certificateChain.length == 0) {
            throw new CertificateException("Certificate chain is empty");
        }
        X509Certificate certificate = certificateChain[0];
        String subjectDN = certificate.getSubjectX500Principal().getName();
        if (!subjectDN.endsWith("@contoso.com")) {
            throw new CertificateException("Certificate subject DN does not end with 'contoso.com': " + subjectDN);
        }
        String issuerDN = certificate.getIssuerX500Principal().getName();
        if (!issuerDN.endsWith("@contoso.com")) {
            throw new CertificateException("Certificate issuer DN does not end with 'contoso.com': " + issuerDN);
        }
        this.trustManager.checkServerTrusted(certificateChain, "RSA");
    }
}

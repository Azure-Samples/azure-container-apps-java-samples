package com.microsoft.sample.security.servlet;

import com.microsoft.sample.security.validator.X509CertificateValidator;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AzureContainerAppsCertificateFilter implements Filter {

    private static final String AZURE_CONTAINER_APPS_CLIENT_CERTIFICATE_HEADER = "X-Forwarded-Client-Cert";
    private static final String JAKARTA_SERVLET_REQUEST_X_509_CERTIFICATE = "jakarta.servlet.request.X509Certificate";
    private static final String CERTIFICATE_PATTERN = "Hash=([^;]+);Cert=\"([^\"]+)\";Chain=\"([^\"]+)\";?";
    private static final String END_CERTIFICATE_PATTERN = "(?<=-----END CERTIFICATE-----)";
    private static final String X509 = "X.509";

    private final X509CertificateValidator certificateValidator;
    private final CertificateFactory certificateFactory;

    public AzureContainerAppsCertificateFilter(X509CertificateValidator certificateValidator) throws CertificateException {
        this.certificateValidator = certificateValidator;
        this.certificateFactory = CertificateFactory.getInstance(X509);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        X509Certificate[] x509Certificates;
        try {
            x509Certificates = extractCertificates((HttpServletRequest) request);
            certificateValidator.validate(x509Certificates);
        } catch (CertificateException e) {
            ((HttpServletResponse) response).sendError(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
            return;
        }
        request.setAttribute(JAKARTA_SERVLET_REQUEST_X_509_CERTIFICATE, x509Certificates);
        chain.doFilter(request, response);
    }

    private X509Certificate[] extractCertificates(HttpServletRequest request) throws CertificateException {
        X509Certificate[] x509Certificates = getCertificatesFromJakartaAttribute(request);

        if (x509Certificates == null) {
            // Azure Container Apps redirects the certificate in a header field
            String header = request.getHeader(AZURE_CONTAINER_APPS_CLIENT_CERTIFICATE_HEADER);
            if (header != null && !header.isEmpty()) {
                String certChain = extractCertsFromAzureContainerAppsHeader(header);
                x509Certificates = convertToX509CertificateArray(certChain);
            }
        }

        return x509Certificates;
    }

    private String extractCertsFromAzureContainerAppsHeader(String certHeader) throws CertificateException {
        Pattern pattern = Pattern.compile(CERTIFICATE_PATTERN);
        Matcher matcher = pattern.matcher(certHeader);

        if (matcher.find()) {
            String certs = matcher.group(3); // the chain part
            if (certs.isEmpty()) {
                certs = matcher.group(2); // the cert part
            }
            return URLDecoder.decode(certs, StandardCharsets.UTF_8);
        } else {
            throw new CertificateException(AZURE_CONTAINER_APPS_CLIENT_CERTIFICATE_HEADER + " header string does not match the expected pattern.");
        }
    }

    private X509Certificate[] convertToX509CertificateArray(String certChain) throws CertificateException {
        String[] certStrings = certChain.split(END_CERTIFICATE_PATTERN);
        List<X509Certificate> certificates = new ArrayList<>();

        for (String certString : certStrings) {
            if (!certString.trim().isEmpty()) {
                try (ByteArrayInputStream certificateStream = new ByteArrayInputStream(certString.getBytes())) {
                    X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certificateStream);
                    certificates.add(certificate);
                } catch (IOException e) {
                    throw new CertificateException("Failed to convert certificates string to X509Certificate", e);
                }
            }
        }

        return certificates.toArray(new X509Certificate[0]);
    }

    private X509Certificate[] getCertificatesFromJakartaAttribute(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(JAKARTA_SERVLET_REQUEST_X_509_CERTIFICATE);

        if (certs != null && certs.length > 0) {
            return certs;
        }
        return null;
    }

}

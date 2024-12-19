package com.microsoft.sample.security.reactive;

import com.microsoft.sample.security.validator.X509CertificateValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

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
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
public class AzureContainerAppsCertificateWebFilter implements WebFilter, Ordered {

    private static final String AZURE_CONTAINER_APPS_CLIENT_CERTIFICATE_HEADER = "X-Forwarded-Client-Cert";
    private static final String JAKARTA_SERVLET_REQUEST_X_509_CERTIFICATE = "jakarta.servlet.request.X509Certificate";
    private static final String CERTIFICATE_PATTERN = "Hash=([^;]+);Cert=\"([^\"]+)\";Chain=\"([^\"]+)\";?";
    private static final String END_CERTIFICATE_PATTERN = "(?<=-----END CERTIFICATE-----)";
    private static final String X509 = "X.509";

    private final X509CertificateValidator certificateValidator;
    private final CertificateFactory certificateFactory;

    public AzureContainerAppsCertificateWebFilter(X509CertificateValidator certificateValidator) throws CertificateException {
        this.certificateValidator = certificateValidator;
        this.certificateFactory = CertificateFactory.getInstance(X509);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return Mono.fromCallable(() -> extractCertificates(exchange))
            .flatMap(certs -> {
                try {
                    certificateValidator.validate(certs);
                    exchange.getAttributes().put(JAKARTA_SERVLET_REQUEST_X_509_CERTIFICATE, certs);
                    return chain.filter(exchange);
                } catch (CertificateException e) {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            })
            .onErrorResume(CertificateException.class, e -> {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            });
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private X509Certificate[] extractCertificates(ServerWebExchange exchange) throws CertificateException {
        String header = exchange.getRequest().getHeaders().getFirst(AZURE_CONTAINER_APPS_CLIENT_CERTIFICATE_HEADER);
        if (header != null && !header.isEmpty()) {
            String certChain = extractCertsFromAzureContainerAppsHeader(header);
            return convertToX509CertificateArray(certChain);
        }
        return new X509Certificate[0];
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
            throw new CertificateException(AZURE_CONTAINER_APPS_CLIENT_CERTIFICATE_HEADER + " header string does not "
                + "match the expected pattern.");
        }
    }

    private X509Certificate[] convertToX509CertificateArray(String certChain) throws CertificateException {
        String[] certStrings = certChain.split(END_CERTIFICATE_PATTERN);
        List<X509Certificate> certificates = new ArrayList<>();
        for (String certString : certStrings) {
            if (!certString.trim().isEmpty()) {
                try (ByteArrayInputStream certificateStream = new ByteArrayInputStream(certString.getBytes())) {
                    X509Certificate certificate =
                        (X509Certificate) certificateFactory.generateCertificate(certificateStream);
                    certificates.add(certificate);
                } catch (IOException e) {
                    throw new CertificateException("Failed to convert certificates string to X509Certificate", e);
                }
            }
        }
        return certificates.toArray(new X509Certificate[0]);
    }
}
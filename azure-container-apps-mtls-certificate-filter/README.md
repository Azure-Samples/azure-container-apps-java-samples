# Build an mTLS application in Azure Container Apps

This project demonstrates how to run a Java application In Azure Container Apps (ACA) to receive mTLS handshake certificates and validate. It is the supplementary sample of the Microsoft document [Building a Secure mTLS Java Application in Azure Container Apps](https://review.learn.microsoft.com/en-us/azure/container-apps/java-mtls?branch=pr-en-us-291193).

In this project, the applications act as an mTLS server to extract X.509 certificates from incoming HTTP request header, and show an example of validating the certificates using the server application's own trust store, which should be customized according to your own business logic.

## Project Structure

This project is divided into three modules, each demonstrating how to implement the mTLS handshake server in different types of Java applications:

- [Servlet Web App using Jakarta API](azure-container-apps-mtls-certificate-filter-jakarta): This module demonstrates how to extract certificates using the Jakarta Servlet API, which supports Spring Boot 3.x.
- [Servlet Web App using Javax API](azure-container-apps-mtls-certificate-filter-javax): This module demonstrates how to extract certificates using the Javax Servlet API, which supports Spring Boot 2.x.
- [Reactive Web App](azure-container-apps-mtls-certificate-filter-reactive): This module demonstrates how to extract certificates in a reactive web application.

All the 3 modules have the similar structure, which includes a certificate filter and a validator.

One main difference between the servlet modules and the reactive module is that the servlet ones add a [FilterRegistrationBean](azure-container-apps-mtls-certificate-filter-jakarta/src/main/java/com/microsoft/sample/security/servlet/FilterRegistrationBeanConfig.java) to register the certificate filter to the servlet container, whereas the reactive application can directly apply a web filter bean.

## Main components

As mentioned above, the main components of the project include an X.509 certificate filter and a certificate validator.

### X.509 Certificate Filter

The certificate filter is responsible for intercepting incoming requests, extracting the X.509 certificates from [Azure Container Apps' specific header](https://learn.microsoft.com/azure/container-apps/ingress-overview#http-headers), and storing them in the request attribute for further usages. Then the application can access the certificates from the attribute.

### Certificate Validator

The certificate validator is only an example, it should be implemented according to your own business requirement and the specific Java framework you are using. The validator checks the X.509 certificates extracted by the certificate filter, and it loads the server application's own trust store, which can contains the public and private CA certificates. So to use this validator, you should first prepare a trust store in your Container App and configure the trust store path and password in the application properties.

## How to run

To deploy this application to Azure Container Apps, you need to prepare the following resources:

1. Prepare a trust store containing your CA certificates.
2. Deploy your app to Azure Container Apps.
3. Configure your container app to require client certificates.
4. Test the application.

The following sections provide detailed steps for each of the above operations and takes the [azure-container-apps-mtls-certificate-filter-jakarta](azure-container-apps-mtls-certificate-filter-jakarta) module as an example.

### Prepare a trust store and certificates for testing

In this section, we will prepare a trusted CA certificate store and the client certificates which can be verified by one of the CA certificate in the store. In production use case, the trusted CA certificates and the client certificates are likely to be provided by some authority. **Here, for demonstration, we will use OpenSSL to generate the certificates, which should be used in development environment only.** The below operations use the [openssl](https://wiki.openssl.org/index.php/Binaries) library, so your need to have it installed prior to following the next step.

1. Step into the module you want to test, and generate a root CA certificate and key:

    ```bash
    cd azure-container-apps-mtls-certificate-filter-jakarta
    openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt
    ```
   The command will ask you to provide the password and some information like below.

   ```bash
   #### sample inputs ####
   Enter PEM pass phrase:<password-1>
   Verifying - Enter PEM pass phrase:<password-1>
   ----
   Country Name (2 letter code) [AU]:US
   State or Province Name (full name) [Some-State]:Washington
   Locality Name (eg, city) []:Redmond
   Organization Name (eg, company) [Internet Widgits Pty Ltd]:Contoso
   Organizational Unit Name (eg, section) []:
   Common Name (e.g. server FQDN or YOUR name) []:ca.contoso.com
   Email Address []:ca@contoso.com
   ```

2. Generate a trust store:

    ```bash
    keytool -import -trustcacerts -noprompt -alias ca -file rootCA.crt -keystore truststore.jks
    ```
   The command will ask you to provide the password for the trust store:
   ```bash
   #### sample inputs ####
   Enter keystore password:<password-2>
   Re-enter new password:<password-2>
   Certificate was added to keystore
   ```

3. Generate a client certificate and key:

   Create a certificate signing request:
    ```bash
    openssl req -new -newkey rsa:4096 -nodes -keyout client.key -out client.csr
    ```
   You will be asked again to provide information about the certificate:
   ```bash
   #### sample inputs ####
   Country Name (2 letter code) [AU]:US
   State or Province Name (full name) [Some-State]:Washington
   Locality Name (eg, city) []:Redmond
   Organization Name (eg, company) [Internet Widgits Pty Ltd]:Contoso
   Organizational Unit Name (eg, section) []:
   Common Name (e.g. server FQDN or YOUR name) []:user-a.users.contoso.com
   Email Address []:user-a@contoso.com
   
   Please enter the following 'extra' attributes
   to be sent with your certificate request
   A challenge password []:
   An optional company name []:
   ```

   Then sign the certificate with the root CA:
    ```bash
    openssl x509 -req -days 365 -in client.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out client.crt
    ```
   And you will be asked to provide the password of the root CA:
   ```bash
    Enter pass phrase for rootCA.key:<password-1>
   ```

### Deploy to Azure Container Apps

Open the [pom.xml](azure-container-apps-mtls-certificate-filter-jakarta/pom.xml) and modify the [azure-container-apps-maven-plugin](https://github.com/microsoft/azure-maven-plugins/wiki/Azure-Container-Apps:-Deploy) configuration(subscriptionId, resourceGroup, appEnvironmentName, region and appName).

Run the command below to build your app and deploy to Azure Container Apps, and replace `<password-2>` with the password you set for the trust store:

```bash
./mvnw clean package
./mvnw azure-container-apps:deploy -DtruststorePassword=<password-2>
```

### Configure your container app to require client certificates

Please refer to the document [Building a Secure mTLS Java Application in Azure Container Apps](https://review.learn.microsoft.com/en-us/azure/container-apps/java-mtls?branch=pr-en-us-291193) to configure your container app to require client certificates.

### Test the application

Now you can test the application by sending a request with the client certificate to the application. You can use tools like [curl](https://curl.se/) to send the request.

 ```bash
 curl -k --cert client.crt --key client.key <your-container-app-url>/hello
 ```

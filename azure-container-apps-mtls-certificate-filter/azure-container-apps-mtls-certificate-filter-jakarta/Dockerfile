# Use an official OpenJDK runtime as a parent image
FROM mcr.microsoft.com/openjdk/jdk:17-mariner

ARG TRUSTSTORE_PATH=truststore.jks
ARG APPLICATION_JAR=target/azure-container-apps-mtls-certificate-filter-jakarta-0.0.1-SNAPSHOT.jar

# Set the working directory
WORKDIR /app

# Copy the application JAR file and trust store
COPY ${APPLICATION_JAR} /app/application.jar
COPY ${TRUSTSTORE_PATH} /app/truststore.jks

# Expose the port the application runs on
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "application.jar"]
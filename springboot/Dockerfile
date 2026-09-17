# Build the jar in the image so a deploy needs no local Maven or JDK.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build

# Dependencies first: this layer is cached until pom.xml itself changes.
COPY pom.xml .
RUN mvn -q -B dependency:go-offline

COPY src ./src
RUN mvn -q -B clean package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app

# Never run as root in a container that faces the network.
RUN useradd --system --create-home --uid 10001 app
USER app

COPY --from=build /build/target/crud-service-*.jar app.jar

EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=5 \
  CMD ["sh", "-c", "wget -qO- http://127.0.0.1:8080/actuator/health | grep -q '\"status\":\"UP\"'"]

ENTRYPOINT ["java", "-jar", "/app/app.jar"]

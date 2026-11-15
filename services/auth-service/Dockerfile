
# Stage 1: Build the Spring Boot application
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn -B -DskipTests package

# Stage 2: Run the application
FROM eclipse-temurin:21-jre

WORKDIR /app

RUN groupadd --system secureops && \
    useradd --system --gid secureops secureops

COPY --from=build --chown=secureops:secureops \
    /app/target/*.jar app.jar

USER secureops

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]

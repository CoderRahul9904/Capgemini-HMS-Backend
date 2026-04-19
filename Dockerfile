# Build stage
FROM maven:3.8.4-openjdk-17-slim AS build
COPY . /app
WORKDIR /app
RUN mvn clean install -DskipTests

# Run stage
FROM openjdk:17-jdk-slim
COPY --from=build /app/target/hms-0.0.1-SNAPSHOT.jar /app/hms.jar
WORKDIR /app
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "hms.jar"]

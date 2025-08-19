FROM openjdk:17

WORKDIR /app

COPY . .

RUN ./mvnw clean package -DskipTests

EXPOSE 8082

ENTRYPOINT ["java", "-jar","target/user-service-0.0.1-SNAPSHOT.jar"]

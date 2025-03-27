FROM eclipse-temurin:17-jdk
WORKDIR /app
COPY . .
RUN chmod +x gradlew
RUN ./gradlew build --no-daemon
CMD ["java", "-jar", "build/libs/auth_service-1.jar"]

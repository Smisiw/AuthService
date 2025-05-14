# Стадия сборки
FROM gradle:8.4-jdk17 AS build
WORKDIR /app
COPY . .
RUN chmod +x gradlew
RUN gradle build --no-daemon

# Стадия запуска
FROM eclipse-temurin:17-jdk-alpine
VOLUME /tmp
COPY --from=build /app/build/libs/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
FROM eclipse-temurin:21-jre
WORKDIR /app
RUN useradd --no-create-home --shell /bin/false --uid 10004 leona
COPY admin-service/build/libs/*.jar /app/libs/
RUN cp "$(find /app/libs -maxdepth 1 -type f -name '*.jar' ! -name '*-plain.jar' | head -n 1)" /app/app.jar \
    && rm -rf /app/libs
USER leona
EXPOSE 8083
ENV JAVA_OPTS="-XX:+UseZGC -XX:MaxRAMPercentage=75"
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]

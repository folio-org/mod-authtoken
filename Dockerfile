FROM openjdk:8-jre-alpine

ENV VERTICLE_FILE authtoken_module-fat.jar

# Set the location of the verticles
ENV VERTICLE_HOME /usr/verticles

# Copy your fat jar to the container
COPY target/$VERTICLE_FILE $VERTICLE_HOME/module.jar

# Create user/group 'folio'
RUN addgroup folio && \
    adduser -H -h $VERTICLE_HOME -G folio -D folio && \
    chown -R folio.folio $VERTICLE_HOME

# Run as this user
USER folio

# Launch the verticle
WORKDIR $VERTICLE_HOME

# Expose this port locally in the container.
EXPOSE 8081

ENTRYPOINT exec java $JAVA_OPTS -jar module.jar

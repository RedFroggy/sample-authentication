package fr.redfroggy.sample.server.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Settings for socket
 */
@Component
@ConfigurationProperties
@Data
public class SocketSettings {

    protected String host = "localhost";

    protected int port = 12345;

}

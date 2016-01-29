package fr.redfroggy.sample.tpa.server;

import fr.redfroggy.sample.tpa.server.services.ServerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import javax.annotation.PostConstruct;

/**
 * Server application
 */
@SpringBootApplication
@EnableAutoConfiguration
@Slf4j
public class Server {

    @Autowired
    protected ServerService serverService;

    @PostConstruct
    protected void run() {
        serverService.run();
    }

    /**
     * Main server method
     *
     * @param args Command args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        Server.log.info("Server is running");
        SpringApplication app = new SpringApplication(Server.class);
        app.setWebEnvironment(false);
        ConfigurableApplicationContext ctx = app.run(args);

        System.exit(SpringApplication.exit(ctx));
        Server.log.info("Server stopped");
    }

}

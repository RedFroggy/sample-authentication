package fr.redfroggy.sample.tpa.client;

import fr.redfroggy.sample.tpa.client.services.ClientService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import javax.annotation.PostConstruct;

/**
 * Client application
 */
@SpringBootApplication
@EnableAutoConfiguration
@Slf4j
public class Client {

    @Autowired
    protected ClientService clientService;

    @PostConstruct
    public void run() {
        clientService.run();
    }

    public static void main(String[] args) throws Exception {
        Client.log.info("Client is running");
        SpringApplication app = new SpringApplication(Client.class);
        app.setWebEnvironment(false);
        ConfigurableApplicationContext ctx = app.run(args);

        System.exit(SpringApplication.exit(ctx));
        Client.log.info("Client stopped");
    }

}

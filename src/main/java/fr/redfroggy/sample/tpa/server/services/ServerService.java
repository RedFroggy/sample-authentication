package fr.redfroggy.sample.tpa.server.services;

import com.google.common.primitives.Bytes;
import fr.redfroggy.sample.tpa.commons.exceptions.CommunicationException;
import fr.redfroggy.sample.tpa.commons.exceptions.EOTException;
import fr.redfroggy.sample.tpa.commons.exceptions.ServerException;
import fr.redfroggy.sample.tpa.commons.protocol.CommandSet;
import fr.redfroggy.sample.tpa.commons.services.AbstractCommunicationService;
import fr.redfroggy.sample.tpa.commons.utils.BytesUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Server service
 */
@Slf4j
@Service
public class ServerService extends AbstractCommunicationService {

    @Autowired
    protected ServerSocket socket;

    protected Socket connectionSocket;

    protected byte[] challenge;

    protected byte[] randomClient;

    /**
     * Run server
     */
    public void run() {

        try {
            log.info("Server waiting for connection");
            connectionSocket = socket.accept();
            if (connectionSocket.isConnected()) {
                out = new DataOutputStream(connectionSocket.getOutputStream());
                in = connectionSocket.getInputStream();
                listen();
            }
            socket.close();
        } catch (Exception e) {
            log.info("Server socket closed with exception", e);
            run();
        }
    }

    /**
     * Open server socket
     *
     * @throws ServerException If a transmission error occurred
     */
    protected void listen() throws ServerException {

        log.info("Client " + connectionSocket.getInetAddress().toString() + " connected");
        boolean endOfTransmission = false;
        while (!endOfTransmission) {
            try {
                byte[] command = receive();
                byte[] response = execute(command);
                send(response, false);
            } catch (EOTException e) {
                endOfTransmission = true;
            } catch (CommunicationException e) {
                throw new ServerException("Server communication error", e);
            }
        }
        log.info("Client " + connectionSocket.getInetAddress().toString() + " disconnected");
    }

    /**
     * Interpret received command from client
     *
     * @param command Command to interpret
     * @return Result bytes
     * @throws ServerException If an interpretation error occurred
     */
    protected byte[] execute(byte[] command) throws ServerException {

        if (command == null || command.length == 0) {
            return CommandSet.error("Command is empty");
        }

        byte ins = command[0];
        byte[] data = Arrays.copyOfRange(command, 1, command.length);

        switch (CommandSet.Instruction.get(ins)) {
            case AUC:
                return authenticateClient(data);
            case AUS:
                return authenticateServer(data);
            case CLG:
                return getChallenge();
            case MSG:
                return showMessage(data);
            case STP:
                throw new EOTException();
            default:
                return CommandSet.error("Unknown instruction");
        }
    }

    /**
     * Generate challenge (3Pass Authentication)
     *
     * @return Challenge bytes
     */
    protected byte[] getChallenge() {
        log.info("Generate challenge");
        challenge = cipherService.random();
        log.debug("challenge: {}", BytesUtils.bytesToHex(challenge, ' '));
        return challenge;
    }

    /**
     * Authenticate client (3Pass Authentication)
     *
     * @param data Client authentication sequence
     * @return Result
     */
    protected byte[] authenticateClient(byte[] data) {
        try {
            log.info("Authentication Client");
            byte[] dkData = cipherService.decode(data);
            byte[] challengeS = Arrays.copyOfRange(dkData, cipherService.getAlgorithm().getBlocSize(), cipherService.getAlgorithm().getBlocSize() * 2);
            byte[] challengeC = Arrays.copyOfRange(dkData, 0, cipherService.getAlgorithm().getBlocSize());


            if (Arrays.equals(challengeS, challenge)) {
                randomClient = challengeC;
                log.debug("Client verification success");
                return CommandSet.success();
            } else {
                return CommandSet.error("Returned challenge not match");
            }

        } catch (GeneralSecurityException e) {
            log.error("Cannot decode challenge", e);
            return CommandSet.error("Cryptographic error");
        }
    }

    /**
     * Authenticate server (3Pass Authentication)
     *
     * @param data Client challenge
     * @return Server authentication sequence
     */
    protected byte[] authenticateServer(byte[] data) {
        try {
            log.info("Authentication Server");
            byte[] rndServer = cipherService.random();
            byte[] ek = cipherService.encode(Bytes.concat(rndServer, data));

            setSessionKey(randomClient, rndServer);

            return ek;
        } catch (GeneralSecurityException e) {
            log.error("Cannot decode challenge", e);
            return CommandSet.error("Cryptographic error");
        }
    }

    /**
     * Display received messages
     *
     * @param data Data
     * @return Result
     */
    protected byte[] showMessage(byte[] data) {
        try {
            log.debug("ek(message): {}", BytesUtils.bytesToHex(data, ' '));
            byte[] message = cipherService.decode(data);
            log.debug("message: {}", BytesUtils.bytesToHex(message, ' '));
            log.info("Message received : " + new String(message));
            return CommandSet.receive(BytesUtils.crc32(message));
        } catch (GeneralSecurityException e) {
            log.error("Cannot decode message", e);
            return CommandSet.error("Cryptographic error");
        }
    }
}

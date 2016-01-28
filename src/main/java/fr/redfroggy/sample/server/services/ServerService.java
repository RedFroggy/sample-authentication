package fr.redfroggy.sample.server.services;

import com.google.common.primitives.Bytes;
import fr.redfroggy.sample.commons.exceptions.EOTException;
import fr.redfroggy.sample.commons.protocol.CommandSet;
import fr.redfroggy.sample.commons.security.CipherService;
import fr.redfroggy.sample.commons.utils.BytesUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Arrays;

@Slf4j
@Service
@Async
public class ServerService {

    protected static final int FRAME_SIZE = 64;

    @Autowired
    protected ServerSocket socket;

    @Autowired
    protected CipherService cipherService;

    protected Socket connectionSocket;

    protected byte[] challenge;

    protected byte[] randomClient;

    DataOutputStream out;

    InputStream in;

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
            e.printStackTrace();
            log.info("Server socket closed with exception");
        } finally {
            run();
        }
    }

    protected void listen() throws Exception {

        log.info("Client " + connectionSocket.getInetAddress().toString() + " connected");
        boolean endOfTransmission = false;
        while (!endOfTransmission) {
            try {
                byte[] command = receive();
                byte[] response = execute(command);
                send(response);
            } catch (EOTException e) {
                endOfTransmission = true;
            }
        }
        log.info("Client " + connectionSocket.getInetAddress().toString() + " disconnected");
    }

    protected byte[] execute(byte[] command) throws Exception {

        if (command == null || command.length == 0) {
            return CommandSet.error("Command is empty");
        }

        byte ins = command[0];
        byte[] data = Arrays.copyOfRange(command, 1, command.length);

        switch(CommandSet.Instruction.get(ins)) {
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

    protected byte[] getChallenge() {
        log.info("Generate challenge");
        challenge = cipherService.random();
        log.debug("challenge: {}", BytesUtils.bytesToHex(challenge, ' '));
        return challenge;
    }

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

    protected byte[] authenticateClient(byte[] data) {
        try {
            log.info("Authentication Client");
            log.debug("data: {}", BytesUtils.bytesToHex(data, ' '));
            byte[] dkData = cipherService.decode(data);
            log.debug("dkData: {}", BytesUtils.bytesToHex(dkData, ' '));
            byte[] challengeS = Arrays.copyOfRange(dkData, cipherService.getAlgorithm().getBlocSize(), cipherService.getAlgorithm().getBlocSize() * 2);
            byte[] challengeC = Arrays.copyOfRange(dkData, 0, cipherService.getAlgorithm().getBlocSize());

            log.debug("challenge: {}", BytesUtils.bytesToHex(challenge, ' '));
            log.debug("challengeS: {}", BytesUtils.bytesToHex(challengeS, ' '));
            log.debug("challengeC: {}", BytesUtils.bytesToHex(challengeC, ' '));

            if (Arrays.equals(challengeS, challenge)) {
                randomClient = challengeC;
                return CommandSet.success();
            } else {
                log.debug("challengeS {} != challenge {}", BytesUtils.bytesToHex(challengeS, ' '), BytesUtils.bytesToHex(challenge, ' '));
                return CommandSet.error("Returned challenge not match");
            }

        } catch (GeneralSecurityException e) {
            log.error("Cannot decode challenge", e);
            return CommandSet.error("Cryptographic error");
        }

    }

    protected byte[] authenticateServer(byte[] data) {
        try {
            log.info("Authentication Server");
            log.debug("data {}", BytesUtils.bytesToHex(data, ' '));
            byte[] rndServer = cipherService.random();
            log.debug("rndServer {}", BytesUtils.bytesToHex(rndServer, ' '));
            byte[] ek = cipherService.encode(Bytes.concat(rndServer, data));
            log.debug("ek {}", BytesUtils.bytesToHex(ek, ' '));

            cipherService.setSessionKey(randomClient, rndServer);
            log.info("Authentication succeed");

            return ek;
        } catch (GeneralSecurityException e) {
            log.error("Cannot decode challenge", e);
            return CommandSet.error("Cryptographic error");
        }

    }

    protected void send(byte[] cmd) throws IOException {
        out.write(cmd);
        log.info("Send: {} bytes | {} | {}", cmd.length, BytesUtils.bytesToHex(cmd, ' '), new String(cmd));
    }

    protected byte[] receive() throws IOException {
        byte[] result = new byte[0];
        int count;
        do {
            byte[] frame = new byte[FRAME_SIZE];
            count = in.read(frame);
            result = Bytes.concat(result, Arrays.copyOf(frame, count));
        } while (count >= FRAME_SIZE);
        log.info("Receive: {} bytes | {} | {}", result.length, BytesUtils.bytesToHex(result, ' '), new String(result));
        return result;
    }
}

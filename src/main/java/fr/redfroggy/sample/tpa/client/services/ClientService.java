package fr.redfroggy.sample.tpa.client.services;

import com.google.common.primitives.Bytes;
import fr.redfroggy.sample.tpa.commons.exceptions.AuthenticationException;
import fr.redfroggy.sample.tpa.commons.exceptions.TransmissionException;
import fr.redfroggy.sample.tpa.commons.protocol.CommandSet;
import fr.redfroggy.sample.tpa.commons.services.AbstractCommunicationService;
import fr.redfroggy.sample.tpa.commons.utils.BytesUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Client service
 */
@Slf4j
@Service
public class ClientService extends AbstractCommunicationService {

    @Autowired
    protected Socket socket;

    @Autowired
    protected BufferedReader inFromUser;

    /**
     * Run client communication with server
     */
    public void run() {

        try {
            log.info("Client ready");
            boolean endOfTransmission = false;

            out = new DataOutputStream(socket.getOutputStream());
            in = socket.getInputStream();

            // Authentication
            authenticate();

            // Send message
            log.info("Ready to send message");
            while (!endOfTransmission) {
                String sentence = inFromUser.readLine();

                if (sentence == null || sentence.isEmpty()) {
                    endOfTransmission = true;
                } else {
                    sendMessage(sentence);
                }
            }

            // Close socket
            socket.close();
            log.info("Client shutdown");

        } catch (TransmissionException e) {
            log.error("Transmission error", e);
        } catch (AuthenticationException e) {
            log.error("Authentication failed", e);
        } catch (IOException e) {
            log.error("Socket error", e);
        } catch (Exception e) {
            log.error("Unknown error", e);
        }
    }

    /**
     * Launch authentication process
     *
     * @throws AuthenticationException If process failed
     */
    public void authenticate() throws AuthenticationException {
        log.info("Authentication process");

        try {
            // Client Authentication : Required challenge to server
            byte[] rndS1 = send(CommandSet.getChallenge());
            byte[] rndC1 = cipherService.random();
            log.debug("rndS1: {}", BytesUtils.bytesToHex(rndS1, ' '));
            log.debug("rndC1: {}", BytesUtils.bytesToHex(rndC1, ' '));

            byte[] ek1 = cipherService.encode(Bytes.concat(rndC1, rndS1));
            cipherService.resetIV();
            log.debug("ek1: {}", BytesUtils.bytesToHex(ek1, ' '));

            // Client Authentication : Send challenge response to server
            byte[] c1 = send(CommandSet.authenticateClient(ek1));
            if (c1[0] != CommandSet.Instruction.SUC.getCode()) {
                throw new AuthenticationException("Authentication failed, Client verification mismatch (" + new String(c1).substring(1) + ")");
            }
            log.debug("Client verification success");

            // Server Authentication : Send challenge to server
            byte[] rndC2 = cipherService.random();
            log.debug("rndC2: {}", BytesUtils.bytesToHex(rndC2, ' '));
            byte[] ek2 = send(CommandSet.authenticateServer(rndC2));
            log.debug("ek2: {}", BytesUtils.bytesToHex(ek2, ' '));
            byte[] c2 = cipherService.decode(ek2);
            log.debug("c2: {}", BytesUtils.bytesToHex(c2, ' '));
            cipherService.resetIV();
            byte[] rndS2 = Arrays.copyOfRange(c2, 0, 16);
            byte[] rndC2p = Arrays.copyOfRange(c2, 16, 32);

            log.debug("rndS2: {}", BytesUtils.bytesToHex(rndS2, ' '));
            log.debug("rndC2: {}", BytesUtils.bytesToHex(rndC2, ' '));
            log.debug("rndC2p: {}", BytesUtils.bytesToHex(rndC2p, ' '));

            if (!Arrays.equals(rndC2, rndC2p)) {
                throw new AuthenticationException("Authentication failed, Server verification mismatch");
            }
            log.debug("Server verification success");

            setSessionKey(rndC1, rndS2);
            log.info("Authentication succeed");

        } catch (GeneralSecurityException e) {
            throw new AuthenticationException("Authentication failed", e);
        } catch (IOException e) {
            throw new AuthenticationException("Authentication failed because of transmission error", e);
        }
    }

    /**
     * Send message to server
     *
     * @param msg Message content
     * @throws Exception If an error occurred
     */
    public void sendMessage(String msg) throws Exception {
        byte[] ekMsg = cipherService.encode(msg.getBytes());
        byte[] result = send(CommandSet.sendMessage(ekMsg));

        if (result[0] == CommandSet.Instruction.RCV.getCode()) {
            // Check if checksum is equal
            byte[] crc32ori = BytesUtils.crc32(msg.getBytes());
            byte[] crc32res = Arrays.copyOfRange(result, 1, result.length);

            if (!Arrays.equals(crc32ori, crc32res)) {
                throw new TransmissionException("Message CRC is invalid");
            } else {
                log.debug("CRC valid");
            }

        } else if (result[0] == CommandSet.Instruction.ERR.getCode()) {
            log.error("Server return error : " + new String(result).substring(1));
        } else {
            log.warn("Unexpected result");
        }
    }

}

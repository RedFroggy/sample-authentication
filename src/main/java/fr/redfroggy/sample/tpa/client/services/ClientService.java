package fr.redfroggy.sample.tpa.client.services;

import com.google.common.primitives.Bytes;
import fr.redfroggy.sample.tpa.commons.exceptions.AuthenticationException;
import fr.redfroggy.sample.tpa.commons.protocol.CommandSet;
import fr.redfroggy.sample.tpa.commons.security.CipherService;
import fr.redfroggy.sample.tpa.commons.utils.BytesUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Arrays;

@Slf4j
@Service
@Async
public class ClientService {

    protected static final int FRAME_SIZE = 64;

    @Autowired
    protected Socket socket;

    @Autowired
    protected CipherService cipherService;

    DataOutputStream out;

    InputStream in;

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
            while(!endOfTransmission) {
                BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
                String sentence = inFromUser.readLine();

                if (sentence.isEmpty()) {
                    endOfTransmission = true;
                } else {
                    sendMessage(sentence);
                }
            }

            // Close socket
            socket.close();
            log.info("Client shutdown");

        } catch (AuthenticationException e) {
            log.error("Authentication failed", e);
        } catch (IOException e) {
            log.error("Socket error", e);
        } catch (Exception e) {
            log.error("Unknown error", e);
        }
    }

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

            cipherService.setSessionKey(rndC1, rndS2);
            log.info("Authentication succeed");

        } catch (GeneralSecurityException e) {
            throw new AuthenticationException("Authentication failed", e);
        } catch (IOException e) {
            throw new AuthenticationException("Authentication failed because of transmission error", e);
        }
    }

    public void sendMessage(String msg) throws Exception {
        byte[] toEncode = BytesUtils.pad(msg.getBytes(), cipherService.getAlgorithm().getBlocSize());
        byte[] ekMsg = cipherService.encode(toEncode);
        byte[] result = send(CommandSet.sendMessage(ekMsg));

        if (result[0] == CommandSet.Instruction.RCV.getCode()) {
            // Check if checksum is equal
            byte[] crc32ori = BytesUtils.crc32(msg.getBytes());
            byte[] crc32res = BytesUtils.crc32(Arrays.copyOfRange(result, 1, result.length));

            if (!Arrays.equals(crc32ori, crc32res)) {
                log.debug("CRC valid");
            }

        } else if (result[0] == CommandSet.Instruction.ERR.getCode()) {
            log.error("Server return error : " + new String(result).substring(1));
        } else {
            log.warn("Unexpected result");
        }
    }

    protected byte[] send(byte[] cmd) throws IOException {
        out.write(cmd);
        log.info("Send: {} bytes | {} | {}", cmd.length, BytesUtils.bytesToHex(cmd, ' '), new String(cmd));
        return receive();
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

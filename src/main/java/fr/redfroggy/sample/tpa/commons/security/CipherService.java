package fr.redfroggy.sample.tpa.commons.security;

import com.google.common.primitives.Bytes;
import fr.redfroggy.sample.tpa.commons.utils.BytesUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;

@Slf4j
public class CipherService {

    protected Random randomizer = new Random();

    @Getter
    protected Algorithm algorithm;

    protected Cipher cipher;

    protected byte[] key;

    protected boolean resetIV = true;

    public CipherService(Algorithm algorithm, byte[] key) {
        this.algorithm = algorithm;
        this.key = key;
    }

    public byte[] random() {

        byte[] rndA = new byte[algorithm.getBlocSize()];
        randomizer.nextBytes(rndA);
        return rndA;
    }

    public byte[] encode(byte[] data) throws GeneralSecurityException {
        return cipher(data, Cipher.ENCRYPT_MODE);
    }

    public byte[] decode(byte[] data) throws GeneralSecurityException {
        return cipher(data, Cipher.DECRYPT_MODE);
    }

    public void resetIV() {
        resetIV = true;
    }

    protected byte[] cipher(byte[] data, int type) throws GeneralSecurityException {

        if (cipher == null) {
            cipher = Cipher.getInstance(algorithm.getCipherAlgorithm());
        }
        if (resetIV) {
            cipher.init(type, new SecretKeySpec(key, algorithm.getKeyAlgorithm()), new IvParameterSpec(new byte[key.length]));
        }

        log.debug("******** CIPHER STATUS *********");
        log.debug("| Mode: {}", Cipher.DECRYPT_MODE == type ? "DECRYPT" : "CRYPT");
        log.debug("| Algorithm: {}", cipher.getAlgorithm());
        log.debug("| Key: {}", BytesUtils.bytesToHex(key, ' '));
        log.debug("| IV (Before): {}", BytesUtils.bytesToHex(cipher.getIV(), ' '));
        log.debug("| Input: {}", BytesUtils.bytesToHex(data, ' '));

        byte[] result = cipher.doFinal(data);

        log.debug("| IV (After): {}", BytesUtils.bytesToHex(cipher.getIV(), ' '));
        log.debug("| Output: {}", BytesUtils.bytesToHex(result, ' '));
        log.debug("********************************");

        return result;
    }

    public void setSessionKey(byte[] clientPart, byte[] serverPart) {

        log.debug("Build {} session key", getAlgorithm());
        byte[] session;

        switch (getAlgorithm()) {
            case DES:
                session = Bytes.concat(Arrays.copyOfRange(clientPart, 0, 4), Arrays.copyOfRange(serverPart, 0, 4));
                break;
            case TDES:
                session = Bytes.concat(Arrays.copyOfRange(clientPart, 0, 4), Arrays.copyOfRange(serverPart, 0, 4),
                        Arrays.copyOfRange(clientPart, 4, 8), Arrays.copyOfRange(serverPart, 4, 8));
                break;
            case AES:
                session =Bytes.concat(Arrays.copyOfRange(clientPart, 0, 4), Arrays.copyOfRange(serverPart, 0, 4),
                        Arrays.copyOfRange(clientPart, 12, 16), Arrays.copyOfRange(serverPart, 12, 16));
                break;
            case TKTDES:
                session =Bytes.concat(Arrays.copyOfRange(clientPart, 0, 4), Arrays.copyOfRange(serverPart, 0, 4),
                        Arrays.copyOfRange(clientPart, 6, 10), Arrays.copyOfRange(serverPart, 6, 10),
                        Arrays.copyOfRange(clientPart, 12, 16), Arrays.copyOfRange(serverPart, 12, 16));
                break;
            default:
                session = new byte[0];
                break;
        }

        log.debug("Client random: {}", BytesUtils.bytesToHex(clientPart, ' '));
        log.debug("Server random: {}", BytesUtils.bytesToHex(serverPart, ' '));
        log.debug("Session key is now: {}", BytesUtils.bytesToHex(session, ' '));
        resetIV();
        key = session;
    }
}

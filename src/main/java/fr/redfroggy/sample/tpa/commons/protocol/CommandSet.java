package fr.redfroggy.sample.tpa.commons.protocol;

public class CommandSet {

    public enum Instruction {
        CLG((byte) 0x13),
        AUS((byte) 0x11),
        AUC((byte) 0x12),
        STP((byte) 0xFF),
        MSG((byte) 0x20),
        RCV((byte) 0x30),
        SUC((byte) 0xE0),
        ERR((byte) 0xF0),
        UKW((byte) 0x00);

        private byte code;

        Instruction(byte code) {
            this.code = code;
        }

        public byte getCode() {
            return code;
        }

        public static Instruction get(byte code) {
            for(Instruction ins : Instruction.values()) {
                if (code == ins.getCode()) {
                    return ins;
                }
            }
            return UKW;
        }
    }

    /**
     * Get stop command
     *
     * @return Stop command
     */
    public static byte[] stop() {
        return new byte[] { Instruction.STP.getCode() };
    }

    /**
     * Get challenge command
     *
     * @return Challenge command
     */
    public static byte[] getChallenge() {
        return new byte[] { Instruction.CLG.getCode() };
    }

    /**
     * Get server authentication command
     *
     * @return Server authentication
     */
    public static byte[] authenticateServer(byte[] auth) {
        byte[] cmd = new byte[auth.length + 1];
        cmd[0] = Instruction.AUS.getCode();
        System.arraycopy(auth, 0, cmd, 1, auth.length);
        return cmd;
    }

    /**
     * Get client authentication command
     *
     * @return Client authentication
     */
    public static byte[] authenticateClient(byte[] auth) {
        byte[] cmd = new byte[auth.length + 1];
        cmd[0] = Instruction.AUC.getCode();
        System.arraycopy(auth, 0, cmd, 1, auth.length);
        return cmd;
    }

    /**
     * Get message command
     *
     * @return Message command
     */
    public static byte[] sendMessage(byte[] message) {
        byte[] cmd = new byte[message.length + 1];
        cmd[0] = Instruction.MSG.getCode();
        System.arraycopy(message, 0, cmd, 1, message.length);
        return cmd;
    }

    /**
     * Get receive command
     *
     * @return Receive command
     */
    public static byte[] receive(byte[] crc) {
        byte[] cmd = new byte[crc.length + 1];
        cmd[0] = Instruction.RCV.getCode();
        System.arraycopy(crc, 0, cmd, 1, crc.length);
        return cmd;
    }

    /**
     * Get success command
     *
     * @return Success command
     */
    public static byte[] success() {
        return new byte[] { Instruction.SUC.getCode() };
    }

    /**
     * Get error command
     *
     * @return Error command
     */
    public static byte[] error(String detail) {
        byte[] cmd = new byte[detail.length() + 1];
        cmd[0] = Instruction.ERR.getCode();
        System.arraycopy(detail.getBytes(), 0, cmd, 1, detail.getBytes().length);
        return cmd;
    }
}

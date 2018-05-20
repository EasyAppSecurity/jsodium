package net.easyappsec.sodium.util;

import java.util.ArrayList;

public class BytesUtil {

    private BytesUtil() {
    }

    public static byte[] bytes(ArrayList<Byte> data) {
        byte[] bytes = new byte[data.size()];
        for (int i = 0; i < data.size(); i++)
            bytes[i] = data.get(i);

        return bytes;
    }

}

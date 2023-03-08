package com.ryan.utils;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DHUtils {
    public static String generateStringSharedKey(String privateKey, String publicKey) {
        try {

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            PrivateKey privateKeyObj = convertByteArrayToPrivateKey(convertStringtoByteArray(privateKey));
            keyAgreement.init(privateKeyObj);
            byte[] bytePublicKey = Base64.getDecoder().decode(publicKey);
            PublicKey publicKeyObj = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(bytePublicKey));
            keyAgreement.doPhase(publicKeyObj, true);
            byte[] byteSharedSecret = keyAgreement.generateSecret();
            return  Base64.getEncoder().encodeToString(byteSharedSecret);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static byte[] generateSharedKey(String privateKey, String publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            PrivateKey privateKeyObj = convertByteArrayToPrivateKey(convertStringtoByteArray(privateKey));
            keyAgreement.init(privateKeyObj);
            byte[] bytePublicKey = Base64.getDecoder().decode(publicKey);
            PublicKey publicKeyObj =  convertByteArrayToPublicKey(convertStringtoByteArray(publicKey));
            keyAgreement.doPhase(publicKeyObj, true);
            return keyAgreement.generateSecret();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] convertStringtoByteArray (String key) {
        return Base64.getDecoder().decode(key);
    }

    public static PrivateKey convertByteArrayToPrivateKey(byte[] array) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(array);
        return keyFactory.generatePrivate(privateKeySpec);

    }

    public static PublicKey convertByteArrayToPublicKey(byte[] array) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(array);
        return keyFactory.generatePublic(publicKeySpec);
    }
}

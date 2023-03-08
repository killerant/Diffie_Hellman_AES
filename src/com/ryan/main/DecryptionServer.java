package com.ryan.main;

import java.security.*;

public class DecryptionServer {
    private PublicKey decryptionPublicKey;
    private PrivateKey decryptionPrivateKey;

    public DecryptionServer() {
        try {
            // Generate a new key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get the public and private keys from the key pair
            decryptionPublicKey = keyPair.getPublic();
            decryptionPrivateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public PublicKey getDecryptionPublicKey() {
        return decryptionPublicKey;
    }

    public PrivateKey getDecryptionPrivateKey() {
        return decryptionPrivateKey;
    }
}

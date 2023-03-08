package com.ryan.main;

import java.security.*;

public class EncryptionServer {
    private PublicKey encryptionPublicKey;
    private PrivateKey encryptionPrivateKey;

    public EncryptionServer(){
        try{
            // Generate a new key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get the public and private keys from the key pair
            encryptionPublicKey = keyPair.getPublic();
            encryptionPrivateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public PublicKey getEncryptionPublicKey() {
        return encryptionPublicKey;
    }

    public PrivateKey getEncryptionPrivateKey() {
        return encryptionPrivateKey;
    }
}

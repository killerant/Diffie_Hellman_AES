package com.ryan.main;

import java.security.*;
import java.util.Base64;

public class AppServer {
    private PublicKey appServerPublicKey;
    private PrivateKey appServerPrivateKey;

    public AppServer() {
        try {
            // Generate a new key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get the public and private keys from the key pair
            appServerPublicKey = keyPair.getPublic();
            appServerPrivateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public PublicKey getAppServerPublicKey() {
        return appServerPublicKey;
    }

    public PrivateKey getAppServerPrivateKey() {
        return appServerPrivateKey;
    }

    public String getStringAppServerPublicKey() {
        return Base64.getEncoder().encodeToString(appServerPublicKey.getEncoded());
    }

    public String getStringAppServerPrivateKey() {
        return Base64.getEncoder().encodeToString(appServerPrivateKey.getEncoded());
    }
}

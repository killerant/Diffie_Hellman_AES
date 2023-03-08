package com.ryan.main;

import com.ryan.enc.AESUtility;
import com.ryan.utils.DHUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.Provider;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Base64;

public class DiffieHellManMain {
    public static void main(String[] args) throws Exception {

        // List the available providers
        Provider[] providers = Security.getProviders();
        int ctr = 1;
        for (Provider provider : providers) {
            System.out.println("Provider " + ctr + ":" + provider.getName());
            ctr++;
        }

        // Add new providersjava -
        Security.addProvider(new BouncyCastleProvider());

        // List the available providers
        providers = Security.getProviders();
        ctr = 1;
        for (Provider provider : providers) {
            System.out.println("Provider " + ctr + ":" + provider.getName());
            ctr++;
        }

        ISeries iSeriesInstance = new ISeries();
        String iSeriesPrivateKey = iSeriesInstance.getStringISeriesPrivateKey();
        String iSeriesPublicKey = iSeriesInstance.getStringISeriesPublicKey();

        AppServer appServerInstance = new AppServer();
        String appServerPrivateKey = appServerInstance.getStringAppServerPrivateKey();
        String appServerPublicKey = appServerInstance.getStringAppServerPublicKey();

        // Generate Shared Keys
        String sharedKey1 = DHUtils.generateStringSharedKey(iSeriesPrivateKey, appServerPublicKey);
        String sharedKey2 = DHUtils.generateStringSharedKey(appServerPrivateKey, iSeriesPublicKey);

        // Print the shared keys
        System.out.println("Shared Key 1: " + sharedKey1);
        System.out.println("Shared Key 2: " + sharedKey2);
        System.out.println("Are shared key 1 and shared key 2 equal? ===> " + sharedKey1.equals(sharedKey2));

        // Convert the shared key 1 to a SecretKey
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec1 = new PBEKeySpec(sharedKey1.toCharArray(), "salt".getBytes(), 1000, 128);
        SecretKey aesSecretKey1 = keyFactory.generateSecret(keySpec1);

        // Encrypt the password
        String password = args[0];
        System.out.println("Password before encryption is :::  " + password);
        IvParameterSpec ivParameterSpec = AESUtility.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";
        String cipherText = AESUtility.encrypt(algorithm, password, aesSecretKey1, ivParameterSpec);
        System.out.println("Encrypted password is ::: " + cipherText);


        // Convert the shared key 2 to a SecretKey
        SecretKeyFactory keyFactory2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec2 = new PBEKeySpec(sharedKey2.toCharArray(), "salt".getBytes(), 1000, 128);
        SecretKey aesSecretKey2 = keyFactory.generateSecret(keySpec2);

        // Decrypt the password
        String plainText = AESUtility.decrypt(algorithm, cipherText, aesSecretKey2, ivParameterSpec);
        System.out.println("Decrypted password is :::" + plainText);

    }

}

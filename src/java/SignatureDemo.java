// SignatureDemo.java — JCA signature and cipher usage, weak to modern.
// Expected CBOM: MD5withRSA (CRITICAL), SHA1withRSA (deprecated),
// SHA256withRSA / SHA384withECDSA (modern signatures), DESede (3DES),
// AES/GCM/NoPadding (modern AEAD).
package com.precogs.menagerie;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;

public class SignatureDemo {

    // MD5withRSA — broken hash under an RSA signature.
    static byte[] signMd5Rsa(byte[] data, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("MD5withRSA");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    // SHA1withRSA — deprecated signature algorithm.
    static byte[] signSha1Rsa(byte[] data, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("SHA1withRSA");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    // SHA256withRSA — modern signature.
    static byte[] signSha256Rsa(byte[] data, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    // SHA384withECDSA — modern EC signature.
    static byte[] signEcdsa(byte[] data, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("SHA384withECDSA");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    // DESede (Triple-DES) — deprecated symmetric cipher.
    static byte[] tripleDes(byte[] data, Key key) throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    // AES/GCM/NoPadding — modern authenticated cipher.
    static byte[] aesGcm(byte[] data, Key key, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(data);
    }

    static Key aesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }
}

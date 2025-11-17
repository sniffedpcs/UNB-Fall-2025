// CryptAnalysis Class
// RSA and Hybrid Encryption Implementation
// Date: 17th November 2025

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;

public class RSACrypto {
    
    // RSA parameters from the assignment
    static final BigInteger p = new BigInteger(
        "15554903035303856344007671063568213071669822184616101992595534860863803506262760067615727000088295330493705796902296102481798240988227195060316199080930616035532980617309644098719341753037782435645781436420697261984870969742096465765855782491538043554917285285471407866976465359446400695692459955929581561107496250057761324472438514351159746606737260676765872636140119669971105314539393270612398055538928361845237237855336149792618908050931870177925910819318623"
    );
    
    static final BigInteger q = new BigInteger(
        "15239930048457525970295803203207379514343031714151154517998415248470711811442956493342175286216470497855132510489015253513519073889825927436792580707512051299817290925038739023722366499292196400002204764665762114445764643179358348705750427753416977399694184804769596469561594013716952794631383872745339020403548881863215482480719445814165242627056637786302612482697923973303250588684822021988008175106735736411689800380179302347354882715496632291069525885653297"
    );
    
    static BigInteger n;
    static BigInteger phi;
    static BigInteger e;
    static BigInteger d;
    
    // Method to compute GCD
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }
    
    // Key Generation
    public static void generateKeys() {
        System.out.println("=== RSA KEY GENERATION ===\n");
        
        // Step 1: Compute n = p * q
        n = p.multiply(q);
        System.out.println("Computed n = p * q");
        
        // Step 2: Compute phi(n) = (p-1)(q-1)
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        System.out.println("Computed phi(n) = (p-1)(q-1)");
        
        // Step 3: Generate e such that gcd(e, phi) = 1
        SecureRandom random = new SecureRandom();
        e = BigInteger.valueOf(65537); // Common choice for e
        
        // Verify gcd(e, phi) = 1
        if (!gcd(e, phi).equals(BigInteger.ONE)) {
            // If 65537 doesn't work, find another e
            e = new BigInteger(16, random);
            while (!gcd(e, phi).equals(BigInteger.ONE) || e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0) {
                e = new BigInteger(16, random);
            }
        }
        System.out.println("Chosen exponent e = " + e);
        
        // Step 4: Compute d = e^(-1) mod phi
        d = e.modInverse(phi);
        System.out.println("Computed private exponent d");
        
        System.out.println("\nPublic Key: (e, n)");
        System.out.println("Private Key: (d, p, q)\n");
    }
    
    // RSA Encryption
    public static BigInteger encrypt(BigInteger message, BigInteger e, BigInteger n) {
        return message.modPow(e, n);
    }
    
    // Naive RSA Decryption
    public static BigInteger decryptNaive(BigInteger ciphertext, BigInteger d, BigInteger n) {
        return ciphertext.modPow(d, n);
    }
    
    // CRT-based RSA Decryption
    public static BigInteger decryptCRT(BigInteger c) {
        // Compute q' = q^(-1) mod p
        BigInteger qPrime = q.modInverse(p);
        
        // Compute p' = p^(-1) mod q
        BigInteger pPrime = p.modInverse(q);
        
        // Compute dp = d mod (p-1)
        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        
        // Compute dq = d mod (q-1)
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
        
        // Compute cp = c mod p
        BigInteger cp = c.mod(p);
        
        // Compute cq = c mod q
        BigInteger cq = c.mod(q);
        
        // Compute mp = cp^dp mod p
        BigInteger mp = cp.modPow(dp, p);
        
        // Compute mq = cq^dq mod q
        BigInteger mq = cq.modPow(dq, q);
        
        // Compute m = mp * q * q' + mq * p * p' mod n
        BigInteger term1 = mp.multiply(q).multiply(qPrime);
        BigInteger term2 = mq.multiply(p).multiply(pPrime);
        BigInteger m = term1.add(term2).mod(n);
        
        return m;
    }
    
    // Task A1: RSA Implementation
    public static void taskA1() {
        System.out.println("\n========================================");
        System.out.println("TASK A1: RSA IMPLEMENTATION");
        System.out.println("========================================\n");
        
        // Generate keys
        generateKeys();
        
        // Generate random message
        SecureRandom random = new SecureRandom();
        BigInteger message = new BigInteger(n.bitLength() - 1, random).mod(n);
        while (message.compareTo(BigInteger.ZERO) <= 0) {
            message = new BigInteger(n.bitLength() - 1, random).mod(n);
        }
        
        System.out.println("----------------------------");
        System.out.println("Chosen message is m = " + message);
        System.out.println("Chosen exponent is e = " + e);
        
        // Encryption
        BigInteger ciphertext = encrypt(message, e, n);
        System.out.println("Ciphertext is c = " + ciphertext);
        
        // Naive Decryption with timing
        long startNaive = System.nanoTime();
        BigInteger decryptedNaive = decryptNaive(ciphertext, d, n);
        long endNaive = System.nanoTime();
        double timeNaive = (endNaive - startNaive) / 1_000_000.0; // Convert to milliseconds
        
        System.out.println("\nDecrypted message using the c^d mod n decryption is m = " + decryptedNaive);
        System.out.println("Computation time of the c^d mod n decryption is = " + timeNaive + " ms");
        
        // CRT Decryption with timing
        long startCRT = System.nanoTime();
        BigInteger decryptedCRT = decryptCRT(ciphertext);
        long endCRT = System.nanoTime();
        double timeCRT = (endCRT - startCRT) / 1_000_000.0; // Convert to milliseconds
        
        System.out.println("\nDecrypted message using the CRT decryption m = " + decryptedCRT);
        System.out.println("Computation time of the CRT-based RSA decryption is = " + timeCRT + " ms");
        
        // Verify correctness
        System.out.println("\nVerification:");
        System.out.println("Naive decryption matches original: " + decryptedNaive.equals(message));
        System.out.println("CRT decryption matches original: " + decryptedCRT.equals(message));
        System.out.println("Speedup factor: " + (timeNaive / timeCRT) + "x");
        System.out.println("----------------------------");
    }
    






    // Task A2: Hybrid Encryption
    public static void taskA2() {
        System.out.println("\n========================================");
        System.out.println("TASK A2: HYBRID ENCRYPTION");
        System.out.println("========================================\n");
        
        try {
            // Generate 1 MB of random data for message M
            byte[] M = new byte[1024 * 1024]; // 1 MB
            Random random = new Random();
            random.nextBytes(M);
            
            // Generate random 256-bit (32 byte) AES key
            byte[] aesKey = new byte[32];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(aesKey);
            
            System.out.println("----------------------------");
            System.out.println("The AES key in hex K: " + bytesToHex(aesKey));
            System.out.println("First 32 bytes of M: " + bytesToHex(M, 32));
            
            // Step 1: Encrypt AES key using PKCS#1 OAEP RSA
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            
            // Create RSA public key
            java.security.spec.RSAPublicKeySpec pubKeySpec = 
                new java.security.spec.RSAPublicKeySpec(n, e);
            java.security.PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
            
            // Create RSA private key
            java.security.spec.RSAPrivateKeySpec privKeySpec = 
                new java.security.spec.RSAPrivateKeySpec(n, d);
            java.security.PrivateKey privateKey = keyFactory.generatePrivate(privKeySpec);
            
            // Encrypt AES key with RSA-OAEP
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, 
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            byte[] Crsa = rsaCipher.doFinal(aesKey);
            
            System.out.println("\nPrinting C_rsa: " + bytesToHex(Crsa));
            
            // Step 2: Encrypt message M using AES-GCM
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
            
            // Generate random IV for GCM (12 bytes is standard)
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, gcmSpec);
            byte[] Caes = aesCipher.doFinal(M);
            
            System.out.println("First 32 bytes of C_aes: " + bytesToHex(Caes, 32));
            
            // Step 3: Decrypt AES key using RSA-OAEP
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            byte[] decryptedKey = rsaCipher.doFinal(Crsa);
            
            System.out.println("\nDecrypted AES key K: " + bytesToHex(decryptedKey));
            
            // Step 4: Decrypt message using AES-GCM
            SecretKeySpec decryptedKeySpec = new SecretKeySpec(decryptedKey, "AES");
            aesCipher.init(Cipher.DECRYPT_MODE, decryptedKeySpec, gcmSpec);
            byte[] decryptedM = aesCipher.doFinal(Caes);
            
            System.out.println("Decrypted first 32 bytes of M: " + bytesToHex(decryptedM, 32));
            
            // Verify correctness
            System.out.println("\nVerification:");
            System.out.println("AES key matches: " + bytesToHex(aesKey).equals(bytesToHex(decryptedKey)));
            System.out.println("Message M matches: " + java.util.Arrays.equals(M, decryptedM));
            System.out.println("----------------------------");
            
        } catch (Exception ex) {
            System.err.println("Error in hybrid encryption: " + ex.getMessage());
            ex.printStackTrace();
        }
    }
    
    // Helper method to convert bytes to hex string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    // Helper method to convert first n bytes to hex string
    public static String bytesToHex(byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(length, bytes.length); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }
    
    // Main method
    public static void main(String[] args) {
        System.out.println("Programming Assignment 1");

        // Run Task A1
        taskA1();
        
        // Run Task A2
        taskA2();
        
        System.out.println("\n========================================");
        System.out.println("PROGRAM COMPLETED SUCCESSFULLY");
        System.out.println("========================================");
    }
}

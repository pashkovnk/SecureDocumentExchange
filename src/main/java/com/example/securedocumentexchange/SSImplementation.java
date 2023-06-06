package com.example.securedocumentexchange;

import com.example.securedocumentexchange.security.SecurityService;
import com.sshtools.common.publickey.InvalidPassphraseException;
import com.sshtools.common.publickey.SshKeyUtils;
import com.sshtools.common.ssh.components.SshPublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class SSImplementation implements SecurityService {
    @Override
    public String encryptMessage(String message, File publicKeyFile) throws IOException, GeneralSecurityException {
        // Генерация ключа AES
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey aesKey = keyGenerator.generateKey();

        // Создание вектора инициализации
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Получение открытого ключа из файла
        SshPublicKey sshPublicKey = SshKeyUtils.getPublicKey(publicKeyFile);
        PublicKey publicKey = sshPublicKey.getJCEPublicKey();

        // Шифрование ключа AES с помощью RSA
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Шифрование сообщения AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        int blockSize = 256 / 8; // Размер блока в байтах
        byte[] messageBytes = message.getBytes();
        int paddedLength = ((messageBytes.length / blockSize) + 1) * blockSize;
        byte[] paddedMessage = new byte[paddedLength];
        System.arraycopy(messageBytes, 0, paddedMessage, 0, messageBytes.length);
        byte[] encryptedMessage = aesCipher.doFinal(paddedMessage);

        // Формирование зашифрованного сообщения
        byte[] encryptedOutput = new byte[iv.length + encryptedAesKey.length + encryptedMessage.length];
        System.arraycopy(iv, 0, encryptedOutput, 0, iv.length);
        System.arraycopy(encryptedAesKey, 0, encryptedOutput, iv.length, encryptedAesKey.length);
        System.arraycopy(encryptedMessage, 0, encryptedOutput, iv.length + encryptedAesKey.length, encryptedMessage.length);

        // Вывод зашифрованного сообщения
        return Base64.getEncoder().encodeToString(encryptedOutput);
    }

    @Override
    public String decryptMessage(String encryptedMessage, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        // Подготовка зашифрованного сообщения к дальнейшей обработке
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, 16);
        byte[] encryptedAesKey = Arrays.copyOfRange(encryptedBytes, 16, 16 + 512);
        byte[] encryptedMessageBytes = Arrays.copyOfRange(encryptedBytes, 16 + 512, encryptedBytes.length);

        // Получение закрытого ключа из файла
        PrivateKey privateKey = SshKeyUtils.getPrivateKey(privateKeyFile, "").getPrivateKey().getJCEPrivateKey();

        // Расшифрование ключа AES с помощью RSA
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);

        // Дешифрование сообщения AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decryptedMessageBytes = aesCipher.doFinal(encryptedMessageBytes);

        // Вывод дешифрованного сообщения
        return new String(decryptedMessageBytes).trim();
    }

    @Override
    public void encryptDocument(File document, File openKey) throws IOException, GeneralSecurityException {
        // Получение данных из файла
        FileInputStream fileInputStream = new FileInputStream(document);
        byte[] message = fileInputStream.readAllBytes();
        fileInputStream.close();

        // Генерация ключа AES
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey aesKey = keyGenerator.generateKey();

        // Создание вектора инициализации
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Получение открытого ключа
        SshPublicKey sshPublicKey = SshKeyUtils.getPublicKey(openKey);
        PublicKey publicKey = sshPublicKey.getJCEPublicKey();

        // Шифрование ключа AES с помощью RSA
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Шифрование сообщения AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        int blockSize = 256 / 8;
        int paddedLength = ((message.length / blockSize) + 1) * blockSize;
        byte[] paddedMessage = new byte[paddedLength];
        System.arraycopy(message, 0, paddedMessage, 0, message.length);
        byte[] encryptedMessage = aesCipher.doFinal(paddedMessage);

        // Формирование зашифрованных данных
        byte[] encryptedOutput = new byte[iv.length + encryptedAesKey.length + encryptedMessage.length];
        System.arraycopy(iv, 0, encryptedOutput, 0, iv.length);
        System.arraycopy(encryptedAesKey, 0, encryptedOutput, iv.length, encryptedAesKey.length);
        System.arraycopy(encryptedMessage, 0, encryptedOutput, iv.length + encryptedAesKey.length, encryptedMessage.length);

        // Вывод зашифрованного содержимого исходного файла в новый с расширением .sde
        String encryptedDocName = document.getName() + ".sde";
        FileOutputStream fileOutputStream = new FileOutputStream(encryptedDocName);
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
        bufferedOutputStream.write(encryptedOutput);
        bufferedOutputStream.close();
        fileOutputStream.close();
    }

    @Override
    public void decryptDocument(File document, File secretKey) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        // Получение зашифрованных данных из файла
        byte[] encryptedBytes;
        try (FileInputStream inputStream = new FileInputStream(document)) {
            encryptedBytes = new byte[(int) document.length()];
            inputStream.read(encryptedBytes);
        }
        // Подготовка зашифрованных данных к дальнейшей обработке
        byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, 16);
        byte[] encryptedAesKey = Arrays.copyOfRange(encryptedBytes, 16, 16 + 512);
        byte[] encryptedMessageBytes = Arrays.copyOfRange(encryptedBytes, 16 + 512, encryptedBytes.length);

        // Получение закрытого ключа
        PrivateKey privateKey = SshKeyUtils.getPrivateKey(secretKey, "").getPrivateKey().getJCEPrivateKey();

        // Расшифрование ключа AES с помощью RSA
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);

        // Дешифрование сообщения AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decryptedMessageBytes = aesCipher.doFinal(encryptedMessageBytes);

        // Вывод дешифрованных данных в файл с тем же именем и расширением до шифрования
        String decryptedDocOutput = new String(decryptedMessageBytes).trim();
        String decryptedDocName = document.getName().replace(".sde", "");
        FileOutputStream fileOutputStream = new FileOutputStream(decryptedDocName);
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
        bufferedOutputStream.write(decryptedDocOutput.getBytes());
        bufferedOutputStream.close();
        fileOutputStream.close();
    }

    @Override
    public void signDocument(File document, File privateKey) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        // Получение закрытого ключа и инициализация объекта класса Signature
        PrivateKey privateKeyFromFile = SshKeyUtils.getPrivateKey(privateKey, "").getPrivateKey().getJCEPrivateKey();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKeyFromFile);

        // Получение данных из файла и присвоение им цифровой подписи
        FileInputStream fileInputStream = new FileInputStream(document);
        byte[] documentBytes = fileInputStream.readAllBytes();
        fileInputStream.close();
        signature.update(documentBytes);
        byte[] signatureBytes = signature.sign();

        // Создание файла цифровой подписи
        File signatureFile = new File(document.getAbsolutePath() + ".sig");
        FileOutputStream fileOutputStream = new FileOutputStream(signatureFile);
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
        bufferedOutputStream.write(signatureBytes);
        bufferedOutputStream.close();
        fileOutputStream.close();
    }

    @Override
    public boolean verifyDocument(File document, File signFile, File publicKey) throws IOException, GeneralSecurityException {
        // Получение открытого ключа и инициализация объекта класса Signature
        PublicKey publicKeyFromFile = SshKeyUtils.getPublicKey(publicKey).getJCEPublicKey();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKeyFromFile);

        // Получение данных из файла и файла цифровой подписи
        FileInputStream fileInputStream = new FileInputStream(document);
        FileInputStream fileInputStreamForSign = new FileInputStream(signFile);
        byte[] documentBytes = fileInputStream.readAllBytes();
        byte[] signBytes = fileInputStreamForSign.readAllBytes();
        fileInputStream.close();
        fileInputStreamForSign.close();

        // Проверка цифровой подписи
        signature.update(documentBytes);
        return signature.verify(signBytes);
    }
}

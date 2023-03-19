import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.InputMismatchException;
import java.util.Scanner;

public class Cipher {


    //==============DEFAULT VALUES===============
    private ArrayList<String> textList;
    private ArrayList<String> cipherList;
    private String fileName = "";
    private String key = "";

    //=========VALUES FOR CONFIGURATIONS=========
    public static final String cipher_value = "AES/CBC/PKCS5Padding";
    public static final String specification_key = "AES";
    public static final int bits_represented_by_bites = 8;
    public static final int small_key_bits = 128;
    public static final int medium_key_bits = 192;
    public static final int big_key_bits = 256;

    //=================EXCEPTIONS================
    public static final String encrypted = "Encrypt";
    public static final String decrypted = "Decrypt";
    public static final String wrong_key_size = " (Encoded Base64) Key is required for 128, 192, or 256";


    //================CONSTRUCTORS================
    public Cipher(String fName, String passwordValue) {
        this.cipherList = new ArrayList<>();
        this.fileName = fName;
        this.key = passwordValue;

        if (fName.equalsIgnoreCase("originaltext")) {
            loadOriginalMessageAndEncrypt(this.fileName);
        } else {
            loadCipherTextDecrypt(this.fileName);
        }
    }
    public Cipher(String filename) {
        this.fileName = filename;
        this.textList = new ArrayList<>();
        loadOriginalMessageFromFile(this.fileName);
    }

    //======================ENCRYPTION=======================

    public static boolean ValidKeyValue(byte[] key) {

        //===========PASSING BYTES TO BIT COUNT===============
        int keyValueLengthBits = key.length * bits_represented_by_bites;

        // ==CHECKING IF THE BIT COUNT IS CORRECT FOR AN AES KEY VALUE===

        return keyValueLengthBits == small_key_bits
                || keyValueLengthBits == medium_key_bits
                || keyValueLengthBits == big_key_bits;
    }

    //========DISPLAYING THE MESSAGE FROM THE FILE===========
    public void displayMessageFromFile() {
        for (String cipher1 : textList)
            System.out.println(cipher1);
    }

    //=======DISPLAYING THE WHOLE MESSAGE FROM THE FILE======
    public void displayCiphertext() {
        for (String cipher2 : cipherList)
            System.out.println(cipher2);
    }

    //====LOAD AND DISPLAY ORIGINAL MESSAGE FROM THE FILE====
    public void loadOriginalMessageFromFile(String fileName) {
        Scanner scanner = null;
        try {
            scanner = new Scanner(new File(fileName));
            scanner.useDelimiter("\n");

            while (scanner.hasNext()) {

                String PlainMessage = scanner.nextLine();

                textList.add(PlainMessage);

            }
            System.out.println("\n=============================ORIGINAL MESSAGE======================================");
            displayMessageFromFile();
            System.out.println("===================================================================================");

        }
        // ===CATCHING AN ERROR MESSAGE IF THE FILE NOT FOUND IT===
        catch (FileNotFoundException e) {
            System.out.println("The File is Not Found it.");
            System.exit(1);
        }
        //=====RUNNING FINALLY IF THE FILE IS FOUND AND INFORMATION IS LOADED.
        catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (scanner != null) {
                System.out.println("Original message it was saved in the file");
                scanner.close();
            }
        }
    }

    //SAVE AND DECRYPT THE ORIGINAL MESSAGE
    public void loadOriginalMessageAndEncrypt(String fileName) {
        Scanner scanner = null;
        try {

            scanner = new Scanner(new File(fileName));
            scanner.useDelimiter("\n");

            while (scanner.hasNext()) {

                String OriginalMessage = scanner.nextLine();

                String cipherText = encryptString(OriginalMessage, key);

                System.out.println("\n=============================================================================== ENCRYPTED TEXT================================================================================");
                System.out.println("ENCRYPTED TEXT: " + cipherText + " " + "\nENCRYPTION KEY: " + key + " ");
                System.out.println("==============================================================================================================================================================================");
                addToFileChipher(cipherText);
            }
        }
        // ===CATCHING AN ERROR MESSAGE IF THE FILE NOT FOUND IT===
        catch (FileNotFoundException e) {
            System.out.println("File Not Found");
            System.exit(1);
        }
        //=====RUNNING FINALLY IF THE FILE IS FOUND AND INFORMATION IS LOADED.
        catch (Exception e) {
            e.printStackTrace();
        } finally {

            if (scanner != null) {
                scanner.close();
            }
        }
    }

    //====LOADING THE CIPHERTEXT TO THE FILE====
    public void addToFileChipher(String data) throws IOException {
        FileWriter writer = new FileWriter("ciphertext");

        writer.append(data + "\n");
        writer.close();
        System.out.println("The text is loaded into the ciphertext file\n");

    }

    //====SAVING THE TEXT IN THE CIPHERTEXT FILE AND DECRYPT IT====
    public void loadCipherTextDecrypt(String fileName) {

        Scanner scanner = null;
        try {

            scanner = new Scanner(new File(fileName));
            scanner.useDelimiter("\n");

            while (scanner.hasNext()) {

                String CipherText = scanner.nextLine();

                System.out.println("\n=============================================================================CIPHER TEXT =====================================================================================");
                System.out.println("ENCRYPTED TEXT: " + CipherText + "");
                System.out.println("==============================================================================================================================================================================");

                String plainText = decryptString(CipherText, key);

                System.out.println("\n=============================================== PLAIN TEXT==================================================");
                System.out.println("DECRYPTED TEXT: " + plainText + "");
                System.out.println("============================================================================================================");
                addTextToFIlePlain(plainText);

            }

        }
        // ===CATCHING AN ERROR MESSAGE IF THE FILE NOT FOUND IT===
        catch (FileNotFoundException e) {
            System.out.println("File Not Found");
            System.exit(1);
        }
        //=====RUNNING FINALLY IF THE FILE IS FOUND AND INFORMATION IS LOADED.
        catch (Exception e) {
            e.printStackTrace();
        } finally {

            if (scanner != null) {
                System.out.println("The File is Saved");
                scanner.close();
            }
        }
    }

    //====LOADED DECRYPTED DATA INTO PLAINTEXT FILE====
    public void addTextToFIlePlain(String data) throws IOException {
        FileWriter writer = new FileWriter("plaintext");
        writer.append(data + "\n");
        writer.close();
        System.out.println("The message is loaded inside the PlainText file\n");

    }

    // =========ENCRYPTION UTILITIES============
    public static String encryptString(String plaintext, String base64Key) {

        //====DECODING THE BASE64 AND ENCODING THE KEY VALUE INTO BYTES====
        byte[] decodedKeyBytes = Base64.getDecoder().decode(base64Key);

        //===============VERIFY IF THE KEY IS A USEFUL LENGTH==============
        if (!Cipher.ValidKeyValue(decodedKeyBytes)) {
            throw new CipherException(wrong_key_size);
        }

        try {

            //=====CREATING A SPECIFICATION OBJECT`S KEY===
            SecretKey secret = new SecretKeySpec(decodedKeyBytes, specification_key);

            // =========START THE CIPHER ALGORITHM=========
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(cipher_value);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secret);

            // =====EXTRACTING THE BLOCK FROM THE VECTOR====
            byte[] ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

            // =========ENCRYPTING THE PLAINTEXT============
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

            //=====ENCODING-BASE64 INITIALISE THE VECTOR AND THE CIPHERTEXT BYTES====
            return Base64.getEncoder().encodeToString(ivBytes)
                    + "|"
                    + Base64.getEncoder().encodeToString(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | InvalidParameterSpecException e) {
            throw new CipherException(decrypted + e.getMessage());
        }
    }

    // =========DECRYPTION UTILITIES============

    public static String decryptString(String CipherText, String base64Key) {

        //====DECODING THE BASE64 AND ENCODING THE KEY VALUE INTO BYTES====
        byte[] decodedKeyBytes = Base64.getDecoder().decode(base64Key);

        //===============VERIFY IF THE KEY IS A USEFUL LENGTH==============
        if (!Cipher.ValidKeyValue(decodedKeyBytes)) {
            throw new CipherException(wrong_key_size);
        }
        try {
            //====DECODING THE BASE64 FROM STRING INTO THE VECTOR AND THE CIPHERTEXT BYTES===
            String[] cipherTextParts = CipherText.split("\\|");
            byte[] ivBytes = Base64.getDecoder().decode(cipherTextParts[0]);
            byte[] ciphertextBytes = Base64.getDecoder().decode(cipherTextParts[1]);

            //=====CREATING A SPECIFICATION OBJECT`S KEY===
            SecretKey secret = new SecretKeySpec(decodedKeyBytes, specification_key);

            // =========START THE CIPHER ALGORITHM=========
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(cipher_value);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));

            //=====DECODING AND RETURNING THE PLAINTEXT MESSAGE======
            String plaintext = new String(cipher.doFinal(ciphertextBytes));
            return plaintext;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CipherException(decrypted + e.getMessage());
        }
    }

    @Override
    public String toString() {
        return "Cipher{" +
                "textList=" + textList +
                ", fileName='" + fileName + '\'' +
                ", key='" + key + '\'' +
                '}';
    }

}

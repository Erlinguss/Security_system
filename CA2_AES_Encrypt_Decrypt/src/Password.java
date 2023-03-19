import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Password {

    //==============DEFAULT VALUES===============
    public static final String Key_type = "PBKDF2WithHmacSHA512";
    public static final int Iterations = 65536;
    public static final int Key_length = 256;
    public static final int Salt_Bites = 32;

    //=================EXCEPTIONS=================
    public static final String Algorithm_Error = "Wrong algorithm";
    public static final String Specifications_Error = "Wrong key specification";

    //============= INSTANCES OF VARIABLES===============
    private String password;
    private String salt;

    //=====GENERATE A RANDOM SALT VALUE AS A BASE64 ENCODING STRING=====

    /**
     * TODO @return A random 32-byte (256 bit) salt value as a
     *         Base64-encoded string.
     */
    public static String generateRandomSalt() {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[Salt_Bites];
        random.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    //=================CONSTRUCTORS=================
    /**
     * TODO //Construct from a passed password and salt (short constructor)
     *TODO// The iterations and keySize fields are set to the class's defaults for these values.
     */
    /** * @param password A plaintext password
     * @param salt     A password salt value (as a string)
     */
    public Password(String password, String salt) throws PasswordLengthException {
        this.setPassword(password);
        this.setSalt(salt);
    }

    public Password(Password other) throws PasswordLengthException {
        this.setPassword(other.getPassword());
        this.setSalt(other.getSalt());
    }

    //=====================GETTERS===================
    /**
     * @return The currently set plaintext password.
     */

    public String getPassword() {
        return this.password;
    }
    /**
     * @return The currently set password salt value.
     */

    public String getSalt() {
        return this.salt;
    }

    //=====================SETTERS===================
    /**
     * TODO// Set the raw (plaintext) password. This method should
     * TODO// throw an exception (the type of the exception is up
     * TODO// to you) if there is an attempt to set an WEAK password
     *
     * @TODO Implement password strength testing
     *
     * @param password A plaintext password.
     */

    public void setPassword(String password) throws PasswordLengthException {
        this.password = password;

    }
    /**
     * TODO Set the salt value to be used when hashing the
     * current object's password. This method should
     * throw an exception (the type of the exception is up
     * to you) if there is an attempt to set an WEAK salt
     *
     * @TODO Implement validation
     *    Question 1: Should the salt be of a minimum length
     *    Question 2: What is that minimum length?
     *
     * @param salt A password salt value (as a string)
     */
    public void setSalt(String salt) {
        this.salt = salt;
    }


    //=====================HASHING UTILITIES===================
    /**
     *TODO  Returns a derived key (hash) that has been generated using
     * PBKDF2 (configurable with the KEY_FACTORY_TYPE constant) and
     * SHA512 over {getIterations()} iterations. The resulting hash
     * is returned as a base64-encoded string.
     *
     * @return Hash as a base64-encoded string.
     * @throws PasswordException if the hashing function is not
     *  correctly configured.
     */
    public String generateHash() {

        try {

            char[] passwordCharacters = this.getPassword().toCharArray();
            byte[] saltBytes = Base64.getDecoder().decode(this.getSalt());

            SecretKeyFactory secretedFactory = SecretKeyFactory.getInstance(Key_type);
            PBEKeySpec spec = new PBEKeySpec(passwordCharacters, saltBytes, Iterations, Key_length);
            SecretKey key = secretedFactory.generateSecret(spec);

            return Base64.getEncoder().encodeToString(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new PasswordException(Algorithm_Error);
        } catch (InvalidKeySpecException e) {
            throw new PasswordException(Specifications_Error);
        }
    }

    // ====METHOD TO RETURN TRUE IF THE HASH IS THE SAME AS THE RESULT=====

    public boolean matchesHash(String hash) {
        return this.generateHash().equals(hash);
    }

}

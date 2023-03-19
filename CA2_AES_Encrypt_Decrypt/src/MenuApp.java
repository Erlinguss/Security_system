import java.util.InputMismatchException;
import java.util.Scanner;

//Group: SD2A
//Made By:
//        Abiel Lopez.
//        Erling Munguia.
//        Lee Xuan Ong.

public class MenuApp {

    //====ERROR EXCEPTIONS APPLIED IN THE MENU SYSTEM======
    private static final String WRONG_INTUP = "Error-Input, please enter the correct option";
    private static final String MIS_MATCH = "InputMisMatch Error-Input is not a Number";
    private static final String OUT_OF_RANGE = "Please enter a number";

    public MenuApp() {

    }
    public void executeProgram() throws PasswordLengthException {
        Scanner keyboard = new Scanner(System.in);
        int Option = 0;

        String mainPassword = "HappyChristmas2022";


        //=======GENERATE THE MASTER=============
        String Value = Password.generateRandomSalt();
        String masterEncryptionKey = new Password(mainPassword, Value).generateHash();
        boolean ItsNumber = false;

        do {
            try {
                while (Option != 3) {
                    //====MENU DRIVER FOR USER
                    System.out.println();
                    System.out.println("=======AES ENCRYPT/DECRYPT MENU ========");
                    System.out.println("========================================");
                    System.out.println("| Please enter a number from the  Menu |");
                    System.out.println("|======================================|");
                    System.out.println("|                                      |");
                    System.out.println("|          1.Encrypt a File            |");
                    System.out.println("|          2.Decrypt a File            |");
                    System.out.println("|          3.Exit Application          |");
                    System.out.println("|                                      |");
                    System.out.println("========================================");

                    Option = keyboard.nextInt();

                    //===SWITCH STATEMENT TO DISPLAY MENU OPTIONS=====
                    switch (Option) {
                        case 1:
                            //====OPTION: TO ENTER FILE NAME FIOR ENCRYPTION TEXT=======
                            System.out.println("====================== EXISTING TEXT FILES ====================");
                            System.out.println("===============================================================");
                            System.out.println("Choose and enter file name with original data for encryption:  ");
                            System.out.println("===============================================================");
                            System.out.println("|                         originaltext                        |");
                            System.out.println("|                          ciphertext                         |");
                            System.out.println("|                           plaintext                         |");
                            System.out.println("===============================================================");

                            String filenameOriginal = keyboard.next();

                            Cipher cipherText = new Cipher(filenameOriginal);

                            Cipher cipherText1 = new Cipher(filenameOriginal, masterEncryptionKey);

                            break;
                        case 2:

                            //====OPTION: FOR USER ENTER FILE NAME FOR DECRYPTION=====
                            System.out.println("====================== EXISTING TEXT FILES  ===================");
                            System.out.println("===============================================================");
                            System.out.println("Choose and enter file name with encrypted data for decryption: ");
                            System.out.println("===============================================================");
                            System.out.println("|                         originaltext                        |");
                            System.out.println("|                          ciphertext                         |");
                            System.out.println("|                           plaintext                         |");
                            System.out.println("===============================================================");

                            String fileNameDecoding = keyboard.next();

                            //====OPTION: FOR USER ENTER KEY TO DECRYPT THE MESSAGE======
                            System.out.println("=================================");
                            System.out.println("Please enter key for decryption: ");
                            System.out.println("=================================");
                            String keyDec = keyboard.next();
                            if (mainPassword.equals(keyDec)) {
                                Cipher ch2 = new Cipher(fileNameDecoding, masterEncryptionKey);
                            }
                            else {
                                System.out.println("============================================================================");
                                System.out.println("|  You are not able to decrypt the text using this key " + "`" + keyDec + "`|");
                                System.out.println("|                       Please do it again.                                |");
                                System.out.println("============================================================================\n\n");

                            }
                            break;

                        case 3:
                            System.out.println("Thank for using the application");
                            break;
                        default:

                            //=====DEFAULT TO DISPLAY AN EXCEPTION======
                            valueOutOfBound(1, 4, OUT_OF_RANGE, Option);
                    }
                }
            }
            //CATCHING ERROR IF THE USER DOES NOT INSERT A NUMBER
            catch (InputMismatchException e) {
                System.out.println(MIS_MATCH);
                ItsNumber = true;
                keyboard.nextLine();
            }
        } while ((ItsNumber));

    }

    //CATCHING ERR
    // OR IF THE USER CHOICE IS NOT MATCHING ANY OF THE OPTIONS FROM THE MENU DRIVER
    public static void valueOutOfBound(int minimum, int maximum, String errorMessage, int keyboard) {
        if (keyboard < minimum || keyboard > maximum) {
            System.out.println(errorMessage);
        }
    }

}
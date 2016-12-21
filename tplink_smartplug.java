import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * 
 * @author pbuckley <pbuckley4192@gmail.com><br/>
 * 
 *         TP-Link Wi-Fi Smart Plug Protocol Java Client<br/>
 * 
 *         For use with TP-Link HS-100 or HS-110<br/>
 */
public class tplink_smartplug
{

   /**
    * Port that the Smart Plug listens on
    */
   private final static int PORT = 9999;

   /**
    * Key that the XOR Cipher starts with
    */
   private final static int KEY = 171;

   /**
    * Main method used to send and receive data from the Smart Plug
    * 
    * @param args
    *           Argument 1: IP Address<br/>
    *           Argument 2: Command to Send<br/>
    */
   public static void main(String[] args)
   {
      Socket socket = null;
      try
      {
         socket = new Socket(args[0], PORT);
         System.out
               .println(socket.isConnected() ? "Connected to Device" : "Device Connection Failed");

         // No point wasting CPU cycles if the socket isin't connected
         if (!socket.isConnected())
         {
            sendCommand(args[1], socket);
            readResponse(socket);
         }

      }
      catch (IOException e)
      {
         e.printStackTrace();
      }
      finally
      {
         if (socket != null)
         {
            try
            {
               System.out.println("Closing");
               socket.close();
            }
            catch (IOException e)
            {
               e.printStackTrace();
            }
         }
      }

      System.out.println("Closed");
   }

   /**
    * Send a command to the smart plug
    * 
    * @param command
    *           Command to send to the Smart Plug
    * @param socket
    *           Socket to send the command on
    * @throws IOException
    *            Failure of socket communications
    */
   private static void sendCommand(String command, Socket socket) throws IOException
   {
      System.out.println("Sending Command: " + command);

      DataOutputStream writer = new DataOutputStream(socket.getOutputStream());
      writer.write(encrypt(command));
   }

   /**
    * Read a response from the Smart Plug
    * 
    * @param socket
    *           Socket to send the command on
    * @throws IOException
    *            Failure of socket communications
    */
   private static void readResponse(Socket socket) throws IOException
   {
      DataInputStream reader = new DataInputStream(socket.getInputStream());
      ArrayList<Byte> result = new ArrayList<Byte>();
      while (reader.available() > 0)
      {
         result.add(reader.readByte());
      }

      System.out.println(decrypt(result.toArray(new Byte[result.size()])));
   }

   /**
    * The smart plug communicates with the client via XOR Ciphered JSON
    * 
    * This encrypts the JSON to the format the plug expects
    * 
    * @param stringToEncrypt
    *           Command to encrypt
    * @return byte array ready to be sent to the device
    */
   static byte[] encrypt(String stringToEncrypt)
   {
      int index = 4; // First 4 bytes are 0x00
      int localKey = KEY; // Store a local copy of the key

      // Create a byte array
      byte[] bytestream = new byte[stringToEncrypt.length() + 4];

      for (char currentChar : stringToEncrypt.toCharArray())
      {
         // Get the encrypted char
         int operationValue = (localKey ^ currentChar);

         // Java handles bytes a bit differently to other languages
         char resultChar = (char) ((operationValue < 0) ? (operationValue += 256) : operationValue);

         // Increment the localKey
         localKey = resultChar;

         // Add the encrypted byte to the return array
         bytestream[index++] = (byte) localKey;
      }
      return bytestream;
   }

   /**
    * Decrypts the XOR Ciphered JSON so it can be displayed to the user
    * 
    * @param bytes
    *           XOR Ciphered JSON array
    * @return String containing the response
    */
   static String decrypt(Byte[] bytes)
   {
      int key = KEY; // Store a local copy of the key

      // StringBuffer to hold the decrypted result
      StringBuffer resultBuffer = new StringBuffer("");

      // We remove the first four bytes (added by the device for a reason unknown)
      for (byte encryptedByte : Arrays.copyOfRange(bytes, 4, bytes.length))
      {
         // Get the decrypted value
         int operationValue = (key ^ encryptedByte);

         // Java handles bytes a bit differently to other languages
         char resultChar = (char) ((operationValue < 0) ? (operationValue += 256) : operationValue);

         // Set the local key value
         key = encryptedByte;

         // Add the decrypted character to the return buffer
         resultBuffer.append(resultChar);
      }

      return resultBuffer.toString();
   }
}

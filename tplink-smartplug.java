import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * 
 * @author pbuckley <pbuckley4192@gmail.com>
 * 
 * This class is a java implementation of sending commands to a TPLink smart plug.
 * 
 * At the moment, it only encrypts and sends the commands.
 */
public class TPLink {

	private final static int PORT = 9999;

	public static void main(String[] args) {

		Socket s = null;
		try {
			s = new Socket(args[0], PORT);
			System.out.println(s.isConnected() ? "Connected to Device" : "Device Connection Failed");
			System.out.println("Sending Command: " + args[1]);

			DataOutputStream writer = new DataOutputStream(s.getOutputStream());
			writer.write(encrypt(args[1]));

		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (s != null) {
				try {
					s.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		System.out.println("Closing");

	}

	public static byte[] encrypt(String s) {
		int key = 171;

		byte[] bs = new byte[s.length() + 4];
		int count = 4;

		for (char c : s.toCharArray()) {
			char a = (char) (key ^ c);
			if (a < 0)
				a += 256;

			key = a;
			bs[count++] = (byte) key;
		}
		return bs;
	}
}

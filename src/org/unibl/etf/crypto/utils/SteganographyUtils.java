package org.unibl.etf.crypto.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;

import org.unibl.etf.crypto.QuizWindow;

public class SteganographyUtils {
	
	public static void encodeBMP(File file, byte[] message, int x) throws IOException {
		int headerSize = locatePixelArray(file);
		File stegoFile = new File(QuizWindow.questionsFolder + "Quiz" + x + ".bmp");
		try {
            Files.copy(file.toPath(), stegoFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
		try(RandomAccessFile raf1 = new RandomAccessFile(file, "r"); RandomAccessFile raf2 = new RandomAccessFile(stegoFile, "rw")) {
			raf1.skipBytes(headerSize);
			raf2.skipBytes(headerSize);
			for (int i = 0; i < message.length; i++)
			{
				//byte stringByte = (byte)message.charAt(i);
				byte stringByte = message[i];
				int temp = 128;
				for (int j = 1; j <= 8; j++) {
					byte read = raf1.readByte();
					read &= 0xfe;
					read |= ((stringByte & temp) >> 8 - j);
					raf2.write(read);
					temp /= 2;
				}
			}
			byte stringByte = 0;
			int temp = 128;
			for (int j = 1; j <= 8; j++) {
				byte read = raf1.readByte();
				read &= 0xfe;
				read |= ((stringByte & temp) >> 8 - j);
				raf2.write(read);
				temp /= 2;
			}
		}
	}

    public static byte[] decodeBMP(File file) throws IOException {
		int headerSize = locatePixelArray(file);
		//StringBuilder sb = new StringBuilder();
		ArrayList<Byte> bytes = new ArrayList<>();
		try(RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.skipBytes(headerSize);
			while (true)
			{
				byte stringByte = 0;
				for (int j = 1; j <= 8; j++) {
					byte read = raf.readByte();
					read &= 0x01;
					stringByte |= (read << 8 - j);
				}
				if (stringByte == 0)
					break;
				//sb.append((char)stringByte);
				bytes.add(stringByte);
			}
		}
		//return sb.toString();
		byte[] out = new byte[bytes.size()];
		int i = 0;
		for (byte b : bytes)
			out[i++] = b;
		return out;
	}

    private static int locatePixelArray(File file) {
		try (FileInputStream stream = new FileInputStream(file)) {
			stream.skip(10);
			int location = 0;
			for (int i = 0; i < 4; i++) {
				location = location | (stream.read() << (4 * i));
			}
			return location;
		} catch (IOException e) {
			return -1;
		}
	}

}

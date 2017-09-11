package com.github.nradov.abnffuzzer;

import static org.junit.Assert.*;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.Charset;

import org.junit.Test;
import com.github.nradov.abnffuzzer.Fuzzer;

public class Example {

	private static final int PORT1 = 143;
	private static final int PORT2 = 993;
	InputStream in;
	OutputStream out;
	BufferedInputStream bin;
	BufferedOutputStream bout;
	BufferedReader reader;
	PrintWriter writer;

	@Test
	public void testMyMethod() throws IOException {
		File file = new File("C:\\Users\\marti\\Desktop\\pü\\abnffuzzer\\src\\test\\resources\\Untitled 1");
		Fuzzer fuzzer = new Fuzzer(file);
		String login = fuzzer.generateAscii("login");
		System.out.println(login);
		InetAddress ipAddress = null;
		try {
			ipAddress = InetAddress.getByName("mail.hhu.de");
			Socket socket = new Socket(ipAddress, PORT1);
			in = socket.getInputStream();
			bin = new BufferedInputStream(in);
			reader = new BufferedReader(new InputStreamReader(bin, Charset.forName("iso-8859-1")));
			out = socket.getOutputStream();
			bout = new BufferedOutputStream(out);
			new Thread(new Runnable() {
				@Override
				public void run() {
					while (true) {
						try {
							String str;
							while ((str = reader.readLine()) != null) {
								System.out.println("Answer: " + str);
							}
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
			}).start();
			writer = new PrintWriter(new OutputStreamWriter(bout, Charset.forName("iso-8859-1")), true);
			writer.println(login);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}

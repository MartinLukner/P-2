package com.github.nradov.abnffuzzer;

import static org.junit.Assert.*;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.Random;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

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
	String rules;
	PrintWriter writer;
	Fuzzer fuzzer;

	@Test
	public void testMyMethod() throws IOException {
		File file = new File("src\\test\\resources\\grammar");
		fuzzer = new Fuzzer(file);
		InetAddress ipAddress = null;
		try {
			Scanner scanner = new Scanner(System.in);
			System.out.println("username: ");
			String username = scanner.nextLine();
			System.out.println("password: ");
			String password = scanner.nextLine();

			ipAddress = InetAddress.getByName("mail.hhu.de");
			Socket s = new Socket(ipAddress, PORT2);
			SSLSocket socket = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(s, s.getInetAddress().getHostAddress(), s.getPort(), true);			
			in = socket.getInputStream();
			bin = new BufferedInputStream(in);
			reader = new BufferedReader(new InputStreamReader(bin));
			out = socket.getOutputStream();
			bout = new BufferedOutputStream(out);
			writer = new PrintWriter(new OutputStreamWriter(bout));
			Thread t = new Thread(new Runnable() {
				@Override
				public void run() {
					while (true) {
						try {
							String str;
							while ((str = reader.readLine()) != null) {
								System.out.println("Answer: ...");
								if(str.equals("A01 OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY "
										+ "THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT "
										+ "CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES "
										+ "WITHIN CONTEXT=SEARCH LIST-STATUS SPECIAL-USE BINARY MOVE NOTIFY QUOTA] Logged in")) {
									System.out.println("Logged in");
									startFuzzing(rules);
								}
							}
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
			});
			t.start();
			System.out.println("rules(seperated by comma): ");
			rules = scanner.nextLine();
			writer.println("A01 LOGIN " + username + " " + password);
			writer.flush();	
			t.join();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void startFuzzing(String rules) {
		String[] parts = rules.split(",");
		Random random = new Random();
		File file = new File("C:\\Users\\marti\\Desktop\\pü\\abnffuzzer\\src\\test\\resources\\folders");
		ArrayList<String> folders = new ArrayList<String>();
		try {
			Scanner scanner = new Scanner(file);
			while (scanner.hasNextLine()) {
				folders.add(scanner.nextLine());
			}
			for (int k = 0; k < folders.size(); k++) {
				System.out.println("------------new folder---------------");
				writer.println("A01 select " + folders.get(k));
				writer.flush();
				for (int i = 0; i <= 5; i++) {
					int r = random.nextInt(parts.length);
					System.out.println("fuzzing " + parts[r]);
					String fuzz = fuzzer.generateAscii(parts[r]);
					System.out.println(fuzz);
					writer.println("A01 " + fuzz);
					writer.flush();
				}
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
}

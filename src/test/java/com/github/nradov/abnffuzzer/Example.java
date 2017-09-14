package com.github.nradov.abnffuzzer;

import static org.junit.Assert.*;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Test;
import com.github.nradov.abnffuzzer.Fuzzer;

public class Example {

	private static final int PORT1 = 143;
	private static final int PORT2 = 993;
    private static final Pattern LOGIN_RESP = Pattern.compile("A01 OK \\[CAPABILITY IMAP4rev1 LITERAL\\+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS SPECIAL-USE BINARY MOVE NOTIFY QUOTA] Logged in");

	@Test
	public void testMyMethod() throws IOException {
		try (
            Connection con = new Connection(PORT2, "mail.hhu.de");
			Scanner stdin = new Scanner(System.in);
		){

			System.out.println("username: ");
			String username = stdin.nextLine();
			System.out.println("password: ");
			String password = stdin.nextLine();
            

			con.sendLine("A01 LOGIN " + username + " " + password);

            String resp = null;
            do {
            	resp = con.readLine();
            	System.out.println(resp);
            } while (resp != null && resp.startsWith("* "));
			if (resp != null && LOGIN_RESP.matcher(resp).matches()) {
				System.out.println("Logged in");
				System.out.println("rules(seperated by comma): ");
				String rules = stdin.nextLine();
				String[] parts = rules.split(",");
				startFuzzing(con, parts);
				Thread t = new Thread(() -> {
					String ln;
					try {
						while ((ln = con.readLine()) != null) {
							System.out.println(ln);
						}
					} catch(IOException e) {
						e.printStackTrace();
					}
				});
				t.run();
				t.join();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void startFuzzing(Connection con, String[] rules) {
		try (
			Fuzz fuzz = new Fuzz(con, "src\\test\\resources\\grammar", rules);
			Stream<String> folders = Files.lines(Paths.get("src\\test\\resources\\folders"))
		){
			folders.forEach(folder -> {
				con.sendLine("A01 SELECT " + folder);
				fuzz.fuzz(10);
			});
		} catch (IOException e) {
			System.err.println(e);
		}
	}
	
	private static class Fuzz implements Closeable{
		private Random random;
		private Fuzzer fuzzer;
		private String[] rules;
		private Connection con;
		
		public Fuzz(Connection con, String grammarPath, String[] rules) throws IOException {
			this.con = con;
			File imapGrammar = new File(grammarPath);
			this.fuzzer = new Fuzzer(imapGrammar);
			this.rules = rules;
			this.random = new Random();
		}

		private String selectRule() {
			int r = random.nextInt(rules.length);
			return rules[r];
		}
		public void fuzz(int iterations) {
				for (int i = 0; i <= iterations; i++) {
					String selectedRule = selectRule();
					String fuzz = fuzzer.generateAscii(selectedRule);

					System.out.println("fuzzing " + selectedRule);
					System.out.println(fuzz);
					con.sendLine(fuzz);
				}
			
		}
		public void close() throws IOException{
			con.close();
		}

	}

    private static class Connection implements Closeable {
        SSLSocket socket;
        BufferedReader reader;
        PrintWriter writer;
        public Connection(int port, String url) throws IOException {
            InetAddress ipAddress = InetAddress.getByName(url);

			Socket s = new Socket(ipAddress, port);
			socket = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(s, s.getInetAddress().getHostAddress(), s.getPort(), true);			

			InputStream in = socket.getInputStream();
			BufferedInputStream bin = new BufferedInputStream(in);
			reader = new BufferedReader(new InputStreamReader(bin));

			OutputStream out = socket.getOutputStream();
			BufferedOutputStream bout = new BufferedOutputStream(out);
			writer = new PrintWriter(new OutputStreamWriter(bout));

        }

        public void close() throws IOException {
            socket.close();
            reader.close();
            writer.close();
        }
        public void sendLine(String line) {
			writer.println(line);
			writer.flush();	
        }
        public String readLine() throws IOException {
            return reader.readLine();
		}
    }
}


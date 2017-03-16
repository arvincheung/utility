
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSLKeystore{
	private String host;
	
	private char[] passphrase;
	
	private String proxyHost;
	
	private int proxyPort;
	
	private int port;
	
	//exclude for Java 1.6 (prime problem)
	private String[] excludedCipherSuites = {"_DHE_", "_DH_"};
	
	
	public void init() throws Exception{
		
		//Check whether jssecacerts exist, get cacerts otherwise
		char SEP = File.separatorChar;
		File dir = new File(System.getProperty("java.home") + SEP + "lib" + SEP + "security");
		File file = new File(dir, "jssecacerts");
		if (file.isFile() == false){
			file = new File(dir, "cacerts");
		}
		
		//Get Keystore from cacerts / jssecacerts
		System.out.println("Loading Keystore " + file + " in " + file.getAbsolutePath() + "...");
		InputStream in = new FileInputStream(file);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(in, passphrase);
		in.close();
		
		//Get TLS (Transport Layer Security) protocol context
		SSLContext context = SSLContext.getInstance("TLS");
		
		//Initialize Trust Manager Factory with Keystore
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);
		
		//Use Custom Trust Manager for getting key chain
		X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
		SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
		context.init(null, new TrustManager[]{tm}, null);
		
		//Get enabled cipher suites for security provider
		SSLParameters params = context.getSupportedSSLParameters();
        List<String> enabledCiphers = new ArrayList<String>();
        for (String cipher : params.getCipherSuites()) {
            boolean exclude = false;
            if (excludedCipherSuites != null) {
                for (int i=0; i<excludedCipherSuites.length && !exclude; i++) {
                    exclude = cipher.indexOf(excludedCipherSuites[i]) >= 0;
                }
            }
            if (!exclude) {
                enabledCiphers.add(cipher);
            }
        }
        
        //Create array of cipher suites excluding those declared above
        String[] cArray = new String[enabledCiphers.size()];
        enabledCiphers.toArray(cArray);
		
		//Create custom SSL Socket Factory to use new cipher suites
		SSLSocketFactory factory = context.getSocketFactory();
		factory = new DOSSLSocketFactory(factory, cArray);
		
		System.out.println("Opening Connection to " + host + "...");
		SSLSocket socket;
		try{
			//Create SSL Socket
			socket = (SSLSocket)factory.createSocket(host, port);
		} catch (UnknownHostException e){
			//Create tunnel to proxy
			System.out.println("Creating tunnel to proxy " + proxyHost + " through port " + proxyPort + "..." );
			Socket tunnel = new Socket(proxyHost, proxyPort);
			doTunnelHandshake(tunnel, host, port);
			
			//Layer new SSL Socket (https) over tunnel (http)
			socket = (SSLSocket)factory.createSocket(tunnel, host, port, true);
		} catch (ConnectException e){
			//Create tunnel to proxy
			System.out.println("Creating tunnel to proxy " + proxyHost + " through port " + proxyPort + "..." );
			Socket tunnel = new Socket(proxyHost, proxyPort);
			doTunnelHandshake(tunnel, host, port);
			
			//Layer new SSL Socket (https) over tunnel (http)
			socket = (SSLSocket)factory.createSocket(tunnel, host, port, true);
		}
		
		//Socket should be opened
		socket.setSoTimeout(10000);
		try{
			//Try handshake to check PKIX Path Building
			System.out.println("Starting SSL handshake");
			socket.startHandshake();
			socket.close();
			System.out.println();
			System.out.println("No errors, certificate is already trusted");
			return;
		} catch (SSLHandshakeException e) {
			//PKIX Path Building Failed
			System.out.println();
			
			//Get Certificate Key Chains
			X509Certificate[] chain = tm.chain;
			if (chain == null){
				System.out.println("Could not obtain server certificate chain");
				return;
			}
			
			System.out.println();
			System.out.println("Server sent " + chain.length + " certificate(s).");
			System.out.println();
			
			//Get certificate hash
			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			for (int i = 0; i< chain.length; i ++){
				X509Certificate cert = chain[i];
				System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
				System.out.println(" Issuer " + cert.getIssuerDN());
				sha1.update(cert.getEncoded());
				System.out.println("  sha1  " + toHexString(sha1.digest()));
				md5.update(cert.getEncoded());
				System.out.println(" md5 " + toHexString(md5.digest()));
				System.out.println();
			}
			
			//Set certificate alias as <hostname-1>
			X509Certificate cert = chain[0];
			String alias = host + "-" + 1;
			ks.setCertificateEntry(alias, cert);
			
			//Write certificate to Keystore
			OutputStream out = new FileOutputStream(file);
			ks.store(out, passphrase);
			out.close();
			
			System.out.println();
			System.out.println(cert);
			System.out.println();
			System.out.println("Added certificate to keystore " + file + " using alias '" + alias + "'");
			System.out.println();
			System.out.println("Please restart server");
			
			System.setProperty("javax.net.ssl.trustStore", file.getAbsolutePath());
			System.out.println("TrustStore set to " + file.getAbsolutePath());
			
			System.setProperty("javax.net.ssl.trustStoreType", "JKS");
		} catch (Exception e) {
			System.out.println();
			e.printStackTrace();
			throw e;
		}
	}
	
	private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();
	
	private static String toHexString(byte[] bytes){
		StringBuilder sb = new StringBuilder(bytes.length * 3);
		for (int b : bytes){
			b &= 0xff;
			sb.append(HEXDIGITS[b >> 4]);
			sb.append(HEXDIGITS[b & 15]);
			sb.append(' ');
		}
		return sb.toString();
	}
	
	/*
     * Tell our tunnel where we want to CONNECT, and look for the
     * right reply.  Throw IOException if anything goes wrong.
     */
    private void doTunnelHandshake(Socket tunnel, String host, int port)
    throws IOException
    {
    	System.out.println("Tunnel Opened");
        OutputStream out = tunnel.getOutputStream();
        String javaVersion = "Java/" + System.getProperty("java.version");
        String userAgent = System.getProperty("http.agent") == null ? javaVersion : System.getProperty("http.agent") + " " + javaVersion;
        String msg = "CONNECT " + host + ":" + port + " HTTP/1.0\n"
                     + "User-Agent: "
                     + userAgent
                     + "\r\n\r\n";
        byte b[];
        try {
        	//http protocol uses ASCII7
            b = msg.getBytes("ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            //just for trying
            b = msg.getBytes();
        }
        out.write(b);
        out.flush();

        /*
         * We need to store the reply so we can create a detailed
         * error message to the user.
         */
        byte            reply[] = new byte[200];
        int             replyLen = 0;
        int             newlinesSeen = 0;
        boolean         headerDone = false;     /* Done on first newline */

        InputStream     in = tunnel.getInputStream();

        while (newlinesSeen < 2) {
            int i = in.read();
            if (i < 0) {
                throw new IOException("Unexpected EOF from proxy");
            }
            if (i == '\n') {
                headerDone = true;
                ++newlinesSeen;
            } else if (i != '\r') {
                newlinesSeen = 0;
                if (!headerDone && replyLen < reply.length) {
                    reply[replyLen++] = (byte) i;
                }
            }
        }

        /*
         * Converting the byte array to a string is slightly wasteful
         * in the case where the connection was successful, but it's
         * insignificant compared to the network overhead.
         */
        String replyStr;
        try {
            replyStr = new String(reply, 0, replyLen, "ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            replyStr = new String(reply, 0, replyLen);
        }

        //Check HTTP status for 200 (Successful)
        String regex = "(^HTTP\\/[0-9.]+ 200).+";
        if(!Pattern.matches(regex, replyStr)) {
            throw new IOException("Unable to tunnel through "
                    + proxyHost + ":" + proxyPort
                    + ".  Proxy returns \"" + replyStr + "\"");
        }

       System.out.println("Tunnel Handshake Successful!");
    }
	
	private static class SavingTrustManager implements X509TrustManager{
		private final X509TrustManager tm;
		private X509Certificate[] chain;
		
		SavingTrustManager(X509TrustManager tm){
			this.tm = tm;
		}
		
		public X509Certificate[] getAcceptedIssuers(){
			return tm.getAcceptedIssuers();
		}
		
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException{
			this.chain = chain;
			tm.checkClientTrusted(chain, authType);
		}
		
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			this.chain = chain;
			tm.checkServerTrusted(chain, authType);
		}
	}
	
	 private static class DOSSLSocketFactory extends javax.net.ssl.SSLSocketFactory {

	        private SSLSocketFactory sf = null;
	        private String[] enabledCiphers = null;

	        private DOSSLSocketFactory(SSLSocketFactory sf, String[] enabledCiphers) {
	            super();
	            this.sf = sf;
	            this.enabledCiphers = enabledCiphers;
	        }

	        private Socket getSocketWithEnabledCiphers(Socket socket) {
	            if (enabledCiphers != null && socket != null && socket instanceof SSLSocket)
	                ((SSLSocket)socket).setEnabledCipherSuites(enabledCiphers);

	            return socket;
	        }

	        @Override
	        public Socket createSocket(Socket s, String host, int port,
	                boolean autoClose) throws IOException {
	            return getSocketWithEnabledCiphers(sf.createSocket(s, host, port, autoClose));
	        }

	        @Override
	        public String[] getDefaultCipherSuites() {
	            return sf.getDefaultCipherSuites();
	        }

	        @Override
	        public String[] getSupportedCipherSuites() {
	            if (enabledCiphers == null)
	                return sf.getSupportedCipherSuites();
	            else
	                return enabledCiphers;
	        }

	        @Override
	        public Socket createSocket(String host, int port) throws IOException,
	                UnknownHostException {
	            return getSocketWithEnabledCiphers(sf.createSocket(host, port));
	        }

	        @Override
	        public Socket createSocket(InetAddress address, int port)
	                throws IOException {
	            return getSocketWithEnabledCiphers(sf.createSocket(address, port));
	        }

	        @Override
	        public Socket createSocket(String host, int port, InetAddress localAddress,
	                int localPort) throws IOException, UnknownHostException {
	            return getSocketWithEnabledCiphers(sf.createSocket(host, port, localAddress, localPort));
	        }

	        @Override
	        public Socket createSocket(InetAddress address, int port,
	                InetAddress localaddress, int localport) throws IOException {
	            return getSocketWithEnabledCiphers(sf.createSocket(address, port, localaddress, localport));
	        }

	    }
}

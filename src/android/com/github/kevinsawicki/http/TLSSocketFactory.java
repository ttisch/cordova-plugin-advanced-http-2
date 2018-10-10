package com.github.kevinsawicki.http;

import java.utils.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class TLSSocketFactory extends SSLSocketFactory {

    private static final String PREFERRED_CIPHER_SUITE = "TLS_RSA_WITH_AES_128_CBC_SHA";
    private SSLSocketFactory internalSSLSocketFactory;

    public TLSSocketFactory(SSLContext context) {
        internalSSLSocketFactory = context.getSocketFactory();
    }

    @Override
    public String[] getDefaultCipherSuites() {

        return setupPreferredDefaultCipherSuites(internalSSLSocketFactory);
    }

    @Override
    public String[] getSupportedCipherSuites() {

        return setupPreferredSupportedCipherSuites(internalSSLSocketFactory);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return enableTLSOnSocket(internalSSLSocketFactory.createSocket(s, host, port, autoClose));
        String[] cipherSuites = setupPreferredDefaultCipherSuites(internalSSLSocketFactory);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return enableTLSOnSocket(internalSSLSocketFactory.createSocket(host, port));
        String[] cipherSuites = setupPreferredDefaultCipherSuites(internalSSLSocketFactory);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        return enableTLSOnSocket(internalSSLSocketFactory.createSocket(host, port, localHost, localPort));
        String[] cipherSuites = setupPreferredDefaultCipherSuites(internalSSLSocketFactory);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return enableTLSOnSocket(internalSSLSocketFactory.createSocket(host, port));
        String[] cipherSuites = setupPreferredDefaultCipherSuites(internalSSLSocketFactory);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return enableTLSOnSocket(internalSSLSocketFactory.createSocket(address, port, localAddress, localPort));
        String[] cipherSuites = setupPreferredDefaultCipherSuites(internalSSLSocketFactory);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
    }

    private Socket enableTLSOnSocket(Socket socket) {
        if(socket != null && (socket instanceof SSLSocket)) {
            ((SSLSocket)socket).setEnabledProtocols(new String[] {"TLSv1.2"});
            String[] cipherSuites = setupPreferredDefaultCipherSuites(internalSSLSocketFactory);
            ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
        }
        return socket;
    }

    private static String[] setupPreferredDefaultCipherSuites(SSLSocketFactory sslSocketFactory) {
        String[] defaultCipherSuites = sslSocketFactory.getDefaultCipherSuites();

        ArrayList<String> suitesList = new ArrayList<String>(Arrays.asList(defaultCipherSuites));
        suitesList.remove(PREFERRED_CIPHER_SUITE);
        suitesList.add(0, PREFERRED_CIPHER_SUITE);

        return suitesList.toArray(new String[suitesList.size()]);
    }

    private static String[] setupPreferredSupportedCipherSuites(SSLSocketFactory sslSocketFactory) {
        String[] supportedCipherSuites = sslSocketFactory.getSupportedCipherSuites();

        ArrayList<String> suitesList = new ArrayList<String>(Arrays.asList(supportedCipherSuites));
        suitesList.remove(PREFERRED_CIPHER_SUITE);
        suitesList.add(0, PREFERRED_CIPHER_SUITE);

        return suitesList.toArray(new String[suitesList.size()]);
    }
}

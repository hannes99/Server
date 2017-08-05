import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;

public class Server {
    public static void main(String[] args) throws Exception {
        ServerSocket m_ServerSocket = new ServerSocket(12111);
        while (true) {
            Socket clientSocket = m_ServerSocket.accept();
            ClientServiceThread cliThread = new ClientServiceThread(clientSocket);
            cliThread.start();
        }
    }
}

class ClientServiceThread extends Thread {
    private Socket clientSocket;
    private SecretKey aes_session_key;
    private OutputStream out;
    private InputStream in;
    private String[] actions = {"login", "quit"};
    private DBConnection dbConnection;

    ClientServiceThread(Socket s) {
        clientSocket = s;
        System.out.println("Session mit Addresse - "
                + clientSocket.getInetAddress().getHostName());
        try {
            out = clientSocket.getOutputStream();
            in = clientSocket.getInputStream();


            KeyPair rsa_key_pair = generate_new_rsa_key();
            out.write(rsa_key_pair.getPublic().getEncoded());
            out.flush();

            byte[] aes_key = read(true);


            Cipher dec = Cipher.getInstance("RSA");
            dec.init(Cipher.DECRYPT_MODE, rsa_key_pair.getPrivate());
            byte[] aes_key_dec = dec.doFinal(aes_key);
            aes_session_key = new SecretKeySpec(aes_key_dec, 0, aes_key_dec.length, "AES");
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    private KeyPair generate_new_rsa_key() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);
        return keyGen.genKeyPair();
    }


    private String read() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] content = new byte[2048];
        int bytesRead;
        while ((bytesRead = in.read(content)) != -1) {
            baos.write(content, 0, bytesRead);
            if (bytesRead < 2048)
                break;
        }
        if (aes_session_key != null) {
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.DECRYPT_MODE, aes_session_key);
            return new String(c.doFinal(baos.toByteArray()));
        } else {
            return new String(baos.toByteArray());
        }
    }

    private byte[] read(boolean raw) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] content = new byte[2048];
        int bytesRead;
        while ((bytesRead = in.read(content)) != -1) {
            baos.write(content, 0, bytesRead);
            if (bytesRead < 2048)
                break;
        }
        if (aes_session_key != null) {
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.DECRYPT_MODE, aes_session_key);
            return c.doFinal(baos.toByteArray());
        } else {
            return baos.toByteArray();
        }
    }


    private void send(String data) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, aes_session_key);
        out.write(c.doFinal(data.getBytes()));
        out.flush();
    }

    private void send(byte[] raw) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, aes_session_key);
        out.write(c.doFinal(raw));
        out.flush();
    }

    private void close() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Session mit Addresse - "
                + clientSocket.getInetAddress().getHostName()+" geschlossen!");
    }

    public void run() {
        try{
            boolean listen = true;
            while(listen) {
                String action = read();

                if (!Arrays.asList(actions).contains(action)) {
                    send("ACTION DOES NOT EXIST");
                } else {
                    send("OK");
                    switch (action) {
                        case "login":
                            dbConnection = new DBConnection();
                            PreparedStatement preparedStatement = dbConnection.getConnection().prepareStatement("" +
                                    "SELECT password FROM logins WHERE username = ?;");
                            String user = read();
                            send("OK");
                            byte[] pass = read(true);
                            String pass_hash = DatatypeConverter.printHexBinary(pass);

                            preparedStatement.setString(1, user);
                            ResultSet rs = preparedStatement.executeQuery();
                            String stored_pw = null;
                            if (rs.next()) {
                                stored_pw = rs.getString("password");
                            }
                            if(stored_pw != null && stored_pw.equals(pass_hash)){
                                send("OK");
                            }else{
                                Thread.sleep(2000);
                                send("WRONG PW");
                            }
                            break;
                        case "quit":
                            close();
                            listen=false;
                            break;
                    }
                }
            }
        }catch (Exception e) {
            e.printStackTrace();
        }
    }
}

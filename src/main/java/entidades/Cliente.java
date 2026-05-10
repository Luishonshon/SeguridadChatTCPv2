package entidades;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;

import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import componentes.JChat;
import componentes.PButton;
import componentes.PTextField;

/**
 *
 * @author angel
 */
public class Cliente {
    // variables de instancia
    private String nombre;
    private InetAddress ipServer;
    private int puertoServer;
    private Encriptador encriptador;
    private ObjectInputStream in;
    private ObjectOutputStream out;

    // componentes de la interfaz
    private JTextArea chat;
    private PTextField texto;
    private PButton btnEnviar;
    private JLabel lblAdmin;
    private JLabel lblNombreChat;

    public Cliente(String nombre, String ipServer, int puertoServer) throws IOException, ClassNotFoundException {
        this.nombre = nombre;
        this.ipServer = InetAddress.getByName(ipServer);
        this.puertoServer = puertoServer;
    }

    public void asignarComponentes(JChat pnlChat) {
        this.btnEnviar = pnlChat.getBtnEnviar();
        this.chat = pnlChat.getTxtArea();
        this.texto = pnlChat.getTxtMensaje();
        this.lblAdmin = pnlChat.getLblAdmin();
        this.lblNombreChat = pnlChat.getLblServer();
    }

    /**
     * Metodo que se encarga de unirse al servidor
     * 
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public void unirseServidor() throws IOException, ClassNotFoundException {
        Socket socket = new Socket(ipServer, puertoServer);
        out = new ObjectOutputStream(socket.getOutputStream());
        out.flush();
        in = new ObjectInputStream(socket.getInputStream());
        
        handshake();//establece una clave con el servidor
        new Thread(() -> {//recibe los mensajes del servidor en el hilo
            try {
                recibirMensajes(socket);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        runBtnEnviar();//activacion del listener que envia mensajes al servidor
    }

    /**
     * Recibe los mensajes del servidor y los muestra en el chat
     * 
     * @param socket
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private void recibirMensajes(Socket socket) throws IOException {
        try {
            while (true) {
                String mensaje = (String) in.readObject();
                encriptador.setMensaje(mensaje);
                encriptador.decifrar();
                SwingUtilities.invokeLater(() -> {
					chat.append(encriptador.getMensaje() + "\n");
                });
            }
        } catch (IOException | ClassNotFoundException e) {
            socket.close();
            System.err.println("Connection closed or error reading from server: " + e.getMessage());
        }
    }

    /**
     * Metodo que realiza el handshake entre el cliente y el servidor
     * 
     * @param socket
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private void handshake() throws IOException, ClassNotFoundException {
        encriptador = new Encriptador();
        BigInteger[] parametros = encriptador.getParam();
        out.writeObject(parametros); //manda los parametros de alice
        out.flush();
        out.reset();
        
        BigInteger[] bobParam = (BigInteger[]) in.readObject();// recibe los parametros de bob
        encriptador.finalizar(bobParam);

        encriptador.setMensaje(nombre);
        encriptador.cifrar();
        out.writeObject(encriptador.getMensaje());// manda la informacion basica encriptada
        out.flush();
        out.reset();

        String mensaje = (String) in.readObject();// recibe el nombre del chat del servidor encriptado
        encriptador.setMensaje(mensaje);
        encriptador.decifrar();
        lblNombreChat.setText(encriptador.getMensaje());

        mensaje = (String) in.readObject();// recibe el nombre del admin del servidor encriptada
        encriptador.setMensaje(mensaje);
        encriptador.decifrar();
        lblAdmin.setText(encriptador.getMensaje());
    }

    public String getNombreServidor(){
        return lblNombreChat.getText();
    }

    /**
     * envia un mensaje al servidor
     * 
     * @param mensaje
     * @throws IOException
     */
    private void runBtnEnviar() {
        btnEnviar.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                try {
                    if(texto.getText()!=null) {
                        encriptador.setMensaje(texto.getText());
                        encriptador.cifrar();
                        out.writeObject(encriptador.getMensaje());
                        out.flush();
                        out.reset();
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                } finally {
                    texto.setText("");
                }
            }
        });
    }
}

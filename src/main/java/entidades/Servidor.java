package entidades;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JTextArea;

import componentes.JChat;
import componentes.PButton;
import componentes.PTextField;

/**
 * clase que representa un socket
 *
 * @author erubiel
 */
public class Servidor {

    //variables globales
    private ServerSocket socket;
    private static HashMap<ObjectOutputStream, Encriptador> encriptadores = new HashMap<>();
    private static HashMap<String, ObjectOutputStream> clientes = new HashMap<>();
    private static LinkedList<String> historial = new LinkedList<>();

    // variables de instancia
    private String nombreServidor;
    private int capacidad;
    private InetAddress ip;
    private int puerto;
    private String nombreAdmin;

    // componentes de la interfaz
    private JChat pnlChat;
    private JTextArea chat;
    private PTextField texto;
    private PButton btnEnviar;

    public Servidor(String nombreServidor, String nombreAdmin, String ip, int puerto, int capacidad)
            throws IOException {
        this.nombreServidor = nombreServidor;
        this.nombreAdmin = nombreAdmin;
        this.ip = InetAddress.getByName(ip);
        this.puerto = puerto;
        this.capacidad = capacidad;
    }

    /**
     * metodo que permite dar control al servidor sobre sus componentres
     * graficos
     *
     * @param pnlChat
     */
    public void asignarComponentes(JChat pnlChat) {
        this.pnlChat = pnlChat;
        this.btnEnviar = pnlChat.getBtnEnviar();
        this.chat = pnlChat.getTxtArea();
        this.texto = pnlChat.getTxtMensaje();
    }

    //metodos de coneccion principales
    /**
     * inicia el servidor
     *
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public void iniciarServidor() throws IOException, ClassNotFoundException {
        socket = new ServerSocket(puerto, capacidad, ip);
        chat.append("Servidor " + nombreServidor + " iniciado\n");
        new Thread(() -> {
            try {
                escucharConexiones(socket);
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }).start();

        // Agregar el ActionListener al botón de enviar
        runBtnEnviar();
    }

    /**
     * escucha las conecciones entrantes
     *
     * @param socket
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private void escucharConexiones(ServerSocket socket) throws IOException, ClassNotFoundException {
        while (true) {
            Socket cliente = socket.accept();
            ObjectOutputStream out = new ObjectOutputStream(cliente.getOutputStream()); //wrapper salida
            out.flush();
            ObjectInputStream in = new ObjectInputStream(cliente.getInputStream()); //wrapper ingreso

            Encriptador en = handshake(in, out); //determina una clave secreta de comunicacion
            String nombreCliente = validarDatos(en, in, out); //determina si el cliente es valido
            clientes.put(nombreCliente, out); //agrega el cliente a la lista de clientes
            pnlChat.dibujaUsuario(nombreCliente);
            new Thread(() -> manejaUsuario(en, cliente, in, out, nombreCliente)).start();; //asignar un hilo para el cliente
        }
    }

    /**
     * maneja la coneccion de un usuario
     *
     * @param cliente
     */
    private void manejaUsuario(Encriptador encriptador, Socket socket, ObjectInputStream in, ObjectOutputStream out, String nombreCliente) {
        try {
            Pattern patronPriv = Pattern.compile("^/priv\\s+(\\w+)\\s+(.+)$");
            Matcher matcherPriv;
            while (true) {
                String mensaje = (String) in.readObject();
                if (mensaje instanceof String) {
                    encriptador.setMensaje(mensaje);
                    encriptador.decifrar();
                    String mensajeDecifrado = encriptador.getMensaje();
                    matcherPriv = patronPriv.matcher(mensajeDecifrado);

                    if (mensajeDecifrado.equalsIgnoreCase("/salir")) { //si quiere salir se sale de una
                        break;
                    } else if (matcherPriv.matches()) { //evalua si quiere enviar un mensaje privado
                        String destinatario = matcherPriv.group(1);
                        System.out.println(destinatario);
                        String msjPriv = matcherPriv.group(2);
                        System.out.println(msjPriv);
                        enviarMensajePrivado(nombreCliente, destinatario, msjPriv);
                    } else {
                        enviarMensaje(nombreCliente, mensajeDecifrado);
                    }
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            try {
                socket.close();
                pnlChat.eliminarUsuario(nombreCliente);
                encriptadores.remove(out);
                clientes.remove(nombreCliente);
                enviarMensaje("SERVIDOR", "Cliente Ha Perdido La Conexion: " + nombreCliente);
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        } finally {
            try {
                socket.close();
                pnlChat.eliminarUsuario(nombreCliente);
                encriptadores.remove(out);
                clientes.remove(nombreCliente);
                enviarMensaje("SERVIDOR", "Cliente Se Ha Desconectado: " + nombreCliente);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    //metodos de coneccion auxiliares
    /**
     * recibe los parametros de alice y manda los de bob
     *
     * @param cliente
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private Encriptador handshake(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {
        BigInteger[] aliceParam = (BigInteger[]) in.readObject();
        Encriptador encriptador = new Encriptador(aliceParam); //manda los parametros de bob
        out.writeObject(encriptador.getParam());
        out.flush();
        out.reset();
        return encriptador;
    }

    private String validarDatos(Encriptador encriptador, ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {
        String mensaje = (String) in.readObject();// recibe el nombre del cliente de manera segura
        encriptador.setMensaje(mensaje);
        encriptador.decifrar();
        String nombreCliente = encriptador.getMensaje();

        //validacion de nombre (no nombres reptidos, no nombres de admin, no nombres de servidor)
        if (nombreCliente.equals(nombreAdmin) || nombreCliente.equals("SERVIDOR") || clientes.containsKey(nombreCliente)) {
            throw new IOException("Nombre de usuario no valido");
        } else {
            encriptadores.put(out, encriptador);//agrega el cliente a la lista de clientes    
            encriptador.setMensaje(nombreServidor);// manda el nombre del servidor de manera segura una vez aceptado
            encriptador.cifrar();
            out.writeObject(encriptador.getMensaje());
            out.flush();
            out.reset();

            encriptador.setMensaje(nombreAdmin);// manda el nombre del admin de manera segura una vez aceptado
            encriptador.cifrar();
            out.writeObject(encriptador.getMensaje());
            out.flush();
            out.reset();

            // manda el historial de mensajes al cliente
            for (String m : historial) {
                encriptador.setMensaje(m);
                encriptador.cifrar();
                out.writeObject(encriptador.getMensaje());
                out.flush();
                out.reset();
            }
            enviarMensaje("SERVIDOR", "Nuevo Cliente Conectado: " + nombreCliente);
        }
        return nombreCliente;
    }

    /**
     * envia un mensaje al cliente
     *
     * @param mensaje
     * @throws IOException
     */
    private void enviarMensaje(String emisor, String mensaje) throws IOException {
        String tiempo = String.format("%02d:%02d", Calendar.getInstance().get(Calendar.HOUR_OF_DAY), Calendar.getInstance().get(Calendar.MINUTE));
        final String msjFormateado = "[" + tiempo + "][" + emisor + "]: " + mensaje;

        encriptadores.forEach((out, encriptador) -> {
            try {
                encriptador.setMensaje(msjFormateado);
                encriptador.cifrar();
                out.writeObject(encriptador.getMensaje());
                out.flush();
                out.reset();
            } catch (IOException e) {
                System.err.println("Error al enviar el mensaje a " + socket.getInetAddress());
            }
        });
        chat.append(msjFormateado + "\n");
        historial.add(msjFormateado);
    }

    /**
     * metodo que permite enviar mensajes privados
     *
     * @param nombreServidor
     */
    private void enviarMensajePrivado(String emisor, String destinatario, String mensaje) throws IOException {
        String tiempo = String.format("%02d:%02d", Calendar.getInstance().get(Calendar.HOUR_OF_DAY), Calendar.getInstance().get(Calendar.MINUTE));
        final String msjFormateado = "[" + tiempo + "][" + emisor + "]: " + mensaje;
        clientes.forEach((nombre, out) -> {
            System.out.println("Entró al metodo enviarMensajePrivado");
            if (nombre.equals(destinatario)) {
                try {
                    System.out.println("Entro al if");
                    Encriptador enc = encriptadores.get(out);
                    if (enc != null) {
                        enc.setMensaje(msjFormateado);
                        enc.cifrar();
                        out.writeObject(enc.getMensaje());
                    }
                    out.flush();
                    out.reset();
                } catch (IOException e) {
                    System.out.println("Error al enviar el mensaje a " + nombre);
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * envia un mensaje al cliente
     *
     * @param mensaje
     * @throws IOException
     */
    private void runBtnEnviar() {
        btnEnviar.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                try {
                    enviarMensaje(nombreAdmin, texto.getText());
                } catch (IOException ex) {
                    ex.printStackTrace();
                } finally {
                    texto.setText("");
                }
            }
        });
    }
}

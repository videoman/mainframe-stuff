// Save this file as SocketShellServer.java
import java.io.*;
import java.net.*;

public class SocketShellServer {
    public static void main(String[] args) {
        // Default port
        int port = 9933;
        
        // Override port if specified as argument
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number. Using default: " + port);
            }
        }
        
        try {
            // Create server socket
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server listening on port " + port);
            
            // Wait for connection
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress().getHostAddress());
            
            // Set up communication streams with client
            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();
            PrintWriter outToClient = new PrintWriter(clientOut, true);
            
            // Start the shell process
            ProcessBuilder processBuilder = new ProcessBuilder("/bin/sh");
            processBuilder.redirectErrorStream(true); // Merge stdout and stderr
            Process shellProcess = processBuilder.start();
            
            // Set up streams to communicate with shell process
            OutputStream shellIn = shellProcess.getOutputStream();
            InputStream shellOut = shellProcess.getInputStream();
            
            outToClient.println("Connected to shell bridge. Commands will be forwarded to /bin/sh");
            
            // Create two threads for bidirectional communication
            
            // Thread 1: Client -> Shell
            Thread clientToShell = new Thread(() -> {
                byte[] buffer = new byte[1024];
                int bytesRead;
                
                try {
                    while ((bytesRead = clientIn.read(buffer)) != -1) {
                        shellIn.write(buffer, 0, bytesRead);
                        shellIn.flush();
                    }
                } catch (IOException e) {
                    System.err.println("Error in client->shell communication: " + e.getMessage());
                } finally {
                    try {
                        shellIn.close();
                    } catch (IOException e) {
                        System.err.println("Error closing shell input stream: " + e.getMessage());
                    }
                }
            });
            
            // Thread 2: Shell -> Client
            Thread shellToClient = new Thread(() -> {
                byte[] buffer = new byte[1024];
                int bytesRead;
                
                try {
                    while ((bytesRead = shellOut.read(buffer)) != -1) {
                        clientOut.write(buffer, 0, bytesRead);
                        clientOut.flush();
                    }
                } catch (IOException e) {
                    System.err.println("Error in shell->client communication: " + e.getMessage());
                } finally {
                    try {
                        clientOut.close();
                    } catch (IOException e) {
                        System.err.println("Error closing client output stream: " + e.getMessage());
                    }
                }
            });
            
            // Start the threads
            clientToShell.start();
            shellToClient.start();
            
            // Wait for the shell process to exit
            int exitCode = shellProcess.waitFor();
            System.out.println("Shell process exited with code: " + exitCode);
            
            // Clean up
            clientSocket.close();
            serverSocket.close();
            
        } catch (IOException | InterruptedException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;
    private static final boolean isTesting = false; //TODO: CHANGE WHEN SUBMIT
    private static int[] generatedQueryID = new int[65536];
    private static int totalQuery = 0;
    private static int decodingIndex = 0;
    public static Set<ResourceRecord> answers;
    public static Set<ResourceRecord> nameServers;
    public static Set<ResourceRecord> additional;


    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node, int queryID) throws IOException {
//        if (isTesting) {
//            System.out.println("SOUT大法好1");
//            System.out.println(Arrays.toString(message));
//        }


        message[0] = (byte) (queryID >>> 8);
        message[1] = (byte) (queryID & 0xff);
        message[5] = (byte) (1);
        String[] serverNames = node.getHostName().split("[.]");
        int index = 12;
//        if (isTesting) {
//            System.out.println("SOUT大法好2");
//            System.out.println(queryID);
//            System.out.println(queryID >> 8);
//            System.out.println(queryID & 0xff);
//        }
        for (String serverName : serverNames) {
            message[index++] = (byte) serverName.length();
            for (int j = 0; j < serverName.length(); j++) {
                message[index++] = (byte) ((int) serverName.charAt(j));
            }
        }
//        if (isTesting) {
//            System.out.println("SOUT大法好3");
//            System.out.println(Arrays.toString(message));
//        }
        message[index++] = (byte) 0;
        message[index++] = (byte) ((node.getType().getCode() >>> 8) & 0xff);
        message[index++] = (byte) (node.getType().getCode() & 0xff);
        message[index++] = (byte) 0;
        message[index++] = (byte) 1;

        int timeOutCount = 0;
        int maxTimeOut = 2;
        byte[] response = new byte[1024];
//        if (isTesting) {
//            System.out.println("SOUT大法好4");
//            System.out.println(Arrays.toString(message));
//        }
        while (timeOutCount < maxTimeOut) {
            if (verboseTracing) {
                System.out.println("\n");
                verbosePrint(queryID, node, server);
            }
            DatagramPacket dp = new DatagramPacket(message, index + 1, server, DEFAULT_DNS_PORT);
            try {
                socket.send(dp);
            } catch (IOException e) {
                break;
            }

            DatagramPacket responsePacket = new DatagramPacket(response, response.length);
            try {
                socket.receive(responsePacket);
                int responseID = parseTwoBytesToInt(response[0],response[1]);
                int QR = (response[2] & 0x80) >>> 7; // get 1st bit

                while (queryID != responseID || QR != 1) {
                    socket.receive(responsePacket);
                    responseID = parseTwoBytesToInt(response[0],response[1]);
                    QR = (response[2] & 0x80) >>> 7; // get 1st bit
                }
                return new DNSServerResponse(ByteBuffer.wrap(response), queryID);
            } catch (SocketTimeoutException e) {
                timeOutCount++;
            } catch (IOException e) {
                System.exit(0);
            }
        }
        return new DNSServerResponse(ByteBuffer.wrap(response), queryID);
    }

    private static int parseTwoBytesToInt(byte b1, byte b2) {
        return ((b1 & 0xff) << 8) + (b2 & 0xff);
    }



    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        answers = new HashSet<>();
        nameServers = new HashSet<>();
        additional  = new HashSet<>();
        if (responseBuffer == null) {
            return null;
        }
        Set<ResourceRecord> rtn = new HashSet<>();
        byte[] response = responseBuffer.array();
        int responseID = parseTwoBytesToInt(response[0],response[1]);
        int QR = (response[2] & 0x80) >>> 7;
        int opCode = (response[2] & 0x78) >>> 3;
        int AA = (response[2] & 0x04) >>> 2;
        int TC = (response[2] & 0x02) >>> 1;
        int RD = response[2] & 0x01;

        if (verboseTracing) {
            System.out.println("Response ID: " + responseID + " Authoritative = " + (AA == 1));
        }

        int RA = response[3] & 0x80;
        int rCode = response[3] & 0x0F;
        if (rCode == 3 || rCode == 5) {
            return null;
        }

        int QDCOUNT = parseTwoBytesToInt(response[4], response[5]);
        int ANCOUNT = parseTwoBytesToInt(response[6], response[7]);
        int NSCOUNT = parseTwoBytesToInt(response[8], response[9]);
        int ARCOUNT = parseTwoBytesToInt(response[10], response[11]);

        decodingIndex = 12;
        StringBuilder QName = new StringBuilder();
        while(true) {
            int partialLength = response[decodingIndex++] & 0xff;
            if (partialLength == 0) {
                break;
            }
            for (int i = 0; i < partialLength; i++) {
                char c = (char) (response[decodingIndex++] & 0xff);
                QName.append(c);
            }
            QName.append('.');
        }

        int QTYPE = parseTwoBytesToInt(response[decodingIndex++], response[decodingIndex++]);
        int QCLASS = parseTwoBytesToInt(response[decodingIndex++], response[decodingIndex++]);

        ResourceRecord rRecord;

        if (verboseTracing) {
            System.out.println("  Answers (" + ANCOUNT + ")");
        }
        for (int i = 0; i < ANCOUNT; i++) {
            rRecord = decodeAndCacheSingleRecord(response);
            answers.add(rRecord);
        }

        if (verboseTracing) {
            System.out.println("  Nameservers (" + NSCOUNT + ")");
        }
        for (int i=0; i < NSCOUNT; i++) {
            rRecord = decodeAndCacheSingleRecord(response);
            nameServers.add(rRecord);
            if (rRecord != null) {
                nameServers.add(rRecord);
            }
        }

        if (verboseTracing) {
            System.out.println("  Additional Information (" + ARCOUNT + ")");
        }
        for (int i = 0; i < ARCOUNT; i++) {
            rRecord = decodeAndCacheSingleRecord(response);
            if (rRecord != null) {
                additional.add(rRecord);
            }
        }

        addToCache(cache);

//        if (AA == 1 || rCode != 0) {
            return nameServers;
//        } else {
//            return null;
//        }
    }

    private static ResourceRecord decodeAndCacheSingleRecord(byte[] response) {
        ResourceRecord record = null;
        String hostName = parseHostName(response, decodingIndex);
        int typeCode = parseTwoBytesToInt(response[decodingIndex++], response[decodingIndex++]);
        int classCode = parseTwoBytesToInt(response[decodingIndex++], response[decodingIndex++]);
        int b1 = decodingIndex++;
        int b2 = decodingIndex++;
        int b3 = decodingIndex++;
        int b4 = decodingIndex++;
        long ttl = (((response[b1] & 0xff) << 24) + ((response[b2] & 0xff) << 16) +
                ((response[b3] & 0xff) << 8) + (response[b4] & 0xff));
        int RDataLength = parseTwoBytesToInt(response[decodingIndex++], response[decodingIndex++]);
        boolean unknownHostError = false;
        String address = "";
        if (typeCode == RecordType.A.getCode()) {
            for (int i = 0; i < RDataLength; i++) {
                address += response[decodingIndex++] & 0xff;
                if (i != RDataLength - 1) {
                    address += '.';
                }
            }
            InetAddress inetAddress;
            try {
                inetAddress = InetAddress.getByName(address);
                record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), ttl, inetAddress);
                verbosePrintResourceRecord(record, 0);
            } catch (UnknownHostException e) {
                unknownHostError = true;
            }
        } else if (typeCode == RecordType.AAAA.getCode()) {
            for (int i = 0; i < RDataLength / 2; i++) {
                int octet = parseTwoBytesToInt(response[decodingIndex++], response[decodingIndex++]);
                address += Integer.toHexString(octet) + ":";
            }
            address = address.substring(0, address.length() - 1);
            InetAddress inetAddress;
            try {
                inetAddress = InetAddress.getByName(address);
                record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), ttl, inetAddress);
                verbosePrintResourceRecord(record, 0);
            } catch (UnknownHostException e) {
                unknownHostError = true;
            }
        } else if (typeCode == RecordType.NS.getCode() || typeCode == RecordType.CNAME.getCode()) {
            String data = parseHostName(response, decodingIndex);
            record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), ttl, data);
            verbosePrintResourceRecord(record, 0);
        } else {
            String data = parseHostName(response, decodingIndex);
            record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), ttl, "----");
            verbosePrintResourceRecord(record, 0);
        }

        return record;
    }

    private static String parseHostName(byte[] response, int index) {
        String name = "";
        while (true) {
            int partialLength = response[index++] & 0xff;
            if (partialLength == 0) {
                break;
            } else if (partialLength < 192) {
                for (int i = 0; i < partialLength; i++) {
                    char c = (char) (response[index++] & 0xff);
                    name += c;
                }
            } else {
                int newIndex = (response[index++] & 0xff) + 256 * (partialLength - 192);
                name += parseHostName(response, newIndex);
                break;
            }
            name += '.';
        }

        decodingIndex = index;
        if (name.length() > 0 && name.charAt(name.length() - 1) == '.') {
            name = name.substring(0, name.length() - 1);
        }
        return name.toString();
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    public static int getNewUniqueQueryID() {
        int rtn = random.nextInt(65536);
        for (int i = 0; i < totalQuery; i++) {
            if (generatedQueryID[i] == rtn) {
                return getNewUniqueQueryID();
            }
        }
        generatedQueryID[totalQuery++] = rtn;
        return rtn;
    }

    private static void verbosePrint(int qID, DNSNode node, InetAddress server) {
        System.out.println("Query ID     " + qID + " " + node.getHostName() + "  " + node.getType() + " --> " + server.getHostAddress());
    }

    private static void addToCache(DNSCache cache) {

        for (ResourceRecord record : answers) {
            cache.addResult(record);
        }

        for (ResourceRecord record : nameServers) {
            cache.addResult(record);
        }

        for (ResourceRecord record : additional) {
            cache.addResult(record);
        }
    }
}


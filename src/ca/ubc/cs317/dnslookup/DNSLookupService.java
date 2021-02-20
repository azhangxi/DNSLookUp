package ca.ubc.cs317.dnslookup;

import javax.swing.text.rtf.RTFEditorKit;
import java.io.Console;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.*;

public class DNSLookupService {

    private static boolean p1Flag = false; // isolating part 1
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static InetAddress rootServer;
    private static DNSCache cache = DNSCache.getInstance();
    private static RecordType currentType;
    private static boolean querySuccess = true;
    private static int previousQueryID = -1;

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length == 2 && args[1].equals("-p1")) {
            p1Flag = true;
        } else if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            DNSQueryHandler.openSocket();
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    boolean verboseTracing = false;
                    if (commandArgs[1].equalsIgnoreCase("on")) {
                        verboseTracing = true;
                        DNSQueryHandler.setVerboseTracing(true);
                    }
                    else if (commandArgs[1].equalsIgnoreCase("off")) {
                        DNSQueryHandler.setVerboseTracing(false);
                    }
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
            }

        } while (true);

        DNSQueryHandler.closeSocket();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        currentType = type;
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the results for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
//        System.out.println("TEST +++++  1  +++++ TEST");
        currentType = node.getType();

        if (p1Flag) { // For isolating part 1 testing only
            Set<ResourceRecord> rtn = retrieveResultsFromServer(node, rootServer);
            return rtn;
        } else if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
//        System.out.println("TEST +++++  2  +++++ TEST");
        if (cache.getCachedResults(node).isEmpty()) {
            retrieveResultsFromServer(node, rootServer);
//            System.out.println("TEST +++++  3  +++++ TEST");
            if (!cache.getCachedResults(node).isEmpty()) {
            } else {
                // check for CNAME
                DNSNode cNameNode = new DNSNode(node.getHostName(), RecordType.CNAME);
                List<ResourceRecord> cNameResults = new ArrayList<ResourceRecord>(cache.getCachedResults(cNameNode));
//                System.out.println("TEST +++++  4  +++++ TEST");
                if (!cNameResults.isEmpty()) {
                    Set<ResourceRecord> allResults = new HashSet<ResourceRecord>();
                    for (ResourceRecord cnameRecord : cache.getCachedResults(cNameNode)){
                        DNSNode newNewNode = new DNSNode(cnameRecord.getTextResult(), node.getType());
                        allResults.addAll(getResults(newNewNode, indirectionLevel + 1));
                    }
                    return allResults;
                } else {
                    if (rootServer != null) {
                        Set<ResourceRecord> nameServer = retrieveResultsFromServer(node, rootServer);
                        // update cache results
                        Set<ResourceRecord> cachedResults = cache.getCachedResults(node);
                        if (!cachedResults.isEmpty()){
                            return cachedResults;
                        }
                    }
                }
            }
        }
        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static Set<ResourceRecord> retrieveResultsFromServer(DNSNode node, InetAddress server) {
        byte[] message = new byte[512]; // query is no longer than 512 bytes
        DNSServerResponse serverResponse = null;
//        System.out.println("TEST -----  1  ----- TEST");
        try {
            int id;
            if (querySuccess) {
                id = DNSQueryHandler.getNewUniqueQueryID();
            } else {
                id = previousQueryID;
            }
            serverResponse = DNSQueryHandler.buildAndSendQuery(message, server, node, id);
//            System.out.println("TEST -----  2  ----- TEST");

//            System.out.println("TEST -----  3  ----- TEST");
            Set<ResourceRecord> nameservers = DNSQueryHandler.decodeAndCacheResponse(id,
                    serverResponse.getResponse(),
                    cache);
            if (nameservers == null) nameservers = Collections.emptySet();
            if (p1Flag) return nameservers; // For testing part 1 only
            querySuccess = true;
            previousQueryID = serverResponse.getTransactionID();
            queryNextLevel(node, nameservers);
//            System.out.println("TEST -----  4  ----- TEST");
        } catch (SocketTimeoutException e) {
            if (querySuccess) {
                previousQueryID = serverResponse.getTransactionID();
                querySuccess = false;
                retrieveResultsFromServer(node, server);
            } else {
                querySuccess = true;
            }
        } catch (IOException | NullPointerException ignored){}
        previousQueryID = serverResponse.getTransactionID();
//        System.out.println("TEST -----  5  ----- TEST");
        return null;
    }

    /**
     * Query the next level DNS Server, if necessary
     *
     * @param node        Host name and record type of the query.
     * @param nameservers List of name servers returned from the previous level to query the next level.
     */
    private static void queryNextLevel(DNSNode node, Set<ResourceRecord> nameservers) {
        if (!DNSQueryHandler.answers.isEmpty()) {
//            System.out.println("TEST ~~~~~  1  ~~~~~ TEST");
            return;
        }
//        System.out.println("TEST ~~~~~  2  ~~~~~ TEST");
        boolean foundNSAddress = false;
        List<ResourceRecord> nsArr = new ArrayList<>();
        for (ResourceRecord rr : nameservers) {
            if (rr.getType() == RecordType.NS) {
                nsArr.add(rr);
            }
        }
        if (nsArr.isEmpty()) {
            return;
        }
//        System.out.println("TEST ~~~~~  3  ~~~~~ TEST");
        for (ResourceRecord rr : nsArr) {
            String nsName = rr.getTextResult();
            InetAddress address = findNameServerAddress(nsName);
            if (address == null) {
//                System.out.println("TEST ~~~~~  4  ~~~~~ TEST");
                continue;
            } else {
//                System.out.println("TEST ~~~~~  5  ~~~~~ TEST");
                foundNSAddress = true;
                retrieveResultsFromServer(node, address);
                break;
            }
        }
//        System.out.println("TEST ~~~~~  6  ~~~~~ TEST");
        if (!foundNSAddress) {
            ResourceRecord firstNsRecord = nsArr.get(0);
            String nsName = firstNsRecord.getTextResult();
            DNSNode nsNode = new DNSNode(nsName, RecordType.A);
            retrieveResultsFromServer(nsNode, rootServer);
            InetAddress address = findNameServerAddress(nsName);
            if (address == null) {
//                System.out.println("TEST ~~~~~  7  ~~~~~ TEST");
                return;
            } else {
//                System.out.println("TEST ~~~~~  8  ~~~~~ TEST");
                foundNSAddress = true;
                retrieveResultsFromServer(node, address);
                return;
            }
        }
    }

    private static InetAddress findNameServerAddress(String nsName) {
        DNSNode ipv4Node = new DNSNode(nsName, RecordType.A);
        List<ResourceRecord> matches = new ArrayList<ResourceRecord>(cache.getCachedResults(ipv4Node));
        if (!matches.isEmpty()) {
            return matches.get(0).getInetResult();
        } else {
            return null;
        }
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}


DataPeerExchange

DataPeerExchange is a simple client server setup to make files available for download without using a cloud server 
or exposing the protected local network or file system. The communication between client and server is
protected using RSA and AES encryption.

How it works

The party providing files needs the server app, the party receiving files needs the client app.

You may need to install some packages before the software works: pycryptodome

Step 0 [Server / Client]:
Install the app locally

    git clone https://github.com/liebrandapps/DataPeerExchange.git

Step 1 [Server]:
Expose a port on your router for UDP traffic and direct the traffic to the host in your LAN where you
installed the app in step 0. Note: your port must be reachable from the public internet, otherwise
the client will never be able to communicate with the server.

Create a file "dpexServer.ini" in the root directory of the cloned project:

    [general]
    serverHost=<public ip goes here>
    serverPort=<port number goes here>

Assumption is that public and local port are identical.


Step 2 [Client]:
The client runs his app:
    
    export PYTHONPATH=.
    python3 myio/liebrand/dpex/client.py init

As a result a JSON string with the (generated) public key is printed to stdout. Send this via email to the provider
of the server.

Step 3 [Server]:
The server provider saves the JSON to a file and runs the server app:

    export PYTHONPATH=.
    python3 myio/liebrand/dpex/server.py add sampleClient.json

The result is another JSON string also printed to stdout. It contains the (generated) server public key and
some data encrypted with the clients' public key. Send this json via mail to the client.

Now you should have a "clients" directory with another subdirectory below. This lower subdirectory is the data 
of the first client. Copy any files that the client should be able to download into the 'outgoing' directory.

Step 4 [Client]:
The received JSON data should be saved to a file (e.g. sampleServer.json). 

    python3 myio/liebrand/dpex/client.py update sampleServer.jon

Now the client is configured to run with the server.

Step 5 [Server]:
Start the server with parameter "serve" and leave it running:

    python3 myio/liebrand/dpex/server.py serve


Step 6 [Client]:
Retrieve list of available files:

    python3 myio/liebrand/dpex/client.py ls

(Needless to say that the server needs to be running on the other end (Step 5))

Step 7 [Client]:
Get a file

    python3 myio/liebrand/dpex/client.py get filename
    
If the filename contains spaces, make sure that is it enclosed in quotes. The script 'dpexClient.sh' can also be used.

TODOs:
+ server is currently not multi-threaded (i.e., a new thread should be created when a request is being processed)
+ Resume Functionality in case there is already some data downloaded
+ getAll function to retrieve everything from the server
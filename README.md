# C2CC
## Computer 2 Computer Communications
C2CC is a console-based chat application written in JavaScript which can be run by Node.JS.
C2CC comes with some advantages over the conventional GUI based chat apps:
- **It's  quick***
    Since C2CC has no GUI to load, it is quick to start up.
- **It's open source**
    C2CC is completely open source. This means you can edit C2CC to your will to change how C2CC behaves for you and just re-compile it.
- **It's private**
    Unlike traditional chat apps, you have the ability to host your own C2CC server, meaning you have control over C2CC messages and it gives you some sense of privacy knowing someone else can't look into your messages
- **It's secure**
    Say you don't have server equipment and opt to use someone else's C2CC server - you can still rest assured because all C2CC messages are encrypted with double encryption: a client to clien one wrapped in a server to client one. This means, even if the server was maliciously reprogrammed, they cannot see your messages. You would also know about a maliciously programmed server because the message will not recieve the client. This can be spotted due to Acknowledgements, when you send a message to your friend via C2CC, your C2CC creates a packet, encrypted with your friend's public key so the server can't read it, with your message and a string of words to return to acknowledge your friend's end has recieved the message, if your client has not recieved the acknowledgement, you know something is up and either your message can't get to your friend or your friend can't get you.
- **It's unintrusive**
    Our software, your rules. We don't force a large tonne of advertising upon you, or even tell you to update!**
- **It's Portable**
    No 5000 files to carry around, just one executable file and a "data/" directory for C2CC clients and a "users.json" file for C2CC servers. This enables portability, just carry your stuff wherever you need it!

*C2CC is quick to start up, however message transmission speeds depend on the latency of the messaging server, your internet connection speed, your computer processing power and server processing power

**To protect servers and other users, servers will refuse connections if your client is older (or newer for that matter) than the version the server supports

## Installation
Go to the releases tab and either install the server-OSHERE.zip or client-OSHERE.zip depending on what you want to install. (Where "OSHERE" is the name of your OS, either Windows, MacOS or Linux)

### For clients
Extract the files from client.zip into a folder, possibly a new folder as the program will create its own files.
Edit the config.json file, put your config values in there, most importantly fill in the C2CC_ID and SERVER_ADDR, you may wish to change other values.
Run the C2CC executable (the name varies with the OS, for Windows its "c2cc.exe", for Linux its just "c2cc" (which you run in the terminal by doing "chmod +x c2cc" and then "./c2cc"), etc.) to get set up.

### For servers
Extract the files from server.zip into a folder, possibly a new folder as the program will create its own files.
Edit the config.json file, no value change is needed but you may wish to change the server port.
Run the C2CC Server executable (the name varies with the OS, for Windows its "c2cc_server.exe", for Linux its just "c2cc_server" (which you run in the terminal by doing "chmod +x c2cc_server" and then "./c2cc_server"), etc.) to get set up.

## Updating
Updating is as simple as getting the latest zip archive of the software you want from the C2CC repo, and replacing the old executable file with the new one and re-running the program.
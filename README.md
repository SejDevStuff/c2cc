# C2CC

## Computer 2 Computer Communications

C2CC is a console-based chat application written in JavaScript which can be run by Node.JS.
C2CC comes with some advantages over the conventional GUI based chat apps:

- **It's quick\***
  Since C2CC has no GUI to load, it is quick to start up.
- **It's open source**
  C2CC is completely open source. This means you can edit C2CC to your will to change how C2CC behaves for you and just re-compile it. This also means we don't put in any nasty tracking malware in our software. If you aren't so
  sure, look at the code and after confirming nothing bad's in there, compile the program yourself from source using
  a tool like "nexe", or use it from source (requires extra steps like installing dependencies)
- **It's private**
  Unlike traditional chat apps, you have the ability to host your own C2CC server, meaning you have control over C2CC messages and it gives you some sense of privacy knowing someone else can't look into your messages
- **It's secure**
  Keep your messages free from hackers.
  Say you don't have server equipment and opt to use someone else's C2CC server - you can still rest easy because all C2CC messages are encrypted with double encryption: a client to client one wrapped in a server to client one. This means, even if the server was maliciously reprogrammed, they cannot see your messages. You would also know about a maliciously programmed server because the client will not recieve the message.
  Also, you can opt in to using encryption for your server authentication data and friends list, this means its even
  harder for someone to access your account if they have access to your data/ directory.
- **It's unintrusive**
  Our software, your rules. You do what you want, \*\*
- **It's portable**
  No 5000 files to carry around, just one executable file and a ".c2cc" directory. This enables portability, just carry your stuff wherever you need it!

\*C2CC is quick to start up, however message transmission speeds depend on the latency of the messaging server, your internet connection speed, your computer processing power and server processing power

\*\*To protect servers and other users, servers will refuse connections if your client is older (or newer for that matter) than the version the server supports. This is because if the client has an exploit which is bad for the server, it can stay somewhat protected.

## Installation

Go to the releases tab and either install the server-OSHERE.zip or client-OSHERE.zip depending on what you want to install. (Where "OSHERE" is the name of your OS, either win, macos or linux)

### For clients

- Extract the files from client-OSHERE.zip (OSHERE is your OS, win, macos, or linux) into a folder.

- Run the C2CC executable (the name varies with the OS, for Windows its "c2cc-win.exe", for Linux its "c2cc-linux" (which you run in the terminal by doing "chmod +x c2cc-linux" and then "./c2cc-linux"), etc.) to get set up.

- On the first time you run the program, it will create a ".c2cc" directory in your HOME folder (eg: for linux its '/home/USERNAME' and for windows its 'C:\Users\USERNAME\', etc) and inside the .c2cc folder it will create a 'client' folder. Your config is found in this folder, it is called 'c2cc_client_config.js'. If it is successful, it will tell you so.

- Edit the c2cc_client_config.js file, put your config values in there, most importantly fill in the C2CC_ID, HOSTNAME, SERVER_ADDR and ENCRYPT_DATA values, you may wish to change other values.

### For servers

- Extract the files from server-OSHERE.zip (OSHERE is your OS, win, macos, or linux) into a folder.

- Run the C2CC executable (the name varies with the OS, for Windows its "c2cc-server-win.exe", for Linux its "c2cc-server-linux" (which you run in the terminal by doing "chmod +x c2cc-server-linux" and then "./c2cc-server-linux"), etc.) to get set up.

- On the first time you run the program, it will create a ".c2cc" directory in your HOME folder (eg: for linux its '/home/USERNAME' and for windows its 'C:\Users\USERNAME\', etc) and inside the .c2cc folder it will create a 'server' folder. Your config is found in this folder, it is called 'c2cc_server_config.js'. You do not need to change any values by default

## Updating

Updating is as simple as getting the latest zip archive of the software you want from the C2CC repo, and replacing the old executable file with the new one and re-running the program.

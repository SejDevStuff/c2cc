// Hostname: the name that shows up on your prompt, and to others when you send a message to them
// Cannot be seen by messaging server - only by your peer, due to double encryption (see below)
module.exports.HOSTNAME = "C2CCDefault";

/*
    Server Address: the url of the server which handles the messages and is responsible for sending
    them to each peer. Although the actual message and your username cannot be seen by the server
    even if it was reprogrammed to be malicious (due to double encryption), it can still see your 
    IP and possibly where you live

    Make sure to use a server you trust, or you can host your own server and configure it

    Make sure to put 'SERVER_URL:SERVER_PORT'
    If server port is not specified, program will use default port: 6162

    EXCLUDE "http://" as this will be added.
*/
module.exports.SERVER_ADDR = "localhost";


/*
    Your c2cc id is what others use to contact you, it is like an invite ID
    It is reccommended to make it short so its easy to remember for others
*/
module.exports.C2CC_ID = "SejIsEpic";

/*
    Data directory.
    Where the program stores your data.
    If it exists, the program must have permissions to access it.
    If it doesn't exist, the program will create it.
    This is where your server, friends and other data goes.
*/
module.exports.DATA_DIR = "/data/";

/*
    The name of your local friends list file
*/
module.exports.FRIENDS_LIST = "friends.dat"

/*
    Location of server uuid file
*/
module.exports.SRVR_UUID = "servers.dat"

/*
    Location of Master Server Key Hash
*/
module.exports.MASTER_HASH_LOC = "master_hash.dat"

/*
    How to handle peer connection requests

    "SYNC"
    This allows you to talk to one person at a time

    "ASYNC" (!!! NOT SUPPORTED YET !!!)
    This allows you to talk to more than one person at a time,
    but you can only respond to one person. The other people's messages
    are shown in the background

    "BLOCKALL"
    This is like a "do not disturb" and blocks all incoming connections
*/
module.exports.PEER_CONN_HANDLING = "SYNC"

/*
    Prefix which allows you to run commands while in a chat
*/
module.exports.CHAT_COMMAND_PREFIX = "/"

/*
    GIVE_SRVR_CHOICE = On startup, give the choice to either connect to the server listed on the config or enter your own server details
    If true, you will be given the opportunity to enter your own server details on every startup. If false, it will take the server address from the config all the time
*/
module.exports.GIVE_SRVR_CHOICE = false;

/*
    Encrypt data:
        true = Encrypts your server data and friends list, requires a master password on program startup
        Pros: Better data protection
        Cons: Slower performance*.

        false = Doesn't encrypt data
        Pros: faster performance*
        Cons: data is not protected - authentication ID loggers can maybe get your token and pretend to be you

        * only interacting with your friends list and connection to the server are affected, everything
        else stays the same

        WARNING! Once this is set to a value, it cannot be set to another value again unless you delete your 
        server and friend data.
*/
module.exports.ENCRYPT_DATA = true;

/*
    Notify you with a message
    when a peer sent a message if you have not sent a message in 30 seconds.
*/
module.exports.NOTIFY_ME = true;
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
    The name of your local friends list file
*/
module.exports.FRIENDS_LIST = "data/friends.dat"

/*
    Location of server uuid file
*/
module.exports.SRVR_UUID = "data/servers.dat"
/*
    The maximum connections a server can take before it 
    rejects clients, even numbers are preferred as
    a full connection needs two peers.
    ie: If "MAX_CONNECTIONS" was 9, that means there
    will be 4 full connections but someone cannot talk
    to anyone
*/
module.exports.MAX_CONNECTIONS = 10;

/*
    The listening port of the server
*/
module.exports.LISTENING_PORT = 6162;

/*
    The name of the server, will be shown to the client on connect
*/
module.exports.HOSTNAME = "Default"

/*
    The message of the day of the server, will be shown to the client on connect
*/
module.exports.MOTD = "A default C2CC server"
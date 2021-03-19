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


/*
    Autoban: This allows the server to automatically ban users if they seem to attack the server
*/
module.exports.AUTO_BAN = true;

// AUTO BAN THRESHOLDS //

/*
    === Malformed requests thresholds ===
    A malformed request contains illegal objects like "null" or "undefined" that causes the server
    to crash.
    This is the amount of malformed requests a client can make before they get
    banned
*/
module.exports.MAL_REQ_THRESHOLD = 5;
/*
    For how much time should a client be banned if they exceed MAL_REQ_THRESHOLD and AUTO_BAN is on?
    (milliseconds)
    Default is 1 week (7 days = 604800000 ms)
*/
module.exports.MAL_REQ_BAN_DURATION = 604800000;
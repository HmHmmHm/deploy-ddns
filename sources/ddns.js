var ndns = require('native-dns');

class DDNS {
    /**
     * @param {function} onRequest
     * @param {function} onError
     * @param {function} onSocketError
     */
    static createDDNSServer(onRequest, onError, onSocketError) {
        let addListener = (server) => {
            if (!server) return null;
            if (onRequest != undefined) server.on('request', onRequest);
            if (onError != undefined) server.on('error', onError);
            if (onSocketError != undefined) server.on('socketError', onSocketError);
            return server;
        }

        let udpServer = addListener(ndns.createServer());
        let tcpServer = addListener(ndns.createTCPServer());

        return {
            udpServer: udpServer,
            tcpServer: tcpServer
        }
    }

    /**
     * @param {number} port
     * @param {string} address
     * @param {object} udpServer
     * @param {object} tcpServer
     * @param {function} onRequest
     * @param {function} onError
     * @param {function} onSocketError
     */
    static listen(port, address, udpServer, tcpServer, onRequest, onError, onSocketError) {
        if (port == undefined) port = 53;
        if (address == undefined) address = '0.0.0.0';
        if (udpServer == undefined || tcpServer == undefined) {
            let servers = DeployDDNS.createDDNSServer(onRequest, onError, onSocketError);
            udpServer = servers.udpServer;
            tcpServer = servers.tcpServer;
        }

        udpServer.serve(port, address);
        tcpServer.serve(port, address);

        return {
            udpServer: udpServer,
            tcpServer: tcpServer
        }
    }
}

module.exports = DDNS;

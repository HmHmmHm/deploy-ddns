let DeployDDNS = require('../deploy-ddns.js');
let Protocol = require('./protocol.js');

let blockList = {};
let allowedList = {};

let allowedDataPath = path.join(process.cwd(), 'allowed-list.json');
if (FileSystem.existsSync(allowedDataPath)) allowedList = require(allowedDataPath);

let allowedDataUpdate = () =>
    FileSystem.writeFileSync(allowedDataPath, JSON.stringify(allowedList), 'utf-8');

/**
 * @param {string} message
 */
let packetCorrectCheck = (message) => {
    let packet = null;

    try {
        packet = JSON.parse(message);
    } catch {
        return;
    }

    if (packet === null || packet === undefined) return null;
    if (!Array.isArray(packet) || packet.length == 0) return null;

    let pid = packet[0];
    let data = null;
    if (packet.length >= 2) data = packet[1];

    return {
        pid: pid,
        data: data
    };
}

/**
 * @param {number} pid
 * @param {object} data
 * @return {booolean}
 */
let accessAllowedCheck = (pid, data, info) => {
    if (pid != Protocol.HAND_SHAKE_USE_JWT && pid != Protocol.HAND_SHAKE_USE_PRIV_PEM) {
        if (typeof(allowedList[info.address]) == 'undefined')
            return Protocol.NOT_HANDSHAKED;

        switch (pid) {
            case Protocol.ADD_DNS:
            case Protocol.DELETE_DNS_TO_IP:
            case Protocol.DELETE_DNS_TO_NAME:
            case Protocol.ADD_DNS_FAST_FORWARD:
            case Protocol.DELETE_DNS_FAST_FORWARD_TO_CLIENT_IP:
            case Protocol.DELETE_DNS_FAST_FORWARD_TO_SERVER_IP:
            case Protocol.GET_DNS:
            case Protocol.GET_FAST_FORWARD:
                if (typeof(allowedList[info.address]['pem']) == 'undefined') {
                    if (typeof(data['domainName']) == 'undefined')
                        return Protocol.PACKET_IS_WRONG;
                    if (data['domainName'] == 'pem')
                        return Protocol.NOT_AUTHORIZED;
                    if (typeof(allowedList[info.address][data['domainName']]) == 'undefined')
                        return Protocol.NOT_AUTHORIZED;
                    if (allowedList[info.address][data['domainName']] == false)
                        return Protocol.NOT_AUTHORIZED;
                    break;
                }
                break;
            case CLEAR_DNS:
                if (typeof(allowedList[info.address]['pem']) == 'undefined')
                    return Protocol.NOT_AUTHORIZED;
                break;
        }
    }
    return true;
};

let checkPacketIsWrong() {
    let send = arguments[0];
    let pid = arguments[1];
    let info = arguments[2];
    for (let i = 3; i < arguments.length; i++) {
        if (arguments[i] === 'undefined' || arguments[i] === undefined || arguments[i] === null) {
            send([Protocol.PACKET_IS_WRONG, {
                wrongPid: pid
            }]);
            return true;
        }
    }
    return false;
}

class UDPManager {
    static createServer(port, address) {
        if (port == undefined) port = 19100;
        if (address == undefined) address = '0.0.0.0';

        let udpSocket = require('dgram').createSocket('udp4');

        let errorHandler = (error) => {
            DeployDDNS.requestLog('[ERROR] SOCKET ERROR OCCURS IN UDP MANAGER.');
            DeployDDNS.requestLog(error.stack);
        }

        let messageHandler = (message, info) => {
            //CHECK SENDER HAS BANNED
            if (typeof(blockList[info.address]) != 'undefined' && blockList[info.address] >= 3) return;

            //CHECK PACKET IS CORRECT
            let parsedMessage = packetCorrectCheck(message);
            if (parsedMessage == null) return;
            let pid = parsedMessage.pid;
            let data = parsedMessage.data;

            //UDP PACKET SEND FUNCTION
            let send = (buffer) => udpSocket.send(buffer, info.port, info.address, errorHandler);

            let resultResponse = (success) => {
                return {
                    success: success
                };
            };

            //CHECK HANDSHAKE HAS EXIST BEFORE.
            //CHECK DOMAIN ACCESS ALLOWED.
            let permissionCheck = accessAllowedCheck(pid, data, info);
            if (permissionCheck != true) {
                send([permissionCheck, resultResponse(false)]);
                return;
            }

            //PROTOCOL PROCESS
            switch (pid) {
                case Protocol.HAND_SHAKE_USE_JWT:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x0, {jwt:*, domain:*}]
                     * response:[0x0, {success:boolean}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data, typeof(data['jwt']), typeof(data['domain']))) return;

                    let shakeJWTData = data['jwt'];
                    let accessDomain = data['domain'];
                    if (shakeJWTData.length > 3000) return;

                    DeployDDNS.checkJwt(shakeJWTData, accessDomain, (success, comment) => {
                        if (accessDomain == 'pem') success = false;
                        if (success) {
                            if (typeof(allowedList[info.address]) == 'undefined')
                                allowedList[info.address] = {};
                            allowedList[info.address][accessDomain] = true;
                            allowedDataUpdate();
                        } else {
                            if (typeof(blockList[info.address]) == 'undefined')
                                blockList[info.address] = 0;
                            ++blockList[info.address];
                        }

                        DeployDDNS.requestLog(`TRIED TO JWT HANDSHAKE FROM '${info.address}'. RESULT: ${success}`);
                        send([pid, resultResponse(success)]);
                    });
                    break;
                case Protocol.HAND_SHAKE_USE_PRIV_PEM:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x1, {pem:*}]
                     * response:[0x1, {success:boolean}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data, typeof(data['pem']))) return;

                    let shakePEMData = data['pem'];
                    if (shakePEMData.length > 3000) return;

                    let success = DeployDDNS.checkPrivkeyPem(shakePEMData);
                    if (success) {
                        if (typeof(allowedList[info.address]) == 'undefined')
                            allowedList[info.address] = {};
                        allowedList[info.address]['pem'] = true;
                        allowedDataUpdate();
                    } else {
                        if (typeof(blockList[info.address]) == 'undefined')
                            blockList[info.address] = 0;
                        ++blockList[info.address];
                    }

                    DeployDDNS.requestLog(`TRIED TO PEM HANDSHAKE FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, resultResponse(success)]);
                    break;
                case Protocol.ADD_DNS:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x2, {domainName:*, serverIp:*, serverName:*}]
                     * response:[0x2, {success:boolean}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data,
                            typeof(data['domainName']),
                            typeof(data['serverIp']),
                            typeof(data['serverName']))) return;

                    let domainName = data['domainName'];
                    let serverIp = data['serverIp'];
                    let serverName = data['serverName'];

                    DeployDDNS.addDNS(domainName, serverIp, serverName);
                    DeployDDNS.requestLog(`UPDATED '${domainName}' DNS ADDED '${serverIp}' FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, resultResponse(true)]);
                    break;
                case Protocol.DELETE_DNS_TO_IP:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x3, {domainName:*, serverIp:*, }]
                     * response:[0x3, {success:boolean}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data,
                            typeof(data['domainName']),
                            typeof(data['serverIp']))) return;

                    let domainName = data['domainName'];
                    let serverIp = data['serverIp'];

                    let success = DeployDDNS.deleteDNStoIP(domainName, serverIp);
                    DeployDDNS.requestLog(`UPDATED '${domainName}' DNS DELETED '${serverIp}' FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, resultResponse(success)]);
                    break;
                case Protocol.DELETE_DNS_TO_NAME:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x4, {domainName:*, serverName:*}]
                     * response:[0x4, {success:boolean}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data,
                            typeof(data['domainName']),
                            typeof(data['serverName']))) return;

                    let domainName = data['domainName'];
                    let serverName = data['serverName'];

                    let success = DeployDDNS.deleteDNStoName(domainName, serverName);
                    DeployDDNS.requestLog(`UPDATED '${domainName}' DNS DELETED '${serverName}' FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, resultResponse(success)]);
                    break;
                case Protocol.CLEAR_DNS:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x5]
                     * response:[0x5, {success:boolean}]
                     */
                    DeployDDNS.clearDNS();
                    //TODO CLEAR THE ALL LOGs
                    DeployDDNS.requestLog(`ALL DNS DATA CLEARED FROM '${info.address}'.`);
                    send([pid, resultResponse(success)]);
                    break;
                case Protocol.ADD_DNS_FAST_FORWARD:
                    /**
                     * @description
                     * JSON
                     * request:[0x6, {domainName:*, clientIp:*, serverIp:*}]
                     * response:[0x6, {success:boolean}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data,
                            typeof(data['domainName']),
                            typeof(data['clientIp']),
                            typeof(data['serverIp']))) return;

                    let domainName = data['domainName'];
                    let clientIp = data['clientIp'];
                    let serverIp = data['serverIp'];

                    let success = DeployDDNS.addDNSFastForward(domainName, clientIp, serverIp);
                    DeployDDNS.requestLog(`FASTFORWARDED ADDED '${domainName}' DNS CLIENT '${clientIp}' TO ${serverIp} FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, resultResponse(success)]);
                    break;
                case Protocol.DELETE_DNS_FAST_FORWARD_TO_CLIENT_IP:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x7, {domainName:*, clientIp:*}]
                     * response:[0x7, {success:boolean}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data,
                            typeof(data['domainName']),
                            typeof(data['clientIp']))) return;

                    let domainName = data['domainName'];
                    let clientIp = data['clientIp'];

                    let success = DeployDDNS.deleteDNSFastForwardToClientIp(domainName, clientIp);
                    DeployDDNS.requestLog(`FASTFORWARDED DELETED '${domainName}' DNS CLIENT '${clientIp}' FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, resultResponse(success)]);
                    break;
                case Protocol.DELETE_DNS_FAST_FORWARD_TO_SERVER_IP:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x8, {domainName:*, serverIp:*}]
                     * response:[0x8, {success:boolean}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data,
                            typeof(data['domainName']),
                            typeof(data['serverIp']))) return;

                    let domainName = data['domainName'];
                    let serverIp = data['serverIp'];

                    let success = DeployDDNS.deleteDNSFastForwardToServerIp(domainName, serverIp);
                    DeployDDNS.requestLog(`FASTFORWARDED DELETED '${domainName}' DNS SERVER '${serverIp}' FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, resultResponse(success)]);
                    break;
                case Protocol.GET_DNS:
                    /**
                     * @description
                     * type:JSON
                     * request:[0x9, {domainName:*}]
                     * response:[0x9, {*}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data,
                            typeof(data['domainName']))) return;

                    let domainName = data['domainName'];
                    let domainDNSData = DeployDDNS.getDomainDNSData(domainName);
                    DeployDDNS.requestLog(`QUERIED '${domainName}' DNS DATA FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, {
                        success: true,
                        domainDNSData: domainDNSData
                    }]);
                    break;
                case Protocol.GET_FAST_FORWARD:
                    /**
                     * @description
                     * type:JSON
                     * request:[0xA, {domainName:*}]
                     * response:[0xA, {*}]
                     */
                    if (checkPacketIsWrong(send, pid, info, data,
                            typeof(data['domainName']))) return;

                    let domainName = data['domainName'];
                    let domainDNSFastForwardData = DeployDDNS.getDomainDNSFastForwardData(domainName);
                    DeployDDNS.requestLog(`QUERIED '${domainName}' DNS FASTFORWARD DATA FROM '${info.address}'. RESULT: ${success}`);
                    send([pid, {
                        success: true,
                        domainDNSFastForwardData: domainDNSFastForwardData
                    }]);
                    break;
            }
        }

        udpSocket.on('error', errorHandler);
        udpSocket.on('message', messageHandler);
        udpSocket.bind({
            address: address,
            port: port
        });
        return udpSocket;
    }
}

module.exports = UDPManager;

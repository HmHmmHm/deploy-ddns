class Protocol {
    /**
     * @description
     * type:JSON
     * request:[0x0, {jwt:*, domain:*}]
     * response:[0x0, {success:boolean}]
     */
    static get HAND_SHAKE_USE_JWT() {
        return 0x0;
    }

    /**
     * @description
     * type:JSON
     * request:[0x1, {pem:*}]
     * response:[0x1, {success:boolean}]
     */
    static get HAND_SHAKE_USE_PRIV_PEM() {
        return 0x1;
    }

    /**
     * @description
     * type:JSON
     * request:[0x2, {domainName:*, serverIp:*, serverName:*}]
     * response:[0x2, {success:boolean}]
     */
    static get ADD_DNS() {
        return 0x2;
    }

    /**
     * @description
     * type:JSON
     * request:[0x3, {domainName:*, serverIp:*, }]
     * response:[0x3, {success:boolean}]
     */
    static get DELETE_DNS_TO_IP() {
        return 0x3;
    }

    /**
     * @description
     * type:JSON
     * request:[0x4, {domainName:*, serverName:*}]
     * response:[0x4, {success:boolean}]
     */
    static get DELETE_DNS_TO_NAME() {
        return 0x4;
    }

    /**
     * @description
     * type:JSON
     * request:[0x5]
     * response:[0x5, {success:boolean}]
     */
    static get CLEAR_DNS() {
        return 0x5;
    }

    /**
     * @description
     * JSON
     * request:[0x6, {domainName:*, clientIp:*, serverIp:*}]
     * response:[0x6, {success:boolean}]
     */
    static get ADD_DNS_FAST_FORWARD() {
        return 0x6;
    }

    /**
     * @description
     * type:JSON
     * request:[0x7, {domainName:*, clientIp:*}]
     * response:[0x7, {success:boolean}]
     */
    static get DELETE_DNS_FAST_FORWARD_TO_CLIENT_IP() {
        return 0x7;
    }

    /**
     * @description
     * type:JSON
     * request:[0x8, {domainName:*, serverIp:*}]
     * response:[0x8, {success:boolean}]
     */
    static get DELETE_DNS_FAST_FORWARD_TO_SERVER_IP() {
        return 0x8;
    }

    /**
     * @description
     * type:JSON
     * request:[0x9, {domainName:*}]
     * response:[0x9, {*}]
     */
    static get GET_DNS() {
        return 0x9;
    }

    /**
     * @description
     * type:JSON
     * request:[0xA, {domainName:*}]
     * response:[0xA, {*}]
     */
    static get GET_FAST_FORWARD() {
        return 0xA;
    }

    static get NOT_AUTHORIZED(){
        return 0xB;
    }

    static get NOT_HANDSHAKED(){
        return 0xC;
    }

    static get PACKET_IS_WRONG(){
        return 0xD;
    }
}

module.exports = Protocol;

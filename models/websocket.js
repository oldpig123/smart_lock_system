const WebSocket = require('ws');
const ws = new WebSocket('wss://192.168.1.150:8080', { rejectUnauthorized: false });
var status = false;

ws.on('message', function message(data) {
    console.log('received: %s', data);
    if (data == 'true') {
        status = true;
    }
    if (data == 'false') {
        status = false;
    }
    console.log(status);
});

function getstatus() {
    //console.log('function called');
    return status;
}
module.exports = {ws,getstatus};
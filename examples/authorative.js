var ndns = require('../lib/ndns');
var server = ndns.createServer('udp4');

var LOCAL_PORT = 53;
var ns_c = ndns.ns_class;
var ns_t = ndns.ns_type;

server.on("request", function(req, res) {
    res.setHeader(req.header);
    res.header.qr = 1;
    res.header.aa = 1;
    res.header.rd = 0;
    res.header.ra = 0;
    res.header.ancount = 0;
    for (var i = 0; i < req.q.length; i++) {
	res.q.add(req.q[i]);
	res.addRR(req.q[i].name, 0, ns_c.in, ns_t.txt, "Hello world");
	res.header.ancount++;
    }
    
    res.send();
});
server.bind(LOCAL_PORT);

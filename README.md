ndns -- dns client/server library for nodejs
==============================

## Synposis

An example DNS server written with node which responds 'Hello World':
var ndns = require('ndns');

	ndns.createServer('udp4', function (req, res) {
    	    res.setHeader(req.header);
    	    res.header.qr = 1;
	    res.header.aa = 1;
	    res.header.rd = 0;
	    res.header.ra = 0;
	    res.header.ancount = 0;
	    for (var i = 0; i < req.q.length; i++) {
		res.q.add(req.q[i]);
		res.addRR(req.q[i].name, 3600, ndns.ns_t.txt, "hello, world");
		res.header.ancount++;
	    }
	    res.send();
	}).bind(5300);

console.log("Server running at 0.0.0.0:5300")

To run the server, put the code into a file called example.js and execute it
with the node program:

> node example.js
> Server running at 0.0.0.0:5300

All of the examples in the documentation can be run similarly.

## ndns

To use the ndns server and client one must require('ndns').

DNS request messages are represented by an object like this:

{ header:
   { id: 39545
   , qr: 0
   , opcode: 0
   , aa: 0
   , tc: 0
   , rd: 1
   , ra: 0
   , z: 0
   , ad: 0
   , cd: 0
   , rcode: 0
   , qdcount: 1
   , ancount: 0
   , nscount: 0
   , arcount: 0
   }
, q: 
   { '0': 
      { name: 'example.com'
      , type: 1
      , class: 1
      }
   , length: 1
   }
, rr: 
   { '0': 
      { name: 'example.com'
      , ttl: 3600
      , class: 1
      , type: 16
      , rdata: ["hello, world"]
      }
   , length: 1
   }
}


## ndns.Server

This is a dgram.Socket with the following events:

Event: 'request'
function (request, response) {}

request is an instance of ndns.ServerRequest and response is an instance of
ndns.ServerResponse

ndns.createServer(type, requestListener)
Return a new dns server object

The requestListener is a function which is automatially added to the 'request'
event.

For documentation on dgram.Socket, see http://nodejs.org/api.html#dgram-267

## ndns.ServerRequest

This object is created internally by a DNS-server, not by the user, and passed
as the first argument to a 'request' listener
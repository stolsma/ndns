var sys = require('sys');

var debug;
var debugLevel = parseInt (process.env.NODE_DEBUG, 16);
if (debugLevel & 0x4) {
	debug = function (x) { sys.error ('NDNS: ' + x); };
} else {
	debug = function () { };
}

var dgram = require('dgram');
var events = require('events');
var Buffer = require('buffer').Buffer;

var FreeList = require('freelist').FreeList;

var ns_packsiz = 512;	// Default UDP Packet size
var ns_maxdname = 1025;	// Maximum domain name
var ns_maxmsg = 65535;	// Maximum message size
var ns_maxcdname = 255;	// Maximum compressed domain name
var ns_maxlabel = 63;	// Maximum compressed domain label
var ns_hfixedsz = 12;	// Bytes of fixed data in header
var ns_qfixedsz = 4;	// Bytes of fixed data in query
var ns_rrfixedsz = 10;	// Bytes of fixed data in r record
var ns_int32sz = 4;	// Bytes of data in a u_int32_t
var ns_int16sz = 2;	// Bytes of data in a u_int16_t
var ns_int8sz = 1;	// Bytes of data in a u_int8_t
var ns_inaddrsz = 4;	// IPv4 T_A
var ns_in6addrsz = 16;	// IPv6 T_AAAA
var ns_cmprsflgs = 0xc0;// Flag bits indicating name compression.
var ns_defaultport = 53;// For both UDP and TCP.

var ns_s = { // sect
	'qd': 0,	// Query: Question.
	'zn': 0,	// Update: Zone.
	'an': 1,	// Query: Answer.
	'pr': 1,	// Update: Prerequisites.
	'ns': 2,	// Query: Name servers.
	'ud': 2,	// Query: Update.
	'ar': 3,	// Query|Update: Additional records.
	'max': 4,
};
exports.ns_s = ns_s;

var ns_f = { // flag
	'qr': 0,	// Question/Response.
	'opcode': 1,	// Operation code.
	'aa': 2,	// Authorative Answer.
	'tc': 3,	// Truncation occured.
	'rd': 4,	// Recursion Desired.
	'ra': 5,	// Recursion Available.
	'z': 6,	// MBZ
	'ad': 7,	// Authentic Data (DNSSEC)
	'cd': 8,	// Checking Disabled (DNSSEC)
	'rcode': 9,	// Response code.
	'max': 10,
};
exports.ns_f = ns_f;

// Currently defined opcodes.
var ns_opcode = {
	'query': 0, 	// Standard query.
	'iquery': 1,	// Inverse query (deprecated/unsupported).
	'status': 2, 	// Name server status query (unsupported).
			// Opcode 3 is undefined/reserved
	'notify': 4,	// Zone change notification.
	'update': 5,	// Zone update message.
};
exports.ns_opcode = ns_opcode;

// Currently defined response codes
var ns_rcode = {
	'noerror': 0,	// No error occured.
	'formerr': 1,	// Format error.
	'servfail': 2,	// Server failure.
	'nxdomain': 3,	// Name error.
	'notimpl': 4,	// Unimplemented.
	'refused': 5,	// Operation refused.
// These are for BIND_UPDATE
	'yxdomain': 6,	// Name exists
	'yxrrset': 7,	// RRset exists
	'nxrrset': 8,	// RRset does not exist
	'notauth': 9,	// Not authoritative for zone
	'notzone': 10,	// Zone of record different from zone section
	'max': 11,
// The following are EDNS extended rcodes
	'badvers': 16,
// The following are TSIG errors
	'badsig': 16,
	'badkey': 17,
	'badtime': 18,
};
exports.ns_rcode = ns_rcode;

// BIND_UPDATE
var ns_oup = { // update_operation
	'delete': 0,
	'add': 1,
	'max': 2,
};
exports.ns_oup = ns_oup;

var NS_TSIG = {
	'FUDGE': 300,
	'TCP_COUNT': 100,
	'ALG_HMAC_MD5': "HMAC-MD5.SIG-ALG.REG.INT",
	
	'ERROR_NO_TSIG': -10,
	'ERROR_NO_SPACE': -11,
	'ERROR_FORMERR': -12,
};
exports.NS_TSIG = NS_TSIG;

// Currently defined type values for resources and queries.
var ns_t = { // type
	'invalid': 0,	// Cookie.
	'a': 1,	// Host address.
	'ns': 2,	// Authoritative server.
	'md': 3,	// Mail destination.
	'mf': 4,	// Mail forwarder.
	'cname': 5,	// Canonical name.
	'soa': 6,	// Start of authority zone.
	'mb': 7,	// Mailbox domain name.
	'mg': 8,	// Mail group member.
	'mr': 9,	// Mail rename name.
	'null': 10,	// Null resource record.
	'wks': 11,	// Well known service.
	'ptr': 12,	// Domain name pointer.
	'hinfo': 13,	// Host information.
	'minfo': 14,	// Mailbox information.
	'mx': 15,	// Mail routing information.
	'txt': 16,	// Text strings.
	'rp': 17,	// Responsible person.
	'afsdb': 18,	// AFS cell database.
	'x25': 19,	// X_25 calling address.
	'isdn': 20,	// ISDN calling address.
	'rt': 21,	// Router.
	'nsap': 22,	// NSAP address.
	'ns_nsap_ptr': 23,	// Reverse NSAP lookup (deprecated)
	'sig': 24,	// Security signature.
	'key': 25,	// Security key.
	'px': 26,	// X.400 mail mapping.
	'gpos': 27,	// Geographical position (withdrawn).
	'aaaa': 28,	// Ip6 Address.
	'loc': 29,	// Location Information.
	'nxt': 30,	// Next domain (security)
	'eid': 31,	// Endpoint identifier.
	'nimloc': 32,	// Nimrod Locator.
	'srv': 33,	// Server Selection.
	'atma': 34,	// ATM Address
	'naptr': 35,	// Naming Authority PoinTeR
	'kx': 36,	// Key Exchange
	'cert': 37,	// Certification Record
	'a6': 38,	// IPv6 Address (deprecated, use ns_t.aaaa)
	'dname': 39,	// Non-terminal DNAME (for IPv6)
	'sink': 40,	// Kitchen sink (experimental)
	'opt': 41,	// EDNS0 option (meta-RR)
	'apl': 42,	// Address prefix list (RFC3123)
	'ds': 43,	// Delegation Signer
	'sshfp': 44,	// SSH Fingerprint
	'ipseckey': 45,// IPSEC Key
	'rrsig': 46,	// RRSet Signature
	'nsec': 47,	// Negative Security
	'dnskey': 48,	// DNS Key
	'dhcid': 49,	// Dynamic host configuartion identifier
	'nsec3': 50,	// Negative security type 3
	'nsec3param': 51,	// Negative security type 3 parameters
	'hip': 55,	// Host Identity Protocol
	'spf': 99,	// Sender Policy Framework
	'tkey': 249,	// Transaction key
	'tsig': 250,	// Transaction signature.
	'ixfr': 251,	// Incremental zone transfer.
	'axfr': 252,	// Transfer zone of authority.
	'mailb': 253,	// Transfer mailbox records.
	'maila': 254,	// Transfer mail agent records.
	'any': 255,	// Wildcard match.
	'zxfr': 256,	// BIND-specific, nonstandard.
	'dlv': 32769,	// DNSSEC look-aside validation.
	'max': 65536
};
exports.ns_t = ns_t;

// Values for class field
var ns_c = { // class
	'invalid':  0,	// Cookie.
	'in': 1,	// Internet.
	'2': 2,	// unallocated/unsupported.
	'chaos': 3,	// MIT Chaos-net.
	'hs': 4,	// MIT Hesoid.
	// Query class values which do not appear in resource records
	'none': 254,	// for prereq. sections in update requests
	'any': 255,	// Wildcard match.
	'max': 65535,
};
exports.ns_c = ns_c;

// DNSSEC constants.
var ns_kt = { // key_type
	'rsa': 1,	// key type RSA/MD5
	'dh': 2,	// Diffie Hellman
	'dsa': 3,	// Digital Signature Standard (MANDATORY)
	'private': 4	// Private key type starts with OID
};
exports.ns_kt = ns_kt;

var cert_t = { // cert_type
	'pkix': 1,	// PKIX (X.509v3)
	'spki': 2,	// SPKI
	'pgp': 3, 	// PGP
	'url': 253,	// URL private type
	'oid': 254	// OID private type
};
exports.cert_t = cert_t;

// Flags field of the KEY RR rdata

var ns_type_elt = 0x40; // edns0 extended label type
var dns_labeltype_bitstring = 0x41;
var digitvalue = [
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 32
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 48
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 64
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 96
	-1, 12, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 112
    	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 128
    	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 256
	];

var hexvalue = [
	"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", 
	"10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", 
	"20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", 
	"30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", 
	"40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", 
	"50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", 
	"60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f", 
	"70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f", 
	"80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f", 
	"90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f", 
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af", 
	"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf", 
	"c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf", 
	"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df", 
	"e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef", 
	"f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff", 
	];

var digits = "0123456789";
var ns_flagdata = [
	{ mask: 0x8000, shift: 15 }, // qr.
	{ mask: 0x7800, shift: 11 }, // opcode.
	{ mask: 0x0400, shift: 10 }, // aa.
	{ mask: 0x0200, shift: 9 }, // tc.
	{ mask: 0x0100, shift: 8 }, // rd.
	{ mask: 0x0080, shift: 7 }, // ra.
	{ mask: 0x0040, shift: 6 }, // z.
	{ mask: 0x0020, shift: 5 }, // ad.
	{ mask: 0x0010, shift: 4 }, // cd.
	{ mask: 0x000f, shift: 0 }, // rcode.
	{ mask: 0x0000, shift: 0 }, // expansion (1/6).
	{ mask: 0x0000, shift: 0 }, // expansion (2/6).
	{ mask: 0x0000, shift: 0 }, // expansion (3/6).
	{ mask: 0x0000, shift: 0 }, // expansion (4/6).
	{ mask: 0x0000, shift: 0 }, // expansion (5/6).
	{ mask: 0x0000, shift: 0 }, // expansion (6/6).
	];

var res_opcodes = [
	"QUERY",
	"IQUERY",
	"CQUERYM",
	"CQUERYU",	// experimental
	"NOTIFY",	// experimental
	"UPDATE",
	"6",
	"7",
	"8",
	"9",
	"10",
	"11",
	"12",
	"13",
	"ZONEINIT",
	"ZONEREF",
	];
var res_sectioncodes = [
	"ZONE",
	"PREREQUISITES",
	"UPDATE",
	"ADDITIONAL",
	];

var p_class_syms = {
	1: "IN",
	3: "CHAOS",
	4: "HESOID",
	254: "ANY",
	255: "NONE"
};
exports.p_class_syms = p_class_syms;

var p_default_section_syms = {
	0: "QUERY",
	1: "ANSWER",
	2: "AUTHORITY",
	3: "ADDITIONAL"
};
exports.p_default_section_syms = p_default_section_syms;

var p_key_syms = {
	1: ["RSA", "RSA KEY with MD5 hash"],
	2: ["DH", "Diffie Hellman"],
	3: ["DSA", "Digital Signature Algorithm"],
	4: ["PRIVATE", "Algorithm obtained from OID"]
};
exports.p_key_syms = p_key_syms;

var p_cert_syms = {
	1: ["PKIX", "PKIX (X.509v3) Certificate"],
	2: ["SKPI", "SPKI Certificate"],
	3: ["PGP", "PGP Certificate"],
	253: ["URL", "URL Private"],
	254: ["OID", "OID Private"]
};
exports.p_cert_syms = p_cert_syms;

var p_type_syms = {
	1: "A",
	2: "NS",
	3: "MD",
	4: "MF",
	5: "CNAME",
	6: "SOA",
	7: "MB",
	8: "MG",
	9: "MR",
	10: "NULL",
	11: "WKS",
	12: "PTR",
	13: "HINFO",
	14: "MINFO",
	15: "MX",
	16: "TXT",
	17: "RP",
	18: "AFSDB",
	19: "X25",
	20: "ISDN",
	21: "RT",
	22: "NSAP",
	23: "NSAP_PTR",
	24: "SIG",
	25: "KEY",
	26: "PX",
	27: "GPOS",
	28: "AAAA",
	29: "LOC",
	30: "NXT",
	31: "EID",
	32: "NIMLOC",
	33: "SRV",
	34: "ATMA",
	35: "NAPTR",
	36: "KX",
	37: "CERT",
	38: "A6",
	39: "DNAME",
	40: "SINK",
	41: "OPT",
	42: "APL",
	43: "DS",
	44: "SSHFP",
	45: "IPSECKEY",
	46: "RRSIG",
	47: "NSEC",
	48: "DNSKEY",
	49: "DHCID",
	50: "NSEC3",
	51: "NSEC3PARAM",
	55: "HIP",
	99: "SPF",
	249: "TKEY",
	250: "TSIG",
	251: "IXFR",
	252: "AXFR",
	253: "MAILB",
	254: "MAILA",
	255: "ANY",
	32769: "DLV",
	256: "ZXFR",
};
exports.p_type_syms = p_type_syms;

var p_rcode_syms = {
	0: ["NOERROR", "no error"],
	1: ["FORMERR", "format error"],
	2: ["SERVFAIL", "server failed"],
	3: ["NXDOMAIN", "no such domain name"],
	4: ["NOTIMP", "not implemented"],
	5: ["REFUSED", "refused"],
// These are for BIND_UPDATE
	6: ["YXDOMAIN", "domain name exist"],
	7: ["YXRRSET", "rrset exists"],
	8: ["NXRRSET", "rrset doesn't exist"],
	9: ["NOTAUTH", "not authoritative"],
	10: ["NOTZONE", "not in zone"],
	11: ["", ""],
// The following are EDNS extended rcodes
// The following are TSIG errors
	16: ["BADSIG", "bad signature"],
	17: ["BADKEY", "bad key"],
	18: ["BADTIME", "bad time"]
};
exports.p_rcode_syms = p_rcode_syms;

var _string = new Buffer (ns_maxdname);
var _dname = new Buffer (ns_maxdname);
var _cdname = new Buffer (ns_maxcdname);
var _map = new Array (8192);

function Ptr () {
	this.p = (arguments.length == 1) ? arguments[0] : null;
}
exports.Ptr = Ptr;

Ptr.prototype.get = function () {
	return this.p;
};

Ptr.prototype.set = function (val) {
	return this.p = val;
};

var errno;

function ns_name_ntop (src, dst, dstsiz) {
	var cp;
	var dn, eom;
	var c;
	var n;
	var l;
	
	cp = 0;
	dn = 0;
	eom = dstsiz;
	
	while ((n = src[cp++]) != 0) {
		if ((n & ns_cmprsflgs) == ns_cmprsflgs) {
			/* some kind of compression pointer */
			errno = 'EMSGSIZE';
			return (-1);
		}
		if (dn != 0) {
			if(dn >= eom) {
				errno = 'EMSGSIZE';
				return (-1);
			}
			dst[dn++] = 0x2e; /* '.' */
		}
		if ((l = labellen(src, cp - 1)) < 0) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		if (dn + l >= eom) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		if ((n & ns_cmprsflgs) == ns_type_elt) {
			var m;
			
			if (n != dns_labeltype_bitstring) {
				/* labellen should reject this case */
				return (-1);
			}
			var cpp = new Ptr (cp);
			if ((m = decode_bitstring (src, cpp, dst, dn, eom)) < 0) {
				errno = 'EMSGSIZE';
				return (-1);
			}
			cp = cpp.get ();
			dn += m;
			continue;
		}
		for(; l > 0; l--) {
			c = src[cp++];
			if (special(c)) {
				if (dn + 1 >= eom) {
					errno = 'EMSGSIZE';
					return (-1);
				}
				dst[dn++] = 0x5c; /* '\\' */
				dst[dn++] = c;
			}
			else if (!printable(c)) {
				if (dn + 3 >= eom) {
					errno = 'EMSGSIZE';
					return (-1);
				}
				dst[dn++] = 0x5c; /* '\\' */
				dst[dn++] = digits[c / 100];
				dst[dn++] = digits[(c % 100) / 10];
				dst[dn++] = digits[c % 10];
			}
			else {
				if (dn >= eom) {
					errno = 'EMSGSIZE';
					return (-1);
				}
				dst[dn++] = c;
			}
		}
	}
	if (dn == 0) {
		if (dn >= eom) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		dst[dn++] = 0x2e; // '.'
	}
	if (dn >= eom) {
		errno = 'EMSGSIZE';
		return (-1);
	}
	dst[dn] = 0;
	return (dn);
}
exports.ns_name_ntop = ns_name_ntop;

function ns_name_pton (src, dst, dstsiz) {
	return ns_name_pton2(src, dst, dstsiz, null);
}
exports.ns_name_pton = ns_name_pton;

function ns_name_pton2 (src, dst, dstsiz, dstlenp) {
	var label, bp, eom;
	var c, n, escaped, e = 0;
	var cp;
	
	escaped = 0;
	bp = 0;
	eom = dstsiz;
	label = bp++;
	
	var srcn = 0;
	var done = false; // instead of goto
	while ((c = src[srcn++]) != 0) {
		if (escaped) {
			if (c == 91) { // '['; start a bit string label
				if ((cp = strchr(src, srcn, 93)) == null) { // ']'
					errno = 'EINVAL';
					return(-1);
				}
				var srcp = new Ptr(srcn);
				var bpp = new Ptr(bp);
				var labelp = new Ptr(label);
				if ((e = encode_bitstring (src, srcp, cp + 2,
							   labelp, dst, bpp, eom)
				     != 0)) {
					errno = e;
					return(-1);
				}
				label = labelp.get ();
				bp = bpp.get ();
				srcn = srcp.get ();
				escaped = 0;
				label = bp++;
				if ((c = src[srcn++]) == 0) {
					done = true;
					break;
				}
			}
			else if ((cp = digits.indexOf(String.fromCharCode(c))) != -1) {
				n = (cp * 100);
				if ((c = src[srcn++]) ||
				    (cp = digits.indexOf(String.fromCharCode(c))) == -1) {
					errno = 'EMSGSIZE';
					return (-1);
				}
				n += (cp) * 10;
				if ((c = src[srcn++]) == 0 ||
				    (cp = digits.indexOf(String.fromCharCode(c))) == -1) {
					errno = 'EMSGSIZE';
					return (-1);
				}
				n += cp;
				if (n > 255) {
					errno = 'EMSGSIZE';
					return (-1);
				}
				c = n;
			}
			escaped = 0;
		} else if (c == 92) { // '\\'
			escaped = 1;
			continue;
		} else if (c == 46) { // '.'
			c = (bp - label - 1);
			if ((c & ns_cmprsflgs) != 0) { // label too big
					errno = 'EMSGSIZE';
					return (-1);
				}
			if (label >= eom) {
				errno = 'EMSGSIZE';
				return (-1);
			}
			dst[label] = c;
			// Fully qualified?
			if (src[srcn] == 0) {
				if (c != 0) {
					if (bp >= eom) {
						errno = 'EMSGSIZE';
						return (-1);
					}
					dst[bp++] = 0;
				}
				if ((bp) > ns_maxcdname) {
					errno = 'EMSGSIZE';
					return (-1);
				}
				if (dstlenp != null) {
					dstlenp.set(bp);
				}
				return (1);
			}
			if (c == 0 || src[srcn] == 46) { // '.'
				errno = 'EMSGSIZE';
				return (-1);
			}
			label = bp++;
			continue;
		}
		if (bp >= eom) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		dst[bp++] = c;
	}
	if (!done) {
		c = (bp - label - 1);
		if ((c & ns_cmprsflgs) != 0) {
			errno = 'EMSGSIZE';
			return (-1);
		}
	}
// done:
	if (label >= eom) {
		errno = 'EMSGSIZE';
		return (-1);
	}
	dst[label] = c;
	if (c != 0) {
		if (bp >= eom) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		dst[bp++] = 0;
	}
	if (bp > ns_maxcdname) { // src too big
		errno = 'EMSGSIZE';
		return (-1);
	}
	if (dstlenp != null) {
		dstlenp.set(bp);
	}
	return (0);
}
exports.ns_name_pton2 = ns_name_pton2;

function strchr (src, off, n) {
	while (off < buf.length && buf[off] != 0) {
		if (buf[off] == n)
			return off;
		off++;
	}
	return null;
}
function ns_name_unpack (msg, offset, len, dst, dstsiz) {
	return ns_name_unpack2 (msg, offset, len, dst, dstsiz, null);
}
exports.ns_name_unpack = ns_name_unpack;

function ns_name_unpack2 (msg, offset, len, dst, dstsiz, dstlenp) {
	var n, l;
	
	var llen = -1;
	var checked = 0;
	var dstn = 0;
	var srcn = offset;
	var dstlim = dstsiz;
	var eom = offset + len;
	if (srcn < 0 || srcn >= eom) {
		errno = 'EMSGSIZE';
		return (-1);
	}
	/* Fetch next label in domain name */
	while ((n = msg[srcn++]) != 0 && !isNaN(srcn)) {
		/* Check for indirection */
		switch (n & ns_cmprsflgs) {
		case 0:
		case ns_type_elt:
			/* Limit checks */
			
			if ((l = labellen (msg, srcn - 1)) < 0) {
				errno = 'EMSGSIZE';
				return (-1);
			}
			if (dstn + l + 1 >= dstlim || srcn + l >= eom) {
				errno = 'EMSGSIZE';
				return (-1);
			}
			checked += l + 1;
			dst[dstn++] = n;
			msg.copy (dst, dstn, srcn, srcn + l);
			dstn += l;
			srcn += l;
			break;
			
		case ns_cmprsflgs:
			if (srcn >= eom) {
				errno = 'EMSGSIZE';
				return (-1);
			}
			if (llen < 0) {
				llen = (srcn - offset) + 1;
			}
			
			srcn = (((n & 0x3F) * 256) | (msg[srcn] & 0xFF));
			
			if (srcn < 0 || srcn >= eom) { /* Out of range */
				errno = 'EMSGSIZE';
				return (-1);
			}
			
			checked += 2;
			/* check for loops in compressed name */
			if (checked >= eom) {
				errno = 'EMSGSIZE';
				return (-1);
			}
			break;
			
		default:
			errno = 'EMSGSIZE';
			return (-1); // flag error
		}
	}
	dst[dstn] = 0;
	if (dstlenp != null)
		dstlenp.set(dstn);
	if (llen < 0)
		llen = srcn - offset;
	return (llen);
}
function ns_name_pack (src, dst, dstn, dstsiz, dnptrs, lastdnptr) {
	var dstp;
	var cpp, lpp, eob, msgp;
	var srcp;
	var n, l, first = 1;
	
	srcp = 0;
	dstp = dstn;
	eob = dstp + dstsiz;
	lpp = cpp = null;
	var ndnptr = 0;
	if (dnptrs != null) {
		msg = dst;
		//if ((msg = dnptrs[ndnptr++]) != null) {
		for (cpp = 0; dnptrs[cpp] != null; cpp++);
		lpp = cpp; // end of list to search
		//}
	} else
		msg = null;
	
	// make sure the domain we are about to add is legal
	l = 0;
	do {
		var l0;
		
		n = src[srcp];
		if ((n & ns_cmprsflgs) == ns_cmprsflgs) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		if ((l0 = labellen(src, srcp)) < 0) {
			errno = 'EINVAL';
			return (-1);
		}
		l += l0 + 1;
		if (l > ns_maxcdname) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		srcp += l0 + 1;
	} while (n != 0);
	
	// from here on we need to reset compression pointer array on error
	srcp = 0;
	var cleanup = false; // instead of goto
	do {
		// look to see if we can use pointers
		n = src[srcp];
		if (n != 0 && msg != null) {
			l = dn_find (src, srcp, msg, dnptrs, ndnptr, lpp);
			if (l >= 0) {
				if (dstp + 1 >= eob) {
					cleanup = true;
					break;
				}
				dst[dstp++] = (l >> 8) | ns_cmprsflgs;
				dst[dstp++] = l & 0xff;
				return (dstp - dstn);
			}
			// Not found, save it.
			if (lastdnptr != null && cpp < lastdnptr - 1 &&
			    (dstp) < 0x4000 && first) {
				dnptrs[cpp++] = dstp;
				dnptrs[cpp++] = null;
				first = 0;
			}
		}
		// copy label to buffer
		if ((n & ns_cmprsflgs) == ns_cmprsflgs) {
			// should not happen
			cleanup = true;
			break;
		}
		n = labellen (src, srcp);
		if (dstp + 1 + n >= eob) {
			cleanup = true;
			break;
		}
		src.copy (dst, dstp, srcp, srcp + (n + 1));
		srcp += n + 1;
		dstp += n + 1;
		
	} while (n != 0);
	
	if (dstp > eob ||
// cleanup:
	    cleanup) {
		if (msg != null) {
			dnptrs[lpp] = null;
		}
		errno = 'EMSGSIZE';
		return (-1);
	}
	return (dstp - dstn);
}
exports.ns_name_pack = ns_name_pack;

function ns_name_skip (b, ptrptr, eom) {
	var cp;
	var n;
	var l;
	
	cp = ptrptr.get ();
	while (cp < eom && (n = b[cp++]) != 0) {
		switch (n & ns_cmprsflgs) {
		case 0: // normal case, n == len
			cp += n;
			continue;
		case ns_type_elt: // edns0 extended label
			if ((l = labellen (b, cp - 1)) < 0) {
				errno = 'EMSGSIZE';
				return (-1);
			}
			cp += l;
			continue;
		case ns_cmprsflgs: // indirection
			cp++;
			break;
		default: // illegal type
			errno = 'EMSGSIZE';
			return (-1);
		}
		break;
	}
	if (cp > eom) {
		errno = 'EMSGSIZE';
		return (-1);
	}
	ptrptr.set (cp);
	return (0);
}
exports.ns_name_skip = ns_name_skip;

function ns_name_length (b, nname, namesiz)
{
	var orig = nname;
	var n;

	while (namesiz-- > 0 && (n = b[nname++]) != 0) {
		if ((n & ns_cmprsflgs) != 0) {
			return (-1);
		}
		if (n > namesiz) {
			return (-1);
		}
		nname += n;
		namesiz -= n;
	}
	return (nname - orig);
}
exports.ns_name_length = ns_name_length;

function strncasecmp (buf1, s1, buf2, s2, n)
{
	for (var i = 0; i < n; i++) {
		if ((buf1[s1+i] | 0x20) != (buf2[s2+i])) {
			return (-1);
		}
	}
	return (0);
}
function ns_name_eq (bufa, a, as, bufb, b, bs)
{
	var ae = a + as, be = b + bs;
	var ac, cb;
	while (ac = bufa[a], bc = bufb[b], ac != 0 && bc != 0) {
		if ((ac & ns_cmprsflgs) != 0 || (bc & ns_cmprsflgs) != 0) {
			errno = 'EISDIR';
			return (-1);
		}
		if (a + ac >= ae || b + bc >= be) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		if (ac != bc || strncasecmp (bufa, ++a,
					     bufb, ++b, ac) != 0) {
			return (0);
		}
		a += ac, b += bc;
	}
	return (ac == 0 && bc == 0);
}
exports.ns_name_eq = ns_name_eq;

function ns_name_owned (bufa, mapa, an, bufb, mapb, bn)
{
	var a, b;
	if (an < bn)
		return (0);
	a = 0, b = 0;
	while (bn > 0) {
		if (mapa[a].len != mapa[b].len ||
		    strncasecmp (bufa, mapa[a].base,
				 bufb, mapb[b].base, mapa[a].len)) {
			return (0);
		}
		a++, an--;
		b++, bn--;
	}

	return (1);
}
exports.ns_name_owned = ns_name_owned;

function ns_name_map (b, nname, namelen, map, mapsize)
{
	var n;
	var l;

	n = b[nname++];
	namelen--;

	/* root zone? */
	if (n == 0) {
		/* extra data follows name? */
		if (namelen > 0) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		return (0);
	}
	/* compression pointer? */
	if ((n & ns_cmprsflgs) != 0) {
		errno = 'EISDIR';
		return (-1);
	}

	/* label too long? */
	if (n > namelen) {
		errno = 'EMSGSIZE';
		return (-1);
	}

	/* recurse to get rest of name done first */
	l = ns_name_map (b, nname + n, namelen - n, map, mapsize);
	if (l < 0) {
		return (-1);
	}

	/* too many labels? */
	if (l >= mapsize)  {
		errno = 'ENAMETOOLONG';
		return (-1);
	}

	map.buf = b;
	map[l] = new Object ();
	/* we're on our way back up-stack, store current map data */
	map[l].base = nname;
	map[l].len = n;
	return (l + 1);
}
exports.ns_name_map = ns_name_map;

function ns_name_labels (b, nname, namesiz)
/* count the number of labels in a domain name. root counts.
   for ns_name_map () */
{
	var ret = 0;
	var n;

	while (namesiz-- > 0 && (n = b[nname++]) != 0) {
		if ((n & ns_cmprsflgs) != 0) {
			errno = 'EISDIR';
			return (-1);
		}
		if (n > namesiz) {
			errno = 'EMSGSIZE';
			return (-1);
		}
		nname += n;
		namesiz -= n;
		ret++;
	}
	return (ret + 1);
}
exports.ns_name_labels = ns_name_labels;

function special (ch) {
	switch(ch) {
	case 0x22: /* '"' */
	case 0x2E: /* '.' */
	case 0x3B: /* ';' */
	case 0x5C: /* '\\' */
	case 0x28: /* '(' */
	case 0x29: /* ')' */
		/* special modifiers in the zone file */
	case 0x40: /* '@' */
	case 0x24: /* '$' */
		return (1);
	default:
		return (0);
	}
}
function printable (ch)
{
	return (ch > 0x20 && ch < 0x7F);
}
function mklower (ch)
{
	if (ch >= 0x41 && ch <= 0x5A)
		return (ch + 0x20);
	return (ch);
}
function dn_find (src, domain, msg, dnptrs, ndnptr, lastdnptr)
{
	var dn, cp, sp;
	var cpp;
	var n;
	
	var next = false; // instead of goto
	for (cpp = ndnptr; cpp < lastdnptr; cpp++) {
		sp = dnptrs[cpp];
		//
		// terminate search on:
		// root label
		// compression pointer
		// unusable offset
		//
		while (msg[sp] != 0 && (msg[sp] & ns_cmprsflgs) == 0 &&
		       (sp) < 0x4000) {
			dn = domain;
			cp = sp;
			while ((n = msg[cp++]) != 0) {
				//
				// check for indirection
				//
				switch (n & ns_cmprsflgs) {
				case 0: // normal case, n == len
					n = labellen (msg, cp - 1); // XXX
					if (n != src[dn++]) {
						next = true;
						break;
					}
					for (null; n > 0; n--) {
						if (mklower (src[dn++]) !=
						    mklower (msg[cp++])) {
							next = true;
							break;
						}
					}
					if (next) {
						break;
					}
					// Is next root for both ?
					if (src[dn] == 0 && msg[cp] == 0) {
						return (sp);
					}
					if (src[dn])  {
						continue;
					}
					next = true;
					break;
				case ns_cmprsflgs: // indirection
					cp = (((n & 0x3f) * 256) | msg[cp]);
					break;
					
				default: // illegal type
					errno = 'EMSGSIZE';
					return (-1);
				}
				if (next) {
					break;
				}
			}
			sp += msg[sp] + 1;
			if (next) {
				next = false;
			}
		}
	}
	errno = 'ENOENT';
	return (-1);
}
exports.dn_find = dn_find;

function decode_bitstring (b, cpp, d, dn, eom)
{
	var cp = cpp.get ();
	var beg = dn, tc;
	var b, blen, plen, i;
	
	if ((blen = (b[cp] & 0xff)) == 0)
		blen = 256;
	plen = (blen + 3) / 4;
	plen += "\\[x/]".length + (blen > 99 ? 3 : (blen > 9) ? 2 : 1);
	if (dn + plen >= eom)
		return (-1);
	
	cp++;
	i = d.write ("\\[x", dn);
	if (i != 3)
		return (-1);
	dn += i;
	for (b = blen; b > 7; b -= 8, cp++) {
		if (dn + 2 >= eom)
			return (-1);
	}
}
exports.decode_bitstring = decode_bitstring;

function encode_bitstring (src, bp, end, labelp, dst, dstp, eom)
{
	var afterslash = 0;
	var cp = bp.get ();
	var tp;
	var c;
	var beg_blen;
	var end_blen = null;
	var value = 0, count = 0, tbcount = 0, blen = 0;
	
	beg_blen = end_blen = null;
	
	// a bitstring must contain at least two bytes
	if (end - cp < 2)
		return errno.EINVAL;
	
	// currently, only hex strings are supported
	if (src[cp++] != 120) // 'x'
		return errno.EINVAL;
	if (!isxdigit((src[cp]) & 0xff)) // reject '\[x/BLEN]'
		return errno.EINVAL;
	
	var done = false;
	for (tp = dstp.get () + 1; cp < end && tp < eom; cp++) {
		switch (c = src[cp++]) {
		case 93: // ']'
			if (afterslash) {
				if (beg_blen == null)
					return errno.EINVAL;
				blen = strtol (src, beg_blen, 10);
				// todo:
				// if ( char after string == ']' )
				// return errno.EINVAL;
			}
			if (count)
				dst[tp++] = ((value << 4) & 0xff);
			cp++; // skip ']'
			done = true;
			break;
		case 47: // '/'
			afterslash = 1;
			break;
		default:
			if (afterslash) {
				if (!isxdigit (c&0xff))
					return errno.EINVAL;
				if (beg_blen == null) {
					
					if (c == 48) { // '0'
						// blen never begins with 0
						return errno.EINVAL;
					}
					beg_blen = cp;
				}
			} else {
				if (!isxdigit (c&0xff))
					return errno.EINVAL;
				value <<= 4;
				value += digitvalue[c];
				count += 4;
				tbcount += 4;
				if (tbcount > 256)
					return errno.EINVAL;
				if (count == 8) {
					dst[tp++] = value;
					count = 0;
				}
			}
			break;
		}
		if (done) {
			break;
		}
	}
	// done:
	if (cp >= end || tp >= eom)
		return errno.EMSGSIZE;
	// bit length validation:
	// If a <length> is present, the number of digits in the <bit-data>
	// MUST be just sufficient to contain the number of bits specified
	// by the <length>. If there are insufficient bits in a final
	// hexadecimal or octal digit, they MUST be zero.
	// RFC2673, Section 3.2
	if (blen && (blen > 0)) {
		var traillen;
		
		if (((blen + 3) & ~3) != tbcount)
			return errno.EINVAL;
		traillen = tbcount - blen; // between 0 and 3
		if (((value << (8 - traillen)) & 0xFF) != 0)
			return errno.EINVAL;
	}
	else
		blen = tbcount;
	if (blen == 256)
		blen = 0;
	
	// encode the type and the significant bit fields
	src[labelp.get ()] = dns_labeltype_bitstring;
	dst[dstp.get ()] = blen;
	
	bp.set (cp);
	dstp.set (tp);
	
	return (0);
}
exports.encode_bitstring = encode_bitstring;

function isxdigit (ch) {
	return ((ch >= 48 && ch <= 57)
		|| (ch >= 97 && ch <= 102)
		|| (ch >= 65 && ch <= 70));
}
function isspace (ch) {
	return (ch == 32 || ch == 12 || ch == 10 || ch == 13 || ch == 9 || ch == 12);
}
function strtol (b, off, end, base) {
	// todo: port from C
	return parseInt (b.toString (off, end), base);
}
function labellen (b, off) {
	var bitlen;
	var l = b[off];
	
	if ((l & ns_cmprsflgs) == ns_cmprsflgs) {
		return (-1);
	}
	if ((l & ns_cmprsflgs) == ns_type_elt) {
		if (l == dns_labeltype_bitstring) {
			bitlen = b[off + 1];
			if (bitlen == 0) {
				bitlen = 256;
			}
			return (1 + (bitlen + 7) / 8);
		}
	}
	return (l);
}
var ns_s = {
	qd: 0,
	zn: 0,
	an: 1,
	pr: 1,
	ns: 2,
	ud: 2,
	ar: 3,
	max: 4
};
exports.ns_s = ns_s;

function ns_msg ()
{
	this._buf = 0;
	this._msg = 0;
	this._eom = 0;
	this._id = 0, this._flags = 0, this._counts = new Array (ns_s.max);
	this._sections = new Array (ns_s.max);
	this._sect = 0;
	this._rrnum = 0;
	this._msg_ptr = new Ptr ();
}
exports.ns_msg = ns_msg;
ns_msg.prototype.getId = function ()
{
	return this._id;
};
ns_msg.prototype.getBase = function ()
{
	return this._msg;
};
ns_msg.prototype.getSize = function ()
{
	return this._eom;
};
ns_msg.prototype.getCount = function (section)
{
	return this._counts[section];
};

function ns_newmsg ()
{
	this.msg = new ns_msg ();
	this.dnptrs = new Array (25);
	this.lastdnptr = this.dnptrs.length;
}
exports.ns_newmsg = ns_newmsg;

function ns_rr2 ()
{
	var nname;
	var nnamel;
	var type;
	var rr_class;
	var ttl;
	var rdlength;
	var rdata;
}
exports.ns_rr2 = ns_rr2;

function dn_skipname (src, ptr, eom)
{
	var saveptr = ptr;
	var ptrptr = new Ptr (ptr);

	if (ns_name_skip (src, ptrptr, eom) == -1) return (-1);
	return (ptrptr.get () - saveptr);
}
function setsection (msg, sect) 
{
	msg._sect = sect;
	if (sect == ns_s.max) {
		msg._rrnum = -1;
		msg._msg_ptr = null;
	} else {
		msg._rrnum = 0;
		msg._msg_ptr = msg._sections[sect];
	}
}
function ns_skiprr (src, ptr, eom, section, count)
{
	var optr = ptr;
	debug (count)
	for (var i = 0; i < count; i++) {
		var b, rdlength;
		b = dn_skipname (src, ptr, eom);
		if (b < 0) return (-1);
		ptr += b + ns_int16sz + ns_int16sz;
		if (section != ns_s.qd) {
			if (ptr + ns_int32sz + ns_int16sz > eom) return (-1);
			ptr += ns_int32sz;
			rdlength = src[ptr] * 256 + src[ptr+1];
			ptr += rdlength;
		}
	}
	if (ptr > eom) {
		errno = 'EMSGSIZE';
		return (-1);
	}
	return (ptr - optr);
}
function ns_initparse (buf, buflen, handle)
{
	var msg = 0, eom = buflen;
	var i;
	
	handle.msg = 0;
	handle._eom = eom;
	if (msg + ns_int16sz > eom) return (-1);
	
	handle._id = buf[msg] * 256 + buf[msg+1];
	msg += ns_int16sz;
	if (msg + ns_int16sz > eom) return (-1);
	handle._flags = buf[msg] * 256 + buf[msg+1];
	msg += ns_int16sz;
	for (i = 0; i < ns_s.max; i++) {
		if (msg + ns_int16sz > eom) return (-1);
		handle._counts[i] = buf[msg] * 256 + buf[msg+1];
		msg += ns_int16sz;
	}
	for (i = 0; i < ns_s.max; i++) {
		if (handle._counts[i] == 0) {
			handle._sections[i] = null;
		} else {
			var b = ns_skiprr (buf, msg, eom, i, handle._counts[i]);
			if (b < 0) return (-1);
			handle._sections[i] = msg;
			msg += b;
		}
	}
	if (msg != eom) return (-1);
	setsection (handle, ns_s.max);
	return (0);
}
exports.ns_initparse = ns_initparse;

function ns_parserr (handle, section, rrnum, rr)
{
	var b;
	var tmp;

	tmp = section;
	if (tmp < 0 || section >= ns_s.max) {
		errno = 'ENODEV';
		return (-1);
	}
	if (section != handle._sect) setsection (handle, section);

	if (rrnum != -1) rrnum = handle._rrnum;
	if (rrnum < 0 || rrnum > handle._counts[section]) {
		errno = 'ENODEV';
		return (-1);
	}
}

function DNSParser (buf, start, end) {
	if (arguments.length < 3) {
		this.initialized = false;
		return;
	}

	if (!(buf instanceof Buffer)) {
		throw new Error("Argument should be a buffer");
	}
	if (start > buf.length) {
		throw new Error("Offset is out of bounds");
	}
	if (end > buf.length) {
		throw new Error("Length extends beyond buffer");
	}

	this.buf = buf;
	this.bufStart = start;
	this.bufEnd = end;
	
	this.parseStart = 0;
	this.parseEnd = 0;

	this.initialized = true;

	this.parseErr = false;
}
exports.DNSParser = DNSParser;

DNSParser.prototype.reinitialize = function () {
	DNSParser.apply (this, arguments);
};
DNSParser.prototype.parseMessage = function () {
	var qdcount, ancount, nscount, arcount, rrcount;
	// todo: streaming parser (for tcp)
	if (typeof this.onMessageBegin === 'function')
		this.onMessageBegin ();

	this.skipHeader (this.onHeader);
	if (this.skipErr)
		return;
	
	qdcount = this.buf[this.parseStart-8] * 256 + this.buf[this.parseStart-7];
	ancount = this.buf[this.parseStart-6] * 256 + this.buf[this.parseStart-5];
	nscount = this.buf[this.parseStart-4] * 256 + this.buf[this.parseStart-3];
	arcount = this.buf[this.parseStart-2] * 256 + this.buf[this.parseStart-1];
	rrcount = ancount + nscount + arcount;
	
	for (var i = 0; i < qdcount; i++) {
		this.skipQuestion (this.onQuestion);
	}
	
	for (var i = 0; i < rrcount; i++) {
		if (ancount > 0 && i == 0) {
			if (typeof this.onAnswerBegin === 'function')
				this.onAnswerBegin ();
		} else if (nscount > 0 && i == ancount) {
			if (typeof this.onAuthorityBegin === 'function')
				this.onAuthorityBegin ();

		} else if (arcount > 0 && i == ancount + nscount) {
			if (typeof this.onAdditionalBegin === 'function')
				this.onAdditionalBegin ();
		}
		this.skipRR (this.onRR);
	}

	if (typeof this.onMessageComplete === 'function')
		this.onMessageComplete ();
};
DNSParser.prototype.skipHeader = function (cb) {
	if (this.skipErr)
		return;
		
	this.parseEnd = this.parseStart + ns_hfixedsz;
	if (this.parseEnd > this.bufEnd) {
		this.skipErr = true;
		return;
	}
	
	if (typeof cb === 'function')
		cb (this.buf, this.parseStart, this.parseEnd);
	
	this.parseStart = this.parseEnd;
};
DNSParser.prototype.skipQuestion = function (cb) {
	if (this.skipErr)
		return;
	
	var ptr = new Ptr (this.parseStart);
	if (ns_name_skip(this.buf, ptr, this.bufEnd) != 0) {
		this.skipErr = true;
		return;
	}
	
	this.parseEnd = ptr.get () + ns_qfixedsz;
	if (this.parseEnd > this.bufEnd) {
		this.skipErr = true;
		return;
	}
	
	if (typeof cb === 'function')
		cb (this.buf, this.parseStart, this.parseEnd);
	
	this.parseStart = this.parseEnd;
};
DNSParser.prototype.skipRR = function (cb) {
	if (this.skipErr)
		return;
	
	var rrcount;
	var ptr = new Ptr (this.parseStart);
	
	if (ns_name_skip (this.buf, ptr, this.bufEnd) != 0) {
		this.skipErr = true;
		return;
	}
	
	this.parseEnd = ptr.get () + ns_rrfixedsz;
	if (this.parseEnd > this.bufEnd) {
		this.skipErr = true;
		return;
	}
	
	this.parseEnd += this.buf[this.parseEnd - 2] * 256 + this.buf[this.parseEnd - 1];
	if (this.parseEnd > this.bufEnd) {
		this.skipErr = true;
		return;
	}
	
	if (typeof cb === 'function')
		cb (this.buf, this.parseStart, this.parseEnd);
	
	this.parseStart = this.parseEnd;
};
DNSParser.prototype.parseName = function () {
	if (this.parseErr)
		return;

	var n, len;

	if ((n = ns_name_unpack (this.buf, this.parseStart, this.parseEnd - this.parseStart, _dname, _dname.length)) == -1) {
		this.parseErr = new Error ("ns_name_unpack")
		return;
	}
	if ((len = ns_name_ntop (_dname, _string, _string.length)) == -1) {
		this.parseErr = new Error("ns_name_ntop");
		return;
	}
	
	this.parseStart += n;
	return _string.toString('ascii', 0, len);
};
DNSParser.prototype.parseUInt8 = function () {
	if (this.parseErr)
		return;

	if (this.parseStart + 1 > this.parseEnd) {
		this.parseErr = new Error ("syntax error")
		return;
	}
	this.parseStart++;
	return this.buf[this.parseStart-1];
};
DNSParser.prototype.parseUInt16 = function () {
	if (this.parseErr)
		return;

	if (this.parseStart + 2 > this.parseEnd) {
		this.parseErr = new Error ("syntax error");
		return;
	}
	this.parseStart += 2;
	return this.buf[this.parseStart-2] * 256 + this.buf[this.parseStart-1];
};
DNSParser.prototype.parseUInt32 = function () {
	if (this.parseErr)
		return;

	if (this.parseStart + 4 > this.parseEnd) {
		this.parseErr = new Error ("syntax error");
		return;
	}
		
	this.parseStart += 4;
	return (this.buf[this.parseStart-4] * 16777216 +
		this.buf[this.parseStart-3] * 65536 + 
		this.buf[this.parseStart-2] * 256 +
		this.buf[this.parseStart-1] );
};
DNSParser.prototype.parseHeader = function (header) {
	var tmp;
	header.id = this.parseUInt16 ();
	tmp = this.parseUInt16 ();
	header.qr = (tmp & 0x8000) >> 15;
	header.opcode = (tmp & 0x7800) >> 11;
	header.aa = (tmp & 0x0400) >> 10;
	header.tc = (tmp & 0x0200) >> 9;
	header.rd = (tmp & 0x0100) >> 8;
	header.ra = (tmp & 0x0080) >> 7;
	header.z = (tmp & 0x0040) >> 6;
	header.ad = (tmp & 0x0020) >> 5;
	header.cd = (tmp & 0x0010) >> 4;
	header.rcode = (tmp & 0x000f) >> 0;

	header.qdcount = this.parseUInt16 ();
	header.ancount = this.parseUInt16 ();
	header.nscount = this.parseUInt16 ();
	header.arcount = this.parseUInt16 ();
};
DNSParser.prototype.parseQuestion = function (question) {
	question.name = this.parseName ();
	question.type = this.parseUInt16 ();
	question.class = this.parseUInt16 ();
	question.typeName = p_type_syms[question.type];
	question.className = p_class_syms[question.class];
};
DNSParser.prototype.parseA = function (rdata) {
	if (this.parseErr)
		return;

	if (this.parseStart + 4 > this.parseEnd) {
		this.parseErr = new Error ("syntax error");
		return;
	}
	this.parseStart += 4;
	return [this.buf[this.parseStart-4],
		this.buf[this.parseStart-2],
		this.buf[this.parseStart-1],
		this.buf[this.parseStart-1]].join ('.');
};
DNSParser.prototype.parseSOA = function (soa) {
        var mname, rname, serial, refresh, retry, expire, minimum;
	mname = this.parseName ();
	rname = this.parseName ();
	serial = this.parseUInt32 ();
	refresh = this.parseUInt32 ();
	retry = this.parseUInt32 ();
	expire = this.parseUInt32 ();
	minimum = this.parseUInt32 ();

        soa.push (mname);
        soa.push (rname);
        soa.push (serial);
        soa.push (refresh);
        soa.push (retry);
        soa.push (expire);
        soa.push (minimum);

	return soa;
};
DNSParser.prototype.parseMX = function (mx) {
        var preference, exchange;
	preference = this.parseUInt16 ();
	exchange = this.parseName ();

	mx.push (preference);
	mx.push (exchange);
	
	return mx;
};
DNSParser.prototype.parseAAAA = function () {
	if (this.parseErr)
		return;

	if (this.parseStart + 16 > this.parseEnd) {
		this.parseErr = new Error ("syntax error");
		return;
	}
	this.parseStart += 16;
	return [(hexvalue[this.buf[this.parseStart-16]]+
		 hexvalue[this.buf[this.parseStart-15]]),
		(hexvalue[this.buf[this.parseStart-14]]+
		 hexvalue[this.buf[this.parseStart-13]]),
		(hexvalue[this.buf[this.parseStart-12]]+
		 hexvalue[this.buf[this.parseStart-11]]),
		(hexvalue[this.buf[this.parseStart-10]]+
		 hexvalue[this.buf[this.parseStart-9]]),
		(hexvalue[this.buf[this.parseStart-8]]+
		 hexvalue[this.buf[this.parseStart-7]]),
		(hexvalue[this.buf[this.parseStart-6]]+
		 hexvalue[this.buf[this.parseStart-5]]),
		(hexvalue[this.buf[this.parseStart-4]]+
		 hexvalue[this.buf[this.parseStart-3]]),
		(hexvalue[this.buf[this.parseStart-2]]+
		 hexvalue[this.buf[this.parseStart-1]])].join (":");
};
DNSParser.prototype.parseOPT = function (opt, rr) {
        var udp_payload_size, extended_rcode, version, z, data;
	if (this.parseErr)
		return;
	debug ('DNSParser.prototype.parseOPT');

	udp_payload_size = rr.class;
	extended_rcode = (rr.ttl >> 24) & 0xff;
	version = (rr.ttl >> 16) & 0xff;
	z = rr.ttl & 0xffff;
	data = this.buf.slice (this.parseStart, this.parseEnd);

        opt.push (udp_payload_size);
        opt.push (extended_rcode);
        opt.push (version);
        opt.push (z);
        opt.push (data);

	this.parseStart = this.parseEnd;
};
DNSParser.prototype.parseNSEC = function (nsec) {
        var next, types_bitmap;
	next = this.parseName ();
	if (this.parseErr)
		return;

	types_bitmap = this.buf.slice (this.parseStart, this.parseEnd);

        nsec.push (next);
        nsec.push (types_bitmap);

	this.parseStart = this.parseEnd;
};
DNSParser.prototype.parseDS = function (rdata) {
        var key_tag, algorithm, digest_type, digest;

        key_tag = this.parseUInt16 ();
        algorithm = this.parseUInt8 ();
        digest_type = this.parseUInt8 ();
	if (this.parseErr)
		return;

	digest = this.buf.slice (this.parseStart, this.parseEnd);

        rdata.push (key_tag);
        rdata.push (algorithm);
        rdata.push (digest_type);
        rdata.push (digest);

	this.parseStart = this.parseEnd;
};
DNSParser.prototype.parseDNSKEY = function (rdata) {
        var flags, protocol, algorithm, pubkey;

        flags = this.parseUInt16 ();
        protocol = this.parseUInt8 ();
        algorithm = this.parseUInt8 ();
	if (this.parseErr)
		return;

	pubkey = this.buf.slice (this.parseStart, this.parseEnd);

        rdata.push (flags);
        rdata.push (protocol);
        rdata.push (algorithm);
        rdata.push (pubkey);

	this.parseStart = this.parseEnd;
};
DNSParser.prototype.parseRR = function (rr) {
	rr.name = this.parseName ();
	rr.type = this.parseUInt16 ();
	rr.class = this.parseUInt16 ();
	rr.ttl = this.parseUInt32 ();
	rr.rdlength = this.parseUInt16 ();
	
	rr.typeName = p_type_syms[rr.type];
	rr.className = p_class_syms[rr.class];
	
	if (this.parseStart + rr.rdlength != this.parseEnd) {
		this.parseErr = new Error ("syntax error");
		return;
	}

	rr.rdata = new Array ();

	switch (rr.type) {
	case 1: // a
                rr.rdata.push (this.parseA ());
		break;
	case 2: // ns
                rr.rdata.push (this.parseName ());
		break;
	case 5: // cname
                rr.rdata.push (this.parseName ());
		break;
	case 6: // soa
		this.parseSOA (rr.rdata);
		break;
	case 12: // ptr
                rr.rdata.push (this.parseName ());
		break;
	case 15: // mx
		this.parseMX (rr.rdata);
		break;
	case 16: // txt
                var txt;
		this.parseUInt8 ();
                rr.rdata.push (this.buf.slice (this.parseStart, this.parseEnd));
                this.parseStart = this.parseEnd;
		break;
	case 28: // aaaa
                rr.rdata.push (this.parseAAAA ());
		break;
	case 41: // opt
		// edns
		this.parseOPT (rr.rdata, rr);
		break;
        case 43: // ds
		this.parseDS (rr.rdata);
		break;
	case 47: // nsec
		this.parseNSEC (rr.rdata);
		break;
        case 48: // dnskey
                this.parseDNSKEY (rr.rdata);
                break;
	default:
                rr.rdata.push (this.buf.slice(this.parseStart, this.parseEnd));
                this.parseStart = this.parseEnd;
		break;
	}

	if (this.parseStart != this.parseEnd) {
		this.parseErr = new Error("syntax error");
	}
};
DNSParser.prototype.finish = function () {
	if (arguments.length == 3 && (arguments[0] instanceof Buffer)){
		this.parseOnce.apply (this, arguments);
	}
};
function DNSWriter (buf, start, end) {
	if (arguments.length < 3) {
		this.initialized = false;
		return;
	}

	if (!(buf instanceof Buffer)) {
		throw new Error ("Argument should be a buffer");
	}
	if (start > end) {
		throw new Error ("Start extends beyond end");
	}
	if (start > buf.length) {
		throw new Error ("Offset is out of bounds");
	}
	if (end > buf.length) {
		throw new Error ("Length extends beyond buffer");
	}
	
	this.dnptrs = new Array (20);
	this.dnptrs[0] = null;
	this.lastdnptr = this.dnptrs.length;
	
	this.rdstart = 0;
	this.trstart = 0;
	
	this.buf = buf;
	this.bufStart = start;
	this.bufEnd = end;
	
	this.writeStart = 0;
	this.writeEnd = this.bufEnd;
	
	this.initialized = true;
	
	this.truncate = false;
}
exports.DNSWriter = DNSWriter;
DNSWriter.prototype.reinitialize = function() {
	DNSWriter.apply (this, arguments);
};
DNSWriter.prototype.startRdata = function () {
	if (this.truncate)
		return;
	
	this.writeUInt16 (0);
	this.rdstart = this.writeStart;
};
DNSWriter.prototype.endRdata = function () {
	if (this.truncate)
		return;
	
	var rdlength = this.writeStart - this.rdstart;
	this.buf[this.rdstart-2] = (rdlength >> 8) & 0xff;
	this.buf[this.rdstart-1] = (rdlength) & 0xff;
};
DNSWriter.prototype.startTruncate = function () {
	if (this.truncate)
		return;
	
	this.trstart = this.writeStart;
};
DNSWriter.prototype.endTruncate = function () {
	debug('DNSWriter.prototype.endTruncate');
	// todo: figure out truncate
	this.writeStart = this.trstart;
};
DNSWriter.prototype._cdname = new Buffer (ns_maxcdname);
DNSWriter.prototype.writeNameBuffer = function (name) {
	if (this.truncate)
		return;
	
	var n, len;
	
	if (ns_name_pton (name, _dname, _dname.length) == -1) {
		this.truncate = true;
		return;
	}
	if ((n = ns_name_pack (_dname, this.buf, this.writeStart, this.writeEnd - this.writeStart, this.dnptrs, this.lastdnptr)) == -1) {
		this.truncate = true;
		return;
	}
	this.writeStart += n;
};
DNSWriter.prototype.writeNameString = function (name) {
	if (this.truncate)
		return;

	var len;
	// copy string to buffer
	len = _string.write (name);
	if (len > 0 && len == _string.length) {
		len--;
	}
	_string[len] = 0; // terminate string
	this.writeNameBuffer (_string);
};
DNSWriter.prototype.writeName = function (name) {
	if (typeof name == 'string') {
		this.writeNameString (name);
	} else if (name instanceof Buffer) {
		this.writeNameBuffer (name);
	} else {
		this.writeNameString ('');
	}
};
DNSWriter.prototype.writeUInt8 = function (uint) {
	if (this.truncate)
		return;
	
	if (this.writeStart + 1 > this.writeEnd) {
		this.truncate = true;
		return;
	}
        uint = parseInt (uint, 10);
        this.buf[this.writeStart++] = uint & 0xff;
};
DNSWriter.prototype.writeUInt16 = function (uint) {
	if (this.truncate)
		return;

	if (this.writeStart + 2 > this.writeEnd) {
		this.truncate = true;
		return;
	}
	uint = parseInt (uint, 10);
	this.buf[this.writeStart++] = (uint >> 8) & 0xff;
	this.buf[this.writeStart++] = uint & 0xff;
};
DNSWriter.prototype.writeUInt32 = function (uint) {
	if (this.truncate)
		return;
	
	if (this.writeStart + 4 > this.writeEnd) {
		this.truncate = true;
		return;
	}
        uint = parseInt (uint, 10);
	this.buf[this.writeStart++] = (uint >> 24) & 0xff;
	this.buf[this.writeStart++] = (uint >> 16) & 0xff;
	this.buf[this.writeStart++] = (uint >> 8) & 0xff;
	this.buf[this.writeStart++] = (uint >> 0) & 0xff;
};
DNSWriter.prototype.writeHeader = function (header) {
	debug ('DNSWriter.prototype.writeHeader');
	var tmp;
	tmp = 0;
	tmp |= (header.qr << 15) & 0x8000;
	tmp |= (header.opcode << 11) & 0x7800;
	tmp |= (header.aa << 10) & 0x0400;
	tmp |= (header.tc << 9) & 0x0200;
	tmp |= (header.rd << 8) & 0x0100;
	tmp |= (header.ra << 7) & 0x0080;
	tmp |= (header.z << 6) & 0x0040;
	tmp |= (header.ad << 5) & 0x0020;
	tmp |= (header.cd << 4) & 0x0010;
	tmp |= (header.rcode << 0) & 0x000f;
	
	this.writeUInt16 (header.id);
	this.writeUInt16 (tmp);
	this.writeUInt16 (header.qdcount);
	this.writeUInt16 (header.ancount);
	this.writeUInt16 (header.nscount);
	this.writeUInt16 (header.arcount);
};
DNSWriter.prototype.writeQuestion = function (question) {
	this.writeName (question.name);
	this.writeUInt16 (question.type);
	this.writeUInt16 (question.class);
};
DNSWriter.prototype.writeBuffer = function (buf) {
	if (this.truncate)
		return;
	
	if (this.writeStart + buf.length > this.writeEnd) {
		this.truncate = true;
		return;
	}
	buf.copy (this.buf, this.writeStart, 0, buf.length);
	this.writeStart += buf.length;
};
DNSWriter.prototype.writeString = function (str) {
	if (this.truncate)
		return;

	if (this.writeStart + Buffer.byteLength (str, 'ascii') > this.writeEnd) {
		this.truncate = true;
		return;
	}
	this.writeStart += this.buf.write (str, this.writeStart);
};
DNSWriter.prototype.writeA = function (a) {
	if (this.truncate)
		return;

	var tmp;
	if (this.writeStart + 4 > this.writeEnd) {
		this.truncate = true;
		return;
	}
	if (typeof a !== 'string') a = '0.0.0.0';
	tmp = a.toString ().split ('.');
	this.buf[this.writeStart++] = tmp[0];
	this.buf[this.writeStart++] = tmp[1];
	this.buf[this.writeStart++] = tmp[2];
	this.buf[this.writeStart++] = tmp[3];
};
DNSWriter.prototype.writeSOA = function (soa) {
	this.writeName (soa[0]); // mname
	this.writeName (soa[1]); // rname
	this.writeUInt32 (soa[2]); // serial
	this.writeUInt32 (soa[3]); // refresh
	this.writeUInt32 (soa[4]); // retry
	this.writeUInt32 (soa[5]); // expire
	this.writeUInt32 (soa[6]); // minumum
};
DNSWriter.prototype.writeMX = function (mx) {
	this.writeUInt16 (mx[0]); // preference
	this.writeName (mx[1]); // exchange
};
DNSWriter.prototype.writeAAAA = function (aaaa) {
	if (this.truncate)
		return;
	
	var n, tmp;
	
	if (this.writeStart + 16 > this.writeEnd) {
		this.truncate = true;
		return;
	}
	if (typeof aaaa !== 'string') aaaa = '0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0';
	tmp = aaaa.split(":");

	for (var i = 0; i < 8; i++) {
		var tmp = this.writeUInt8 (parseInt (tmp[i], 16));
	}
};
DNSWriter.prototype.writeHex = function (hex) {
        if (typeof hex === 'string') {
                for (var i = 0; i < hex.length; i += 2) {
                        var uint = hex.substr (i, 2);
                        this.writeUInt8 (parseInt (uint, 16));
                }
        } else if (Buffer.isBuffer (hex)) {
                this.writeBuffer (hex);
        }
};
DNSWriter.prototype.writeDS = function (ds) {
        debug ('DNSWriter.prototype.writeDS')
	if (this.truncate)
		return;

        var flags = ds[0], protocol = ds[1], algorithm = ds[2], pubkey = ds[3];

        this.writeUInt16 (flags);
        this.writeUInt8 (pubkey);
        this.writeUInt8 (algorithm);
        this.writeHex (pubkey);
};
DNSWriter.prototype.writeRR = function (rr) {
	debug ('DNSWriter.prototype.writeRR');
	
	this.writeName (rr.name);
	this.writeUInt16 (rr.type);
	this.writeUInt16 (rr.class);
	this.writeUInt32 (rr.ttl);
	
	this.startRdata ();

	if (rr.type == 1) { // a
		this.writeA (rr.rdata[0]);
	}
	else if (rr.type == 2) { // ns
		this.writeName (rr.rdata[0]);
	}
	else if (rr.type == 5) { // cname
		this.writeName (rr.rdata[0]);
	}
	else if (rr.type == 6) { // soa
		this.writeSOA (rr.rdata);
	}
	else if (rr.type == 12) { // ptr
		this.writeName (rr.rdata[0]);
	}
	else if (rr.type == 15) { // mx
		this.writeMX (rr.rdata);
	}
	else if (rr.type == 16) { // txt
		if (typeof rr.rdata[0] === 'string') {
			this.writeUInt8 (Buffer.byteLength(rr.rdata[0], 'ascii'));
			this.writeString (rr.rdata[0]);
		} else if (rr.rdata[0] instanceof Buffer) {
			this.writeUInt8 (rr.rdata[0].length);
			this.writeBuffer (rr.rdata[0]);
		}
	}
	else if (rr.type == 28) { // aaaa
		this.writeAAAA (rr.rdata[0]);
	}
        else if (rr.type === 43) { // ds
                debug (sys.inspect (rr));
                
		this.writeDS (rr.rdata);
        }
	else {
		if (typeof rr.rdata[0] === 'string') {
			this.writeString (rr.rdata[0]);
		} else if (rr.rdata[0] instanceof Buffer) {
			this.writeBuffer (rr.rdata[0]);
		}
	}

	this.endRdata ();
};
DNSWriter.prototype.writeMessage = function (message) {
	this.writeHeader (message.header);

	for (var i = 0; i < message.question.length; i++)
		this.writeQuestion (message.question[i]);

	this.startTruncate ();

	for (var i = 0; i < message.rr.length; i++)
		this.writeRR (message.rr[i]);

	if (this.truncate)
		this.endTruncate ();
};
var parsers = new FreeList('parsers', 1000, function() {
	var parser = new DNSParser ();

	var q, rr;
	parser.onMessageBegin = function () {
		debug('parser.onMessageBegin');
		
		parser.incoming = new ServerRequest (parser.socket, parser.rinfo);
	}
	parser.onHeader = function () {
		debug('parser.onHeader');
		
		parser.parseHeader (parser.incoming.header);
	};
	parser.onQuestion = function () {
		debug('parser.onQuestion');

		q = new MessageQuestion ();
		parser.parseQuestion (q);
		parser.incoming.question.push (q);
	};
	parser.onAnswerBegin = function () {
		debug('parser.onAnswerBegin');
	};
	parser.onAuthorityBegin = function () {
		debug('parser.onAuthorityBegin');
	};
	parser.onAdditionalBegin = function () {
		debug('parser.onAdditionalBegin');
	};
	parser.onRR = function () {
		debug('parser.onRR');

		rr = new MessageRR ();
		parser.parseRR (rr);
		parser.incoming.rr.push (rr);
	};
	parser.onMessageComplete = function () {
		debug('parser.onMessageComplete');
		
		parser.onIncoming (parser.incoming);
	};
	
	return parser;
});
function MessageHeader ()
{
	this.id = 0;
	this.qr = 0;
	this.opcode = 0;
	this.aa = 0;
	this.tc = 0;
	this.rd = 0;
	this.ra = 0;
	this.z = 0;
	this.ad = 0;
	this.cd = 0;
	this.rcode = 0;
	this.qdcount = 0;
	this.ancount = 0;
	this.nscount = 0;
	this.arcount = 0;
}
exports.MessageHeader = MessageHeader;

function MessageQuestion (name, type, class)
{
	this.name = name;
	this.type = type;
	this.class = class;
}
exports.MessageQuestion = MessageQuestion;

function MessageRR (name, type, class, ttl, rdata)
{
	this.name = name;
	this.type = type;
	this.class = class;
	this.ttl = ttl;
	this.rdata = rdata;
}
exports.MessageRR = MessageRR;

function Message ()
{
	events.EventEmitter.call (this);

	this.header = new MessageHeader ();
	this.question = new Array ();
	this.rr = new Array ();
}
sys.inherits (Message, events.EventEmitter);
exports.Message = Message;

Message.prototype.addQuestion = function (qname, qtype, qclass)
{
	var q;
	q = new MessageQuestion (qname, qtype, qclass);
	this.question.push (q);
	return q;
};
Message.prototype.addRR = function (name, type, class, ttl)
{
	var rr;
	rr = new MessageRR (name, type, class, ttl, Array.prototype.slice.call (arguments, 4));
	this.rr.push (rr);
	return rr;
};
var _Writer = new DNSWriter ();
var _WriteBuffer = new Buffer (ns_maxmsg);
function sendto_errback (err)
{
};
Message.prototype.sendTo = function (socket, port, host)
{
	_Writer.reinitialize (_WriteBuffer, 0, 512);

	if (this.edns) {
		try {
			_Writer.reinitialize (_WriteBuffer, 0,
					      this.edns.udp_payload_size);
		} catch (e) {
			_Writer.reinitialize (_WriteBuffer, 0, 512);
		}
	}

	_Writer.writeMessage (this);

        var tmp = new Buffer (_Writer.writeStart);
        _WriteBuffer.copy (tmp, 0, 0, _Writer.writeStart);

	socket.send (tmp, 0, tmp.length, port, host, sendto_errback);
};
function ServerRequest (socket, rinfo)
{
	Message.call (this);

	this.socket = socket;
	this.rinfo = rinfo;
}
sys.inherits (ServerResponse, Message);
exports.ServerResponse = ServerResponse;

function ServerResponse (req)
{
	Message.call (this);

	this.socket = req.socket;
	this.rinfo = req.rinfo;

	// edns
	for (var i = 0; i < req.rr.length; i++) {
		var rr = req.rr[i];

		if (rr.type != ns_t.opt) continue;
		var edns = rr.rdata;
		if (edns.version != 0) continue; // only support edns0

		// useful in Message.prototype.sendTo
		this.edns = new Object ();
		this.edns.extended_rcode = edns.extended_rcode;
		this.edns.udp_payload_size = edns.udp_payload_size;
		this.edns.version = edns.version;
		this.edns.z = edns.z;
	}

	/* request and response id are equal */
	this.header.id = req.header.id;
	/* query type = answer */
	this.header.qr = 1;
	/* request and response rd bit are equal */
	this.header.rd = req.header.rd;
	/* request and response question sections are equal */
	this.header.qdcount = req.header.qdcount;
	this.question = req.question;
}
sys.inherits (ServerResponse, Message);
exports.ServerResponse = ServerResponse;

ServerResponse.prototype.send = function ()
{
	this.sendTo (this.socket, this.rinfo.port, this.rinfo.address);
};

function Server (type, requestListener)
{
	dgram.Socket.call (this, type);

	if (requestListener) {
		this.on("request", requestListener);
	}

	this.on ("message", messageListener);
};
sys.inherits (Server, dgram.Socket);
exports.Server = Server;

exports.createServer = function ()
{
	var type = 'udp4';
	var requestListener = null;
	if ((arguments.length >= 1) && (typeof arguments[0] == 'string')) {
		type = arguments[0];
	}
	if ((arguments.length >= 2) && (typeof arguments[1] == 'function')) {
		requestListener = arguments[1];
	}
	return new Server (type, requestListener);
};
var _Parser = parsers.alloc ();
function messageListener (msg, rinfo)
{
	var self = this;
	
	debug ("new message");
	
	_Parser.reinitialize (msg, 0, msg.length);
	_Parser.socket = this;
	_Parser.rinfo = rinfo;
	
	_Parser.onIncoming = function (req) {
		var res = new ServerResponse (req);
		self.emit ("request", req, res);
	};

	_Parser.parseMessage ();
};

function ClientRequest (socket, rinfo)
{
	Message.call (this);

	this.socket = socket;
	this.rinfo = rinfo;
}
sys.inherits (ClientRequest, Message);
exports.ClientRequest = ClientRequest;

ClientRequest.prototype.send = function ()
{
        this.sendTo (this.socket, this.rinfo.port, this.rinfo.address);
};

function ClientResponse (socket, rinfo)
{
	Message.call (this);

	this.socket = socket;
	this.rinfo = rinfo;
}
sys.inherits (ClientResponse, Message);
exports.ClientResponse = ClientResponse;

function Client (type, responseListener)
{
	dgram.Socket.call (this, type);

	if (responseListener) {
		this.on ("response", responseListener);
	}

	this.on ("message", messageListener_client);
};
sys.inherits (Client, dgram.Socket);
exports.Client = Client;

Client.prototype.request = function (host, port) {
	var req = new ClientRequest (this, {port: port, address: host});
	return req;
};

exports.createClient = function ()
{
	var type = 'udp4';
	var responseListener = null;
	if ((arguments.length >= 1) && (typeof arguments[0] == 'string')) {
		type = arguments[0];
	}
	if ((arguments.length >= 2) && (typeof arguments[1] == 'function')) {
		responseListener = arguments[1];
	}
	return new Client (type, responseListener);
};

function messageListener_client (msg, rinfo)
{
	var self = this;

	debug ("new message");

	_Parser.reinitialize (msg, 0, msg.length);
	_Parser.socket = this;
	_Parser.rinfo = rinfo;

	_Parser.onIncoming = function (res) {
		self.emit ("response", res);
	};

	_Parser.parseMessage ();
};

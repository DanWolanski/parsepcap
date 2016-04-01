#!/usr/bin/env node
// Author - Dan Wolanski
// TODO - Put in description
// This script is dependant on the following npm packages
//      yargs- Command line parsing tool
//      pcap-parser - pcap file parser library
//      sip - Lightweight sip library used to parse/read SIP packets
//      fs - used for file manipulation
//      websequencediagrams - Generate png sequence diagrams from the web site
//      moment - Timestamp and delta parsing

var argv = require('yargs')
	.usage('Usage: $0 -f [pcapfile]')
	.default('f','file.pcap')
	.alias('f','filename')
	.argv;
console.log('Script Arguments are: ');
console.log(argv);


var pcapp = require('pcap-parser');
var SIP = require('sip');
var wsd = require('websequencediagrams');
var fs = require('fs');
var moment = require('moment');

var msmlflow = [];
var sipcallmap = new Map();

//Start the parsing of the pcap here
var parser = pcapp.parse(argv.filename);
parser.on('packet', function(packet) {
  // do your packet processing
//      parse_pcap_tcp(buffer)
//      console.log(sip.parse(raw_packet));
//        var packet=pcap.decode.packet(raw_packet);

//console.log(packet.data);
    var parsedpacket = parse_pcap_packet(packet.data);
   //console.log(parsedpacket);

    if(parsedpacket.srcport == 5060 || parsedpacket.srcport == 5070 || parsedpacket.dstport== 5060 || parsedpacket.dstport == 5070){
        //console.log('Sip Packet detected');
        var sipmsg = SIP.parse(parsedpacket.data);
        //console.log(sipmsg);
        var callid=sipmsg.headers['call-id'];
        var totag = sipmsg.headers.to.params.tag;
        var fromtag = sipmsg.headers.to.params.tag;
        var msmldata = '';

        if(sipmsg.headers['content-type']=='application/msml+xml'){
            msmldata=sipmsg.content;
            msmlflow.push({
                srcip: parsedpacket.srcip,
                srcport: parsedpacket.srcport,
                dstip: parsedpacket.dstip,
                dstport: parsedpacket.dstport,
                sipcallid: callid,
                timestamp : packet.header.timestampSeconds+'.'+packet.header.timestampMicroseconds,
                msmldata: msmldata});
        }


        //Check to see if the call-id is inside the call list
        var entry = {
            sipcallid : callid,
            timestamp : packet.header.timestampSeconds+'.'+packet.header.timestampMicroseconds,
            sippacket : sipmsg,
            toTag: totag,
            fromTag: fromtag,
            srcip: parsedpacket.srcip,
            srcport: parsedpacket.srcport,
            dstip: parsedpacket.dstip,
            dstport: parsedpacket.dstport,
            msmldata: msmldata
        };

       // console.log(entry);

        if(!sipcallmap.has(callid)) {
	    console.log('New CallId detected - '+callid);
	    var msgarray = new Array();
            msgarray.push(entry);
            sipcallmap.set(callid,msgarray);
        }else{
		//console.log(callid+' Already in sipcallmap');
        	var currententry=sipcallmap.get(callid);
	        currententry.push(entry);
	}
        //sipcallmap.get(callid).push(entry);


        } // End sip call processing
});

parser.on('end',function() {
    console.log('--------------------------------------');
    console.log('Done parsing file');
    console.log('--------------------------------------');
        console.log(sipcallmap.size+' calls found :');
        console.log(sipcallmap.keys());
    console.log('--------------------------------------');
    console.log('Generating SIP Flows');
    console.log('--------------------------------------');
    //console.log(sipcallmap);
       for(var call of sipcallmap.values()){
        //    console.log('Generating call flow for - '+call);
            GenerateSipFlows(call);
        }

    console.log('--------------------------------------');
    console.log('Generating MSML Flow');
    console.log('--------------------------------------');

  //  console.log(msmlflow);
    GenerateMsmlFlows( msmlflow );


});

parser.on('error',function(error) {
        console.log('Error in parsing');
        console.log(error);
});


function parse_pcap_packet(buffer) {
    //In this case there is not enough header to be a valid packet
    if (buffer.length <= 0x2A) {
	console.log('Buffer too small');
        return null;
    }
    //http://www.markhneedham.com/blog/2012/07/15/tcpdump-learning-how-to-read-udp-packets/

    // Read IP fields

    var diffserv = buffer.readUInt8(0x11);
    var totallength = buffer.readUInt16BE(0x12);

    //ToDo add in support for TCP
    if(buffer.readUInt8(0x19).toString()!= '17' ){
	console.log("We don't yet support tcp");
        return null;
    } else {
	//console.log('Setting to UDP');
        var protocol='udp';
    }

    var srcip = buffer.readUInt8(0x1C).toString() + '.' +
        buffer.readUInt8(0x1D).toString() + '.' +
        buffer.readUInt8(0x1E).toString() + '.' +
        buffer.readUInt8(0x1F).toString();

    var dstip = buffer.readUInt8(0x20).toString() + '.' +
        buffer.readUInt8(0x21).toString() + '.' +
        buffer.readUInt8(0x22).toString() + '.' +
        buffer.readUInt8(0x23).toString();

    //Read the UDP fields
    var srcport = buffer.readUInt16BE(0x24);
    var dstport = buffer.readUInt16BE(0x26);
    var udplength = buffer.readUInt16BE(0x28);

    var data = buffer.slice(0x2C);

    return {
        diffserv: diffserv,
        totallength: totallength,
        protocol: protocol,
        srcip: srcip,
        dstip: dstip,
        srcport: srcport,
        dstport: dstport,
        data: data
    }
}


function GenerateMsmlFlows(mymsmlflows) {
    //In this case there is not enough header to be a valid packet
    if (mymsmlflows.length == 0) {
        return null;
    }
   // console.log(mymsmlflows);
    var seq='title MSML Message Flow\n';

    //srcport: parsedpacket.srcport,
    //    dstip: parsedpacket.dstip,
    //    dstip: parsedpacket.dstport,
    //    sipcallid: callid,
    //    timestamp : packet.header.timestampSeconds+'.'+packet.header.timestampMicroseconds,
    //    msmldata: msmldata})
    mymsmlflows.forEach(function(msg) {
        seq = seq +'ABCDEREPLACEMEABCDE' +msg.srcip + '->' + msg.dstip + ':' +'@['+moment.unix(msg.timestamp).format("HH:mm:ss.SSS")+']\n'+ msg.msmldata +'\n';
        });



            fs.writeFile("msmlSeq.txt", seq.replace(/ABCDEREPLACEMEABCDE/g,'\n'));
    var cleanseq=seq.replace(/\r\n|\n|\r/g, '\\n')
        .replace(/\t/g,'   ')
        .replace(/ABCDEREPLACEMEABCDE/g,'\n');
 //   console.log(cleanseq);

    wsd.diagram(cleanseq, "modern-blue", "png", function(er, buf, typ) {
        if (er) {
            console.error(er);
        } else {
//            console.log("Received MIME type:", typ);
            fs.writeFile("msmlSeq.png", buf);
        }
    });
}


function GenerateSipFlows(mysipflows) {
    //In this case there is not enough header to be a valid packet

     //console.log(mysipflows);
    var seq='title Sip call Flow \n';
    /*
    var entry = {
        sipcallid : callid,
        timestamp : packet.header.timestampSeconds+'.'+packet.header.timestampMicroseconds,
        sippacket : sipmsg,
        toTag: totag,
        fromTag: fromtag,
        srcip: parsedpacket.srcip,
        srcport: parsedpacket.srcport,
        dstip: parsedpacket.dstip,
        dstport: parsedpacket.dstport,
        msmldata: msmldata
    };
    */
    var callid='';

    mysipflows.forEach(function(msg) {
        seq = seq +'ABCDEREPLACEMEABCDE' +msg.srcip + '->' + msg.dstip + ':' +'@['+moment.unix(msg.timestamp).format("HH:mm:ss.SSS")+']\n'+ SIP.stringify(msg.sippacket) +'\n';
        callid=msg.sipcallid;
    });


    fs.writeFile("sipcall-"+callid+".txt", seq);
    var cleanseq=seq.replace(/\r\n|\n|\r/g, '\\n')
        .replace(/\t/g,'   ')
        .replace(/ABCDEREPLACEMEABCDE/g,'\n');
    //console.log(cleanseq);

    wsd.diagram(cleanseq, "modern-blue", "png", function(er, buf, typ) {
        if (er) {
            console.error(er);
        } else {
        //    console.log("Received "+ callid+" flow -  MIME type:", typ);
            fs.writeFile("sipcall-"+callid+".png", buf);
        }
    });

}

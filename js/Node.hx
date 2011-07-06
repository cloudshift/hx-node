/* Same license as Node.js
   Maintainer: Ritchie Turner, blackdog@cloudshift.cl

   Node.js api without haXe embellishments.
*/

package js;

typedef NodeListener = Dynamic;
typedef NodeErr = Null<String>;

/* 
   emits: newListener
 */
typedef NodeEventEmitter = {
  function addListener(event:String,fn:NodeListener):Dynamic;
  function on(event:String,fn:NodeListener):Dynamic;
  function once(event:String,fn:NodeListener):Void;
  function removeListener(event:String,listener:NodeListener):Void;
  function removeAllListeners(event:String):Void;
  function listeners(event:String):Array<NodeListener>;
  function setMaxListeners(m:Int):Void;
  function emit(event:String,?arg1:Dynamic,?arg2:Dynamic,?arg3:Dynamic):Void;
}

typedef NodeWatchOpt = {persistant:Bool,interval:Int};

typedef NodeExecOpt = {
  var encoding:String;
  var timeout:Int;
  var maxBuffer:Int;
  var killSignal:String;
  var env:Dynamic;
  var cwd:String;
}

typedef NodeSpawnOpt = {
  var cwd:String;
  var env:Dynamic;
  var customFds:Array<Int>;
  var setsid:Bool;
}

/* note:can't spec multiple optional args, so adding an arbitrary 3 */
typedef NodeConsole = {
  function log(s:String,?a1:Dynamic,?a2:Dynamic,?a3:Dynamic):Void;
  function info(s:String,?a1:Dynamic,?a2:Dynamic,?a3:Dynamic):Void;
  function warn(s:String,?a1:Dynamic,?a2:Dynamic,?a3:Dynamic):Void;
  function error(s:String,?a1:Dynamic,?a2:Dynamic,?a3:Dynamic):Void;
  function time(label:String):Void;
  function timeEnd(label:String):Void;
  function dir(obj:Dynamic):Void;
  function trace():Void;
  function assert():Void;
}
  
typedef NodePath = {
  function join(?p1:String,?p2:String,?p3:String):String;
  function normalize(p:String):String;
  function resolve(from:Array<String>,to:String):Void;
  function dirname(p:String):String;
  function basename(p:String,?ext:String):String;
  function extname(p:String):String;
  function exists(p:String,cb:Bool->Void):Void;
  function existsSync(p:String):Bool;
}

typedef NodeUrlObj = {
  var href:String;
  var host:String;
  var protocol:String;
  var auth:String;
  var hostname:String;
  var port:String;
  var pathname:String;
  var search:String;
  var query:Dynamic;
  var hash:String;
}

typedef NodeUrl = {
  function parse(p:String,?andQueryString:Bool):NodeUrlObj;
  function format(o:NodeUrlObj):String;
  function resolve(from:Array<String>,to:String):String;
}

typedef NodeQueryString = {
  function parse(s:String,?sep:String,?eq:String):Dynamic;
  function escape(s:String):String;
  function unescape(s:String):String;
  function stringify(obj:Dynamic,?sep:String,?eq:String):String;
}

@:native("Buffer") extern class Buffer implements ArrayAccess<Int> {
  function new(?p1:Dynamic,?p2:Dynamic):Void;
  var length(default,null) : Int;
  function copy(targetBuffer:Buffer,targetStart:Int,sourceStart:Int,sourceEnd:Int):Void;
  function slice(start:Int,end:Int):Buffer;
  function write(s:String,?offset:Int,?enc:String):Void;
  function toString(enc:String,?start:Int,?stop:Int):String;
  static function isBuffer(o:Dynamic):Bool;
  static function byteLength(s:String,?enc:String):Int;
}

typedef NodeScript = {
  function runInThisContext():Dynamic;
  function runInNewContext(?sandbox:Dynamic):Void;
}

typedef NodeVM =  {  
  function runInThisContext():Dynamic;
  function runInNewContext(?sandbox:Dynamic):Void;
  function createScript(code:Dynamic,?fileName:String):NodeScript;
}
  
typedef ReadStreamOpt = {
  var flags:String;
  var encoding:String;
  var fd:Null<Int>;
  var mode:Int;
  var bufferSize:Int;
  //TODO start:Int, end:Int
}

typedef WriteStreamOpt = {
  var flags:String;
  var encoding:String;
  var mode:Int;
}

/* 
   Emits:
   data,end,error,close,fd
*/
typedef NodeReadStream = { > NodeEventEmitter,
  var readable:Bool;
  function pause():Void;
  function resume():Void;
  function destroy():Void;
  function destroySoon():Void;
  function setEncoding(enc:String):Void;
  function pipe(dest:NodeWriteStream,opts:{end:Bool}):Void;
}

/* 
   Emits:
   drain,error,close,pipe
*/
typedef NodeWriteStream = { > NodeEventEmitter,
  var writable:Bool;
  function write(?d:Dynamic,?enc:String):Bool;
  function end(?s:Dynamic,?enc:String):Void; // string or buffer
  function destroy():Void;
}

typedef NodeOs = {
  function hostname():String;
  function type():String;
  function release():String;
  function uptime():Int;
  function loadavg():Array<Float>;
  function totalmem():Int;
  function freemem():Int;
  function cpus():Int;
}

typedef Stat = {
  var dev:Int;
  var ino:Int;
  var mode:Int;
  var nlink:Int;
  var uid:Int;
  var gid:Int;
  var rdev:Int;
  var size:Int;
  var blkSize:Int;
  var blocks:Int;
  var atime:String;
  var mtime:String;
  var ctime:String;
  function isFile():Bool;
  function isDirectory():Bool;
  function isBlockDevice():Bool;
  function isCharacterDevice():Bool;
  function isSymbolicLink():Bool;
  function isFIFO():Bool;
  function isSocket():Bool;
}

typedef NodeFS = {
  // async
  function rename(from:String,to:String,cb:NodeErr->Void):Void;
  function stat(path:String,cb:NodeErr->Stat->Void):Void;
  function fstat(fd:Int,cb:NodeErr->Stat->Void):Void;
  function lstat(path:Dynamic,cb:NodeErr->Stat->Void):Void;
  function link(srcPath:String,dstPath:String,cb:NodeErr->Void):Void;
  function unlink(path:String,cn:NodeErr->Void):Void;
  function symlink(linkData:Dynamic,path:String,cb:NodeErr->Void):Void;
  function readlink(path:String,cb:NodeErr->String->Void):Void;
  function realpath(path:String,cb:NodeErr->String->Void):Void;
  function chmod(path:String,mode:Int,cb:NodeErr->Void):Void;
  function rmdir(path:String,cb:NodeErr->Void):Void;
  function mkdir(path:String,mode:Int,cb:NodeErr->Void):Void;
  function readdir(path:String,cb:NodeErr->Array<String>->Void):Void;
  function close(fd:Int,cb:NodeErr->Void):Void;
  function open(path:String,flags:String,mode:Int,cb:NodeErr->Int->Void):Void;
  function write(fd:Int,bufOrStr:Dynamic,offset:Int,length:Int,position:Null<Int>,?cb:NodeErr->Int->Void):Void;
  function read(fd:Int,buffer:Buffer,offset:Int,length:Int,position:Int,cb:NodeErr->Int->Void):Void;
  function truncate(fd:Int,len:Int,cb:NodeErr->Void):Void;
  function readFile(path:String,?enc:String,cb:NodeErr->String->Void):Void;
  function writeFile(fileName:String,contents:String,cb:NodeErr->Void):Void;
  function chown(path:String,uid:Int,gid:Int,cb:NodeErr->Void):Void ;
  // sync
  function renameSync(from:String,to:String):Void;
  function statSync(path:String):Stat;
  function fstatSync(fd:Int):Stat;
  function lstatSync(path:Dynamic):Stat; // path or fd
  function linkSync(srcPath:String,dstPath:String):Void;
  function unlinkSync(path:String):Void;
  function symlinkSync(linkData:Dynamic,path:String):Void;
  function readlinkSync(path:String):String;
  function realpathSync(path:String):String;
  function chmodSync(path:String,?mode:Int):Void;
  function rmdirSync(path:String):Void;
  function mkdirSync(path:String,mode:Int):Void;
  function readdirSync(path:String):Array<String>;
  function closeSync(fd:Int):Void;
  function openSync(path:String,flags:String,?mode:Int):Int;
  function writeSync(fd:Int,bufOrStr:Dynamic,offset:Int,length:Int,position:Null<Int>):Int;
  function readSync(fd:Int,buffer:Buffer,offset:Int,length:Int,position:Int):Int;
  function truncateSync(fd:Int,len:Int):NodeErr;  
  function readFileSync(path:String,?enc:String):String;
  function writeFileSync(fileName:String,contents:String,?enc:String):Void;
  function chownSync(path:String,uid:Int,gid:Int):Void;
  // other
  function watchFile(fileName:String,?options:NodeWatchOpt,listener:Stat->Stat->Void):Void;
  function unwatchFile(fileName:String):Void;
  function createReadStream(path:String,?options:ReadStreamOpt):NodeReadStream;
  function createWriteStream(path:String,?options:WriteStreamOpt):NodeWriteStream;  
}
  
typedef NodeUtil = {
  function debug(s:String):Void;
  function inspect(o:Dynamic,?showHidden:Bool,?depth:Int):Void;
  function log(s:String):Void;
  function pump(rs:NodeReadStream,ws:NodeWriteStream,cb:Dynamic->Void):Void;
  function inherits(constructor:Dynamic,superConstructor:Dynamic):Void;
}

/* 
  Emits:
  exit, uncaughtException
 */
typedef NodeProcess = { > NodeEventEmitter,
  var stdout:NodeWriteStream;
  var stdin:NodeReadStream;
  var stderr:NodeWriteStream;
  var argv:Array<String>;
  var env:Dynamic;
  var pid:Int;
  var title:String;
  var platform:String;
  var installPrefix:String;
  var execPath:String;
  var version:String;
  
  function memoryUsage():{rss:Int,vsize:Int,heapUsed:Int,heapTotal:Int};
  function nextTick(fn:Void->Void):Void;
  function exit(code:Int):Void;
  function cwd():String;
  function getuid():Int;
  function getgid():Int;
  function setuid(u:Int):Void;
  function setgid(g:Int):Void;
  function umask(?m:Int):Void;
  function chdir(d:String):Void;
  function kill(pid:Int,?signal:String):Void;
  
}


typedef NodeChildProcess = { > NodeEventEmitter,
    var stdin:NodeWriteStream;
    var stdout:NodeReadStream;
    var stderr:NodeReadStream;
    var pid:Int;
}

/* 
   Emits:
   exit
*/
typedef NodeChildProcessCommands = { > NodeEventEmitter,
  function kill(signal:String):Void;
  function spawn(command: String,args: Array<String>,?options: Dynamic ) : NodeChildProcess;
  function exec(command: String,?options:Dynamic,cb: {code:Int}->String->String->Void ): NodeChildProcess;
}


/* NET ............................................. */
  
/* 
   Emits:
   connection
*/
typedef NodeNet = { > NodeEventEmitter, 
  function createServer(fn:NodeNetSocket->Void):NodeNetServer;
  function createConnection(port:Int,host:String):NodeNetSocket;
  // TODO function createConnection(path:String):Void;
  function isIP(input:String):Int; // 4 or 6
  function isIPv4(input:String):Bool;
  function isIPv6(input:String):Bool;
}
  
/* 
   Emits:
   connection,close,request
*/
typedef NodeNetServer = { > NodeEventEmitter,
  var maxConnections:Int;
  var connections:Int;
  function listen(port:Int,?host:String,?cb:Void->Void):Void;
  // TODO function listen(path:String,cb:Void->Void):Void;
  function listenFD(fd:Int):Void;
  function close():Void;
  function address():Void;
}
  
/*
  
  Emits:
  connect,data,end,timeout,drain,error,close

  implements a duplex stream interface
*/
typedef NodeNetSocket = { > NodeEventEmitter, 
  var remoteAddress:String;
  var bufferSize:Int;
  function connect(port:Int,?host:String,?cb:Void->Void):Void;
  //TODO function connect(path,cb:Void->Void):Void;
  function setEncoding(enc:String):Void;
  function setSecure():Void;
  function write(data:Dynamic,?enc:String,?cb:Void->Void):Bool;
  // TODO write(data:Dynamic,?enc:String,?fileDesc:Int,?cb:Void->Void):Bool;
  function end(?data:Dynamic,?enc:String):Void;
  function destroy():Void;
  function pause():Void;
  function resume():Void;
  function setTimeout(timeout:Int,?cb:Void->Void):Void;
  function setNoDelay(?noDelay:Bool):Void;
  function setKeepAlive(enable:Bool,?delay:Int):Void;
  function address():{address:String,port:Int}; 
}

/* HTTP ............................................*/

  
/* 
   Emits:
   data,end
 */
typedef NodeHttpServerReq = {
  var method:String;
  var url:String;
  var headers:Dynamic;
  var trailers:Dynamic;
  var httpVersion:String;
  var connection:NodeNetSocket;
  function setEncoding(enc:String):Void;
  function pause():Void;
  function resume():Void;
}

/* 
 */
typedef NodeHttpServerResp = {
  var statusCode:Int;
  function writeContinue():Void;
  function writeHead(statusCode:Int,?reasonPhrase:String,headers:Dynamic):Void;
  function setHeader(name:String,value:Dynamic):Void;
  function getHeader(name:String):Dynamic;
  function removeHeader(name:String):Void;
  function end(?data:Dynamic,?enc:String):Void;
  function addTrailers(headers:Dynamic):Void;
  function write(chunk:String,?enc:String):Void;  
}

typedef NodeHttpClientReq = { > NodeEventEmitter,
  function sendBody(chunk:String,?enc:String):Void;
  function end():Void;
}

typedef NodeHttpClientResp = { > NodeEventEmitter,
  var statusCode:Int;
  var httpVersion:String;
  var headers:Dynamic;
  var client:NodeHttpClient;
  function setEncoding(enc:String):Void;
  function resume():Void;
  function pause():Void;  
}

typedef NodeHttpClient = { > NodeEventEmitter,
  function request(method:String,path:String,?headers:Dynamic):NodeHttpClientReq;
  function verifyPeer():Bool;
  function getPeerCertificate():NodePeerCert;
}

/* 
   Emits:
   request,connection,checkContinue,upgrade,clientError,close
 */
typedef NodeHttpServer = { > NodeEventEmitter,
  function listen(port:Int,?host:String,?cb:Void->Void):Void;
  function close():Void;
}

/* 
 */
typedef NodeHttpReqOpt = {
  var host:String;
  var port:Int;
  var path:String;
  var method:String;
  var headers:Dynamic;
}

/* 
   Emits
   upgrade,continue
*/
typedef NodeAgent = { > NodeEventEmitter,
  var maxSockets:Int;
  var sockets:Array<NodeNetSocket>;
  var queue:Array<NodeHttpServerReq>;
}
    
typedef NodeHttp = {
  function createServer(listener:NodeHttpServerReq->NodeHttpServerResp->Void,?options:Dynamic):NodeHttpServer;
  function createClient(port:Int,host:String):NodeHttpClient;
  function request(options:NodeHttpReqOpt,res:NodeHttpClientResp->Void):Void;
  function get(options:NodeHttpReqOpt,res:NodeHttpClientResp->Void):Void;
  function getAgent(host:String,port:Int):NodeAgent;
}
  
typedef NodeHttps = {
  function createServer(options:{key:String,cert:String},listener:NodeHttpServerReq->NodeHttpServerResp->Void):NodeHttpServer;
  function request(options:NodeHttpReqOpt,res:NodeHttpClientResp->Void):Void;
  function get(options:NodeHttpReqOpt,res:NodeHttpClientResp->Void):Void;
}
  
typedef NodeDns = {
  function resolve(domain:String,?rrtype:String,cb:NodeErr->Array<Dynamic>->Void):Void;
  function resolve4(domain:String,cb:NodeErr->Array<String>->Void):Void;
  function resolve6(domain:String,cb:NodeErr->Array<String>->Void):Void;
  function resolveMx(domain:String,cb:NodeErr->Array<{priority:Int,exchange:String}>->Void):Void;
  function resolveSrv(domain:String,cb:NodeErr->Array<{priority:Int,weight:Int,port:Int,name:String}->Void>):Void;
  function reverse(ip:String,cb:NodeErr->Array<String>->Void):Void;
  function resolveTxt(domain:String,cb:NodeErr->Array<String>->Void):Void;
  function lookup(domain:String,?family:String,cb:NodeErr->String->Int->Void):Void;
}

typedef NodeTTY = {
  /* returns a non homogenous array of elements, el[0].fd, el[1] is a child process obj
     best check it manually */
  function open(path:String,args:Dynamic):Array<Dynamic>;
  function isatty(fd:Int):Bool;
  function setRawMode(mode:Bool):Void;
  function setWindowSize(fd:Int,row:Int,col:Int):Void;
  function getWindowSize(fd:Int):{row:Int,col:Int};
}

/* UDP ........................................ */

typedef NodeUDPCallback = NodeErr->haxe.io.Bytes->Void;

typedef NodeUDP = {
  // Valid types: udp6, and unix_dgram.
  function createSocket(type:String,cb:NodeUDPCallback):NodeDGSocket;
}

/* 
   Emits: message,listening,close
*/
typedef NodeDGSocket = { > NodeEventEmitter,
  //TODO function send(buf, offset, length, path, [callback])
  function send(buf:Buffer,offset:Int,length:Int,port:Int,address:String,cb:NodeUDPCallback):Void;
  function bind(path:String):Void;
  //function bind(port:Int,?address:String):Void;
  function close():Void;
  function address():Dynamic;
  function setBroadcast(flag:Bool):Void;
  function setTTL(ttl:Int):Void;
  function setMulticastTTL(ttl:Int):Void;
  function setMulticastLoopback(flag:Bool):Void;
  function addMembership(multicastAddress:String,?multicastInterface:String):Void;
  function dropMembership(multicastAddress:String,?multicastInterface:String):Void;
}
  
/* CRYPTO ..................................... */
  
typedef NodeCredDetails = {
  var key:String;
  var cert:String;
  var ca:Array<String>;
}

typedef NodePeerCert = {
  var subject:String;
  var issuer:String;
  var valid_from:String;
  var valid_to:String;
}

typedef NodeCreds = Dynamic;

typedef NodeHmac = {
  function update(data:Dynamic):Void;
  function digest(?enc:String):String;
}
  
typedef NodeHash = {
  function update(data:Dynamic):Void;
  function digest(?enc:String):String;
  function createHmac(algo:String,key:String):NodeHmac;
}

typedef NodeCipher = {
  function update(data:Dynamic,?input_enc:String,?output_enc:String):Dynamic;
  function final(output_enc:String):Void;
}
  
typedef NodeDecipher = {
  function update(data:Dynamic,?input_enc:String,?output_enc:String):Dynamic;
  function final(?output_enc:String):Dynamic;
}
  
typedef NodeSigner = {
  function update(data:Dynamic):Void;
  function sign(private_key:String,?output_format:String):Dynamic;
}
  
typedef NodeVerify = {
  function update(data:Dynamic):Void;
  function verify(cert:String,?sig_format:String):Bool;
}

typedef NodeCrypto = {
  function createCredentials(details:NodeCredDetails):NodeCreds;
  function createHash(algo:String):NodeHash; // 'sha1', 'md5', 'sha256', 'sha512'
  function createCipher(algo:String,key:String):NodeCipher;
  function createDecipher(algo:String,key:String):NodeDecipher;
  function createSign(algo:String):NodeSigner;
  function createVerify(algo:String):NodeVerify;
}

/* TLS/SSL ................................................ */

/* 
   Emits:
   secureConnection
*/
typedef NodeTLSServer = NodeNetServer;

typedef NodeTLS ={
  function connect(port:Int,host:String,opts:Dynamic,cb:Void->Void):Void;
  function createServer(opts:Dynamic,cb:NodeTLSServer->Void):Void;
}

/*
  Snarfed from Tong's version ...
 */ 
typedef NodeAssert = {
	function fail(actual:Dynamic,expected:Dynamic,message:Dynamic,operator:Dynamic): Void;
	function ok(value:Dynamic,?message:Dynamic):Void;
	function equal(actual:Dynamic,expected:Dynamic,?message:Dynamic):Void;
	function notEqual(actual:Dynamic,expected:Dynamic,?message:Dynamic):Void;
	function deepEqual(actual:Dynamic,expected:Dynamic,?message:Dynamic):Void;
	function notDeepEqual(actual:Dynamic,expected:Dynamic,?message:Dynamic):Void;
	function strictEqual(actual:Dynamic,expected:Dynamic,?message:Dynamic):Void;
	function notStrictEqual(actual:Dynamic,expected:Dynamic,?message:Dynamic):Void;
	function throws(block:Dynamic,error:Dynamic,?message:Dynamic):Void;
	function doesNotThrow(block:Dynamic,error:Dynamic,?message:Dynamic):Void;
	function ifError(value:Dynamic):Void;
}

typedef NodeREPL = {
	function start( prompt : String, ?stream : Dynamic ) : Void;
}

// Node Constants
class NodeC {
  public static inline var UTF8 = "utf8";
  public static inline var ASCII = "ascii";
  public static inline var BINARY = "binary";

  //events - thanks tmedema
  public static var EVENT_EVENTEMITTER_NEWLISTENER = "newListener";
	public static var EVENT_EVENTEMITTER_ERROR = "error";
	public static var EVENT_STREAM_DATA = "data";
	public static var EVENT_STREAM_END = "end";
	public static var EVENT_STREAM_ERROR = "error";
	public static var EVENT_STREAM_CLOSE = "close";
	public static var EVENT_STREAM_DRAIN = "drain";
	public static var EVENT_STREAM_CONNECT = "connect";
	public static var EVENT_STREAM_SECURE = "secure";
	public static var EVENT_STREAM_TIMEOUT = "timeout";
	public static var EVENT_PROCESS_EXIT = "exit";
	public static var EVENT_PROCESS_UNCAUGHTEXCEPTION = "uncaughtException";
	public static var EVENT_PROCESS_SIGINT = "SIGINT";
	public static var EVENT_PROCESS_SIGUSR1 = "SIGUSR1";
	public static var EVENT_CHILDPROCESS_EXIT = "exit";
	public static var EVENT_HTTPSERVER_REQUEST = "request";
	public static var EVENT_HTTPSERVER_CONNECTION = "connection";
	public static var EVENT_HTTPSERVER_CLOSE = "close";
	public static var EVENT_HTTPSERVER_UPGRADE = "upgrade";
	public static var EVENT_HTTPSERVER_CLIENTERROR = "clientError";
	public static var EVENT_HTTPSERVERREQUEST_DATA = "data";
	public static var EVENT_HTTPSERVERREQUEST_END = "end";
	public static var EVENT_CLIENTREQUEST_RESPONSE = "response";
	public static var EVENT_CLIENTRESPONSE_DATA = "data";
	public static var EVENT_CLIENTRESPONSE_END = "end";
	public static var EVENT_NETSERVER_CONNECTION = "connection";
	public static var EVENT_NETSERVER_CLOSE = "close";

	public static var FILE_READ = "r";
	public static var FILE_READ_APPEND = "r+";
	public static var FILE_WRITE = "w";
	public static var FILE_WRITE_APPEND = "a+";
	public static var FILE_READWRITE = "a";
	public static var FILE_READWRITE_APPEND = "a+";
}

class Node {  
  public static var require(default,null) : String->Dynamic;
  public static var querystring(default,null) : NodeQueryString;
  public static var util(default,null) : NodeUtil;
  public static var fs(default,null) : NodeFS;
  public static var dgram(default,null) :NodeUDP ;
  public static var net(default,null) : NodeNet;
  public static var os(default,null) : NodeOs;
  public static var http(default,null) : NodeHttp;
  public static var https(default,null) : NodeHttps;
  public static var path(default,null) : NodePath;
  public static var url(default,null) : NodeUrl;
  public static var dns(default,null) : NodeDns;
  public static var vm(default,null) : NodeVM;
  public static var process(default,null) : NodeProcess;
  public static var tty(default,null) : NodeTTY;
  public static var assert(default,null) : NodeAssert;
  public static var crypto(default,null) : NodeCrypto;
  public static var tls(default,null) : NodeTLS;
  public static var repl(default,null) : NodeREPL;
  public static var childProcess(default,null) : NodeChildProcessCommands;
  public static var console(default,null) : NodeConsole;
  
  public static var paths:Array<String>;
  public static var setTimeout:Dynamic->Int->Array<Dynamic>->Int;
  public static var clearTimeout:Int->Void;
  public static var setInterval:Dynamic->Int->Array<Dynamic>->Int;
  public static var clearInterval:Int->Void;  
  public static var global:Dynamic;
  
  public static var __filename:String;
  public static var __dirname:String;
  public static var module:Dynamic;
  public static var stringify:Dynamic->String;
  public static var parse:String->Dynamic;
  public static var queryString:NodeQueryString;

  /* deprecated */
  public static function
  newBuffer(d:Dynamic,?enc:String):Buffer {
    var b = require('buffer');
    if (enc != null)
      return untyped __js__('new b.Buffer(d,enc)');
    else
      return untyped __js__('new b.Buffer(d)');
  }

  public static function
  __init__() {
    __filename = untyped __js__('__filename');
    __dirname = untyped __js__('__dirname');
    paths = untyped  __js__('require.paths');
    setTimeout = untyped __js__('setTimeout');
    clearTimeout = untyped __js__('clearTimeout');
    setInterval = untyped __js__('setInterval');
    clearInterval = untyped __js__('clearInterval');
    global = untyped __js__('global');
    process = untyped __js__('process');
    require = untyped __js__('require');
    console = untyped __js__('console');
    module = untyped __js__('module');  // ref to the current module
    stringify = untyped __js__('JSON.stringify');
    parse = untyped __js__('JSON.parse');
   
    // just load everything, maybe not to everyone's taste
    util = require("util");
    fs = require("fs");
    net = require("net");
    http = require("http");
    https = require("https");
    path = require('path');
    url = require('url');
    os = require('os');
    crypto = require("crypto");
    dns = require("dns");
    queryString = require('querystring');
    assert = require('assert');
    childProcess = require('child_process');
    vm = require('vm');
    tls = require('tls');
    dgram = require('dgram');
    assert = require('assert');
    repl = require('repl');
    var b:Dynamic = require("buffer");
    untyped js.Buffer = b.Buffer;
    
  }
  
}



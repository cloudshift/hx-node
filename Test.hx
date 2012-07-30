
import js.Node;

import haxe.io.Eof;
import haxe.io.Bytes;
import haxe.io.BytesBuffer;
import haxe.io.BytesInput;
import haxe.io.BytesData;

import js.node.AsyncReader;

import js.node.AsyncPositionReaderImpl;
import js.node.AsyncStreamReaderImpl;

//using haxe.aio.File;


enum ReaderType {
  Stream;
  Seek;
  
}

class MyFile {

  public static function
  asyncReader(type:ReaderType,file:String,?bufSize:Int,cb:AsyncReader->Void) {
    return switch(type) {
    case Seek:
      new AsyncPositionReaderImpl(file,bufSize).open(cb);
    case Stream:
      new AsyncStreamReaderImpl(file,bufSize).open(cb);
    }
  }
}


using Lambda;

class Test {

  public static function
  main() {

    trace(js.Node.process.arch);
    //   trace("newSocket:"+js.Node.newSocket().connect(80,"cloudshift.cl"));

    var b = new NodeBuffer(20);
    b.fill("A".charCodeAt(0),0);
    trace(b.toString(NodeC.UTF8));

    var b2 = new NodeBuffer("To be or not to be",NodeC.UTF8);
    trace(b2.toString(NodeC.UTF8));

    var s = "that is the question";
    var arr = [];
    for (c in 0...s.length) arr.push(s.charCodeAt(c));
    
    var b3 = new NodeBuffer(arr);
    trace(b3.toString(NodeC.UTF8));
    
    var file = "README";
    var myBuff = new BytesBuffer();

#if true
    MyFile.asyncReader(Seek,file,10,function(ar) {
        ar.onEof(function() {
            trace(myBuff.getBytes().toString());
            ar.seek(0);
            trace("--------------------------");
            var mybuf = Bytes.alloc(100);
            ar.readBuffer(mybuf,0,100,function(nr) {
                trace("I read :"+nr);
                trace(mybuf.toString());
              });
          });
        recur(ar,myBuff);
      });
    #else
    MyFile.asyncReader(Stream,file,100,function(ar) {
        ar.readBytesInput(function(nr,bytes) {
            trace(bytes.readAll());
            //trace("bytes :"+bytes.length+" -> "+bytes.toString());
          })
          .onEof(function() {
              trace("OK GOT END");
              ar.close();
            });
      });
    #end

    /*
      js.node.File.readStream(file,100)
    */

    /*
    file.stream().toBuffer(Bytes.alloc(50),0,50,function(bytes,nr) {
        trace("Read:"+nr+", "+bytes.toString());
      }).onSuccess(function() {
          trace("nice one I've finished");
        }).onFailure(function(err) {

          });
   
    file.read(function(input) trace(input.readAll()));
    file.copy("NEWREADME").onSuccess(function() trace("finished copying"));
    file.getBytes(function(bytes) {

      });

    file.getContent(function(content) {
        
      });
    
    */
    
  }

  static function recur(pr:AsyncReader,myBuff:BytesBuffer) {
    pr.readBytes(function(bytes) {
        trace(pr.tell()+":"+bytes.length);
        myBuff.addBytes(bytes,0,bytes.length);
        recur(pr,myBuff);
      });
    
  }
  
}
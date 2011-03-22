
import js.Node;

class Ex1 {
   public static function main() {
      trace(Node.process.memoryUsage());
      trace(Node.process.memoryUsage().heapTotal);

      var dns = Node.dns();
      dns.resolve("ipowerhouse.com","A",function(err,ips:Array<Dynamic>) {
          trace(ips);
          });
   }

}

// Compile with
// haxe -D nodejs -cp . -js ex1.js -main Ex1

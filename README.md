```
Usage: tls_decrypt --client_random <32 bytes in hex>
                   --server_random <32 bytes in hex>
                   --master <48 bytes in hex>
                   [
                     --counter <packet sequence number for AEAD associated data>
                     --to_server or --to_client
                     --input <file with TLS packet to decrypt>
                   ]
Only AES128 GCM Ciphersuite is supported.
Only 'Application Data' type TLS packets will be decrypted.If no input file given - only keys will be generated.
```

You can find example TLS HTTP session dump 'network-dump.pcap'. Session was created by the following bash commands
```
$ export SSLKEYLOGFILE=tls-keys
$ curl -v --http1.1 --tlsv1.2 --tls-max 1.2 --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://ya.ru
# other terminal
$ tcpdump -i eth0 -w network-dump.pcap host ya.ru
``` 

You can decrypt it using Wireshark, client random and master key in 'tls-keys' file. But also with 'tls_decrypt' tool.

Get session keys using 'tls_decrypt'. Extract server random using wireshark (it is not ecnrypted) and run tls_decrypt:
```
./tls_decrypt --client_random 62a36d3da1f8fdc272cd248ed71a7a686ee666617170c4ff51c0e6ea54dcd556 --server_random 7d60c425c1c768a5cc63d2c617c3d09c4f7efc654af6ab96444f574e47524401 --master 51f8471166c833a36aad63c05f8545238ae5262bfb757f2a668f6eed93e521e51b1373cdebdc14a0bc1e7008ba3cc3f2
```

Expected output:
```
client write key   : e5c43329b23196f746bc7d7172387f2b
server write key   : 26e896667665707dedbc177735eb686a
client implicit iv : 352cfe07
server implicit iv : b27e13d3
```

encrypted-c2s-http-get.bin - dump of encrypted HTTP GET TLS packet from pcap file.  
encrypted-s2c-http-ok.bin - dump of ecnrypted HTTP response TLS packet from pcap file.

Decrypt http get dump by running:
```
$ ./tls_decrypt --client_random 62a36d3da1f8fdc272cd248ed71a7a686ee666617170c4ff51c0e6ea54dcd556 --server_random 7d60c425c1c768a5cc63d2c617c3d09c4f7efc654af6ab96444f574e47524401 --master 51f8471166c833a36aad63c05f8545238ae5262bfb757f2a668f6eed93e521e51b1373cdebdc14a0bc1e7008ba3cc3f2 --input ../encrypted-c2s-http-get.bin --counter 1 --to_server
```

Expected output:
```
client write key   : e5c43329b23196f746bc7d7172387f2b
server write key   : 26e896667665707dedbc177735eb686a
client implicit iv : 352cfe07
server implicit iv : b27e13d3

decrypted input:
0000 - 47 45 54 20 2f 20 48 54-54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
0010 - 48 6f 73 74 3a 20 79 61-2e 72 75 0d 0a 55 73 65   Host: ya.ru..Use
0020 - 72 2d 41 67 65 6e 74 3a-20 63 75 72 6c 2f 37 2e   r-Agent: curl/7.
0030 - 36 39 2e 31 0d 0a 41 63-63 65 70 74 3a 20 2a 2f   69.1..Accept: */
0040 - 2a 0d 0a 0d 0a                                    *....
```

Decrypt http response dump by running:
```
$ ./tls_decrypt --client_random 62a36d3da1f8fdc272cd248ed71a7a686ee666617170c4ff51c0e6ea54dcd556 --server_random 7d60c425c1c768a5cc63d2c617c3d09c4f7efc654af6ab96444f574e47524401 --master 51f8471166c833a36aad63c05f8545238ae5262bfb757f2a668f6eed93e521e51b1373cdebdc14a0bc1e7008ba3cc3f2 --input ../encrypted-s2c-http-ok.bin --counter 1 --to_client
```

Expected output:
```
client write key   : e5c43329b23196f746bc7d7172387f2b
server write key   : 26e896667665707dedbc177735eb686a
client implicit iv : 352cfe07
server implicit iv : b27e13d3

decrypted input:
0000 - 48 54 54 50 2f 31 2e 31-20 32 30 30 20 4f 6b 0d   HTTP/1.1 200 Ok.
0010 - 0a 41 63 63 65 70 74 2d-43 48 3a 20 56 69 65 77   .Accept-CH: View
0020 - 70 6f 72 74 2d 57 69 64-74 68 2c 20 44 50 52 2c   port-Width, DPR,
0030 - 20 44 65 76 69 63 65 2d-4d 65 6d 6f 72 79 2c 20    Device-Memory, 
0040 - 52 54 54 2c 20 44 6f 77-6e 6c 69 6e 6b 2c 20 45   RTT, Downlink, E
0050 - 43 54 0d 0a 41 63 63 65-70 74 2d 43 48 2d 4c 69   CT..Accept-CH-Li
0060 - 66 65 74 69 6d 65 3a 20-33 31 35 33 36 30 30 30   fetime: 31536000
0070 - 0d 0a 43 61 63 68 65 2d-43 6f 6e 74 72 6f 6c 3a   ..Cache-Control:
0080 - 20 6e 6f 2d 63 61 63 68-65 2c 6e 6f 2d 73 74 6f    no-cache,no-sto
0090 - 72 65 2c 6d 61 78 2d 61-67 65 3d 30 2c 6d 75 73   re,max-age=0,mus
00a0 - 74 2d 72 65 76 61 6c 69-64 61 74 65 0d 0a 43 6f   t-revalidate..Co
00b0 - 6e 74 65 6e 74 2d 4c 65-6e 67 74 68 3a 20 36 30   ntent-Length: 60
00c0 - 35 32 35 0d 0a 43 6f 6e-74 65 6e 74 2d 53 65 63   525..Content-Sec
00d0 - 75 72 69 74 79 2d 50 6f-6c 69 63 79 3a 20 63 6f   urity-Policy: co
00e0 - 6e 6e 65 63 74 2d 73 72-63 20 68 74 74 70 73 3a   nnect-src https:
00f0 - 2f 2f 2a 2e 6d 63 2e 79-61 6e 64 65 78 2e 72 75   //*.mc.yandex.ru
0100 - 20 68 74 74 70 73 3a 2f-2f 61 64 73 74 61 74 2e    https://adstat.
0110 - 79 61 6e 64 65 78 2e 72-75 20 68 74 74 70 73 3a   yandex.ru https:
0120 - 2f 2f 6d 63 2e 61 64 6d-65 74 72 69 63 61 2e 72   //mc.admetrica.r
0130 - 75 20 68 74 74 70 73 3a-2f 2f 6d 63 2e 79 61 6e   u https://mc.yan
0140 - 64 65 78 2e 72 75 20 68-74 74 70 73 3a 2f 2f 79   dex.ru https://y
0150 - 61 6e 64 65 78 2e 72 75-3b 64 65 66 61 75 6c 74   andex.ru;default
<skipped for bravity>
```

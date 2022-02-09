# Secret File Server (Linux)

Compile:
Server compilation:
g++ -o server server.cpp chilkat/lib/libchilkat-9.5.0.so -lresolv -lpthread cryptopp/libcryptopp.a

Client compilation:
g++ -o client client.cpp chilkat/lib/libchilkat-9.5.0.so -lresolv -lpthread cryptopp/libcryptopp.a


Execute:
Server execution:
./server [port number]

Client execution:
./client [server ip] [port number]

Requirement:
chilkat
cryptopp
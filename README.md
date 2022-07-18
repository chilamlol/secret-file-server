# Secret File Server (Linux)

This is a secret file server with TEA encryption built in C++

## Requirement
*  chilkat
*  cryptopp

## Run with linux terminal (g++)

### Compile:

#### Server
```
g++ -o server server.cpp chilkat/lib/libchilkat-9.5.0.so -lresolv -lpthread cryptopp/libcryptopp.a
```

#### Client
```
g++ -o client client.cpp chilkat/lib/libchilkat-9.5.0.so -lresolv -lpthread cryptopp/libcryptopp.a
```

### Run the program:

#### Server
```
./server [port number]
```

#### Client
```
./client [server ip] [port number]
```

#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <vector>
#include <algorithm>
#include <ctime>
#include <sys/stat.h>



//TEA Encryption
#include "./cryptopp/modes.h"
#include "./cryptopp/osrng.h"
#include "./cryptopp/filters.h"
#include "./cryptopp/base64.h" //Base64Encoder
#include "./cryptopp/secblock.h"
#include "./cryptopp/cryptlib.h"
#include "./cryptopp/hex.h"
#include "./cryptopp/tea.h"
#include "./cryptopp/files.h"

//FTP server
#include "./chilkat/include/CkFtp2.h"

typedef unsigned char BYTE; //Declaring BYTE data type
using namespace std;

string strTeaKey1 = "27b7c1ec9608d21728f0081bbad0a606"; // TEA key 1 generated using generator
string strIv = "750a3205eac73b5c"; //Hard coded IV in string

CkFtp2 ftp;
//Using TEA to decrypt the entire file
void teaDecryptFile()
{
	string temp, temp1;

	try
	{
	    CryptoPP::StringSource ivDec(strIv, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(temp)));
	
	    CryptoPP::StringSource keyDec(strTeaKey1, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(temp1)));

	    CryptoPP::SecByteBlock iv((const BYTE*)temp.data(), temp.size());
	    CryptoPP::SecByteBlock key((const BYTE*)temp1.data(), temp1.size());
		
	    CryptoPP::OFB_Mode< CryptoPP::TEA >::Decryption d;
	    d.SetKeyWithIV( key, key.size(), iv );

	    CryptoPP::FileSource ss("euserlist.txt", true, 
				new CryptoPP::HexDecoder (
		                	new CryptoPP::StreamTransformationFilter( d,
		                    		new CryptoPP::FileSink( "duserlist.txt" )
					)// HexDecoder
		                ) // StreamTransformationFilter
		            ); // FileSource
	}
	catch( const CryptoPP::Exception& e )
	{
	    cerr << e.what() << endl;
	    exit(1);
	}
}


//Using TEA to encrypt the entire file
void teaEncryptFile()
{
	string tempIv, tempKey;

	try
	{
	    CryptoPP::StringSource ivDec(strIv, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(tempIv)));
	
	    CryptoPP::StringSource keyDec(strTeaKey1, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(tempKey)));

	    CryptoPP::SecByteBlock iv((const BYTE*)tempIv.data(), tempIv.size());
	    CryptoPP::SecByteBlock key((const BYTE*)tempKey.data(), tempKey.size());
		
	    CryptoPP::OFB_Mode< CryptoPP::TEA >::Encryption e;
	    e.SetKeyWithIV( key, key.size(), iv );

	    CryptoPP::FileSource ss("duserlist.txt", true, 
		                new CryptoPP::StreamTransformationFilter( e, 
					new CryptoPP::HexEncoder(
		                    		new CryptoPP::FileSink( "euserlist.txt" )
					) // HexEncoder
		                ) // StreamTransformationFilter
		            ); // FileSource
	}
	catch( const CryptoPP::Exception& e )
	{
	    cerr << e.what() << endl;
	    exit(1);
	}

	//Empty the decrypted userlist text file
	ofstream ofs;
	ofs.open("duserlist.txt", ofstream::trunc);
	ofs.close();
}


//Tea encrypt message
string teaEncryptMsg(string msg)
{

	string tempIv, tempKey, cipher;
	try
	{
	    CryptoPP::StringSource ivDec(strIv, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(tempIv)));
	
	    CryptoPP::StringSource keyDec(strTeaKey1, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(tempKey)));

	    CryptoPP::SecByteBlock iv((const BYTE*)tempIv.data(), tempIv.size());
	    CryptoPP::SecByteBlock key((const BYTE*)tempKey.data(), tempKey.size());
		
	    CryptoPP::OFB_Mode< CryptoPP::TEA >::Encryption e;
	    e.SetKeyWithIV( key, key.size(), iv );
	    CryptoPP::StringSource ss(msg.c_str(), true, 
		                new CryptoPP::StreamTransformationFilter( e, 
					new CryptoPP::HexEncoder(
		                    		new CryptoPP::StringSink( cipher )
					) // HexEncoder
		                ) // StreamTransformationFilter
		            ); // FileSource
	}
	catch( const CryptoPP::Exception& e )
	{
	    cerr << e.what() << endl;
	    exit(1);
	}

	return cipher;

}


//Check for username duplicate
int checkIfUsernameExist(string username)
{ 
	string line;
	vector<string> userlist;
	
	ifstream infile("duserlist.txt");
	while(getline(infile, line, ':'))
	{
		userlist.push_back(line);
	}

	infile.close(); 

    	// Iterator used to store the position 
	// of searched element
	vector<string>::iterator it;

    	it = find (userlist.begin(), userlist.end(), username);
	if (it != userlist.end())
	{
		return it - userlist.begin();
	}
	else
		return -1;
}


string extractSpecificElement(int position, string type)
{
	string line;
	vector<string> userlist;
	
	ifstream infile("duserlist.txt");
	while(getline(infile, line, ':'))
	{
		userlist.push_back(line);
	}

	infile.close(); 
	
	if (type == "password")
		position += 1;
	if (type == "key")
		position += 2;
	if (type == "date")
		position += 3;

    	return userlist.at(position);
}


void modifySpecificElement(int position, string newPassword)
{
	string line;
	vector<string> userlist;
	
	ifstream infile("duserlist.txt");
	while(getline(infile, line, ':'))
	{
		userlist.push_back(line);
	}

	infile.close(); 
	
	//Overwrite the element
    	userlist.at(position + 1) = newPassword;

	//Overwriting the whole file with the vector
	ofstream output_file("duserlist.txt");
	ostream_iterator<string> output_iterator(output_file, ":");
	copy(userlist.begin(), userlist.end(), output_iterator);
}


//Generate TEA key(2)
string genTeaKey()
{
	string strKey;	

	CryptoPP::AutoSeededRandomPool prng;

	CryptoPP::SecByteBlock key(CryptoPP::TEA::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	CryptoPP::StringSource(key, key.size(), true,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(strKey)
		)
	); // StringSource

	return strKey;
}


//Register user if username not already exist
void registration(string username,string passwordHash)
{
	string sentence, key, now;
	
	//Recast the time_t to long int then convert it to string
	long int t = static_cast<long int> (time(NULL));
	now = to_string(t);
	
	key = genTeaKey(); //Generate TEA Key(2)

	//Username:Password:TEAkey2:TimeCreated
	sentence = username + ":" + passwordHash + ":" + key + ":" + now + ":";

	ofstream outfile;
	
	outfile.open("duserlist.txt", ios_base::app); //append to file
	outfile << sentence;
	outfile.close();
}


bool checkftp(string hostname, string username, string password)
    {
    // This example requires the Chilkat API to have been previously unlocked.
    // See Global Unlock Sample for sample code.

    ftp.put_Hostname(hostname.c_str());
    ftp.put_Username(username.c_str());
    ftp.put_Password(password.c_str());

    // Connect and login to the FTP server.
    bool success = ftp.Connect();
    if (success != true)
	cout << "\nError to setup the FTP server." << endl;
    
    //return connection status
    return success;
}


//Server side
int main(int argc, char *argv[])
{
    //for the server, we only need to specify a port number
    if(argc != 2)
    {
        cerr << "Usage: port" << endl;
        exit(0);
    }
    //grab the port number
    int port = atoi(argv[1]);
    //buffer to send and receive messages with
    char msg[3000];
     
    //setup a socket and connection tools
    sockaddr_in servAddr;
    bzero((char*)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);
 
    //open stream oriented socket with internet address
    //also keep track of the socket descriptor
    int serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSd < 0)
    {
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }
    //bind the socket to its local address
    int bindStatus = bind(serverSd, (struct sockaddr*) &servAddr, 
        sizeof(servAddr));
    if(bindStatus < 0)
    {
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    cout << "Waiting for a client to connect..." << endl;
    //listen for up to 5 requests at a time
    listen(serverSd, 5);
    //receive a request from client using accept
    //we need a new address to connect with the client
    sockaddr_in newSockAddr;
    socklen_t newSockAddrSize = sizeof(newSockAddr);
    //accept, create a new socket descriptor to 
    //handle the new connection with client
    int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
    if(newSd < 0)
    {
        cerr << "Error accepting request from client!" << endl;
        exit(1);
    }
    cout << "Connected with client!" << endl;
    //lets keep track of the session time
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);
    //also keep track of the amount of data sent as well
    int bytesRead, bytesWritten = 0;
    string sesKey;
    while(1)
    {
        //receive a message from the client (listen)
        cout << "\nAwaiting client response..." << endl;
        memset(&msg, 0, sizeof(msg));//clear the buffer
        bytesRead += recv(newSd, (char*)&msg, sizeof(msg), 0);
        if(!strcmp(msg, "exit"))
        {
            cout << "Client has quit the session" << endl;
            break;
        }
        
        string sentence, mode, username, password, rsp;

	sentence = msg;

	mode = sentence.substr(0, sentence.find("||"));
	sentence.erase(0, sentence.find("||") + 2);

	username = sentence.substr(0, sentence.find("||"));
	sentence.erase(0, sentence.find("||") + 2);

	password = sentence.substr(0, sentence.find("||"));

	cout << "Client: " << endl;
	cout << "Mode: " << mode << endl;
	cout << "Username:" << username << endl;
	cout << "Password:" << password << endl;

	
	ifstream file("euserlist.txt"); 

	bool isEmpty = file.peek() == EOF; //pointer to end of file if 0 then empty

	if(mode == "r")
	{
		if(isEmpty) // If file is empty then striaght register	
		{
			registration(username, password); 
			rsp = "Registration completed."; 
			teaEncryptFile();
		} 
		if(!isEmpty) // If file not empty then username duplication check
		{
				
			teaDecryptFile(); //Decrypt the file to perfrom registration process
			if(checkIfUsernameExist(username) == -1)
			{ 
				registration(username, password); 
				rsp = "Registration completed."; 
			}
			else 
			{
				rsp = "Username taken !!!";
			}	
			
			teaEncryptFile(); //Encrypt the file after the registration process completed.
		}
	}
	else if(mode == "l")
	{
		if(isEmpty)
			rsp = "Username not found.";
		if(!isEmpty)
		{
			teaDecryptFile();
			int pos = checkIfUsernameExist(username);
			if(pos == -1)
			{
				rsp = "Username not found.";
			}
			else 
			{
				string storedPassword = extractSpecificElement(pos, "password");
				
				if (storedPassword != password)
					rsp = "Incorrect password !!!";
				else
				{	
					//
					string accountCreationTime = extractSpecificElement(pos, "date");
					long int act = stoi(accountCreationTime);

					long int now = static_cast<long int> (time(NULL));
					if( (now - act) < 86400)
						rsp = "Sorry, your account haven't reach 24 hours.";
					else
					{
						cout << "\nThe user account passed 24 hours, setup FTP server.";
						//create ftpserver
						string hostname, ftpusername, ftppassword;
						do
						{
							cout << "\nHostname(IP): ";
							cin >> hostname;
							cout << "Username: ";
							cin >> ftpusername;
							cout << "Password: ";
							cin >> ftppassword;

						}while(checkftp(hostname, ftpusername, ftppassword) != true);

						string combined, tea2, dir;
						cout << "\nFTP server created" << endl;
						struct stat sb;

						do{
							cout << "\nDirectory selected: ";
							cin >> dir;
							if (stat(dir.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode))
								break;
							else{
							 cout << "\nInvalid directory." << endl;}
						}while(true);


						tea2 = extractSpecificElement(pos, "key");
						//send FTP info

						combined = hostname + "||" + ftpusername + "||" + ftppassword + "||" + tea2 + "||" + dir;
						rsp = "i||" + teaEncryptMsg(combined);
						
						memset(&msg, 0, sizeof(msg)); //clear the buffer
						strcpy(msg, rsp.c_str());
						bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
						
						cout << "Directory changed!" << endl;
						cout << "\nSuccessfully sent FTP server details!" << endl;

						cout << "\nAwaiting client response..." << endl;
						memset(&msg, 0, sizeof(msg));//clear the buffer
						bytesRead += recv(newSd, (char*)&msg, sizeof(msg), 0);
						if(!strcmp(msg, "exit"))
							{
							cout << "\nClient has quit the session" << endl << endl;
            						ftp.Disconnect(); 
							break;
						} //exit the server
							
					}
				}
			}
			
			teaEncryptFile();
		}
			
	}
	else if(mode == "c")
	{
		if(isEmpty)
			rsp = "Username not found.";
		if(!isEmpty)
		{
			teaDecryptFile();
			int pos = checkIfUsernameExist(username);
			if(pos == -1)
			{
				rsp = "Username not found.";
			}
			else 
			{
				string storedPassword = extractSpecificElement(pos, "password");
				
				if (storedPassword != password)
					rsp = "Incorrect password !!!";
				else
				{	
					rsp = "Verified";
					memset(&msg, 0, sizeof(msg)); //clear the buffer
        				strcpy(msg, rsp.c_str());
					bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);

					cout << "\nAwaiting client response..." << endl;
					memset(&msg, 0, sizeof(msg));//clear the buffer
					bytesRead += recv(newSd, (char*)&msg, sizeof(msg), 0);
					
					cout << "Client: " << endl;
					cout << "New Password: " << msg << endl;
					string newPassword = msg;
					modifySpecificElement(pos, newPassword);
					rsp = "Password has changed.";
				}
			}
			
			teaEncryptFile();
		}
	}

	
        memset(&msg, 0, sizeof(msg)); //clear the buffer
        strcpy(msg, rsp.c_str());
        if(rsp == "exit")
        {
            //send to the client that server has closed the connection
            send(newSd, (char*)&msg, strlen(msg), 0);
            break;
        }
        //send the message to client
        bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
    }
    //we need to close the socket descriptors after we're all done
    gettimeofday(&end1, NULL);
    close(newSd);
    close(serverSd);
    cout << "********Session********" << endl;
    cout << "Bytes written: " << bytesWritten << " Bytes read: " << bytesRead << endl;
    cout << "Elapsed time: " << (end1.tv_sec - start1.tv_sec) 
        << " secs" << endl;
    cout << "Connection closed..." << endl;
    return 0;   
    }

//g++ -o server server.cpp chilkat/lib/libchilkat-9.5.0.so -lresolv -lpthread cryptopp/libcryptopp.a


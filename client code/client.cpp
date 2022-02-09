#include <iostream>
#include <string>
#include<stdlib.h> // to use system() for writing terminal command line
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

//SHA1 hashing
#include "./cryptopp/sha.h" 
#include "./cryptopp/hex.h" //HexEncoder()

//TEA encryption library
#include "./cryptopp/tea.h"
#include "./cryptopp/filters.h"
#include "./cryptopp/modes.h"
#include "./cryptopp/secblock.h"
#include "./cryptopp/base64.h"
#include "./cryptopp/osrng.h" //AutoSeededRandomPool
#include "./cryptopp/files.h" //file sink

//FTP server
#include "./chilkat/include/CkFtp2.h"


typedef unsigned char BYTE; //Declaring BYTE data type
using namespace std;

string strTeaKey1 = "27b7c1ec9608d21728f0081bbad0a606"; // TEA key 1 generated using generator
string strIv = "750a3205eac73b5c"; //Hard coded IV in string

CkFtp2 ftp;

bool checkftp(string hostname, string username, string password, string dir)
    {
    // This example requires the Chilkat API to have been previously unlocked.
    // See Global Unlock Sample for sample code.

    ftp.put_Hostname(hostname.c_str());
    ftp.put_Username(username.c_str());
    ftp.put_Password(password.c_str());

    // Connect and login to the FTP server.
    bool success = ftp.Connect();
    
    if(success == true)
    {
    	success = ftp.ChangeRemoteDir(dir.c_str());
    }

    //return connection status
    return success;
}


bool ftpUpload(string local, string remote)
{
    // Upload a file.
    bool success = ftp.PutFile(local.c_str(), remote.c_str());
    
    return success;
}


bool ftpDownload(string remote, string local)
{
    // Download a file.
    bool success = ftp.GetFile(remote.c_str(), local.c_str());
    
    return success;
}


void ftpList(string dir)
{
	int n;
	
	ftp.ChangeRemoteDir(dir.c_str());
	n = ftp.GetDirCount();
	if (n <= 0) {
		cout << "\n0 file found." << endl;
	}
	else{
		cout << endl;
		for (int i = 0; i <= n - 1; i++) {
			 cout << i+1 << ". " << ftp.getFilename(i) << " | " << ftp.GetSize(i) << "bytes |"<< endl;
		}
	}
}

//Using TEA to encrypt the entire file for upload
void teaEncryptFile(string strTeaKey3, string localFileName, string remoteFileName)
{
	string tempIv, tempKey, tempName;
	
	tempName = "e" + localFileName;

	try
	{
	    CryptoPP::StringSource ivDec(strIv, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(tempIv)));
	
	    CryptoPP::StringSource keyDec(strTeaKey3, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(tempKey)));

	    CryptoPP::SecByteBlock iv((const BYTE*)tempIv.data(), tempIv.size());
	    CryptoPP::SecByteBlock key((const BYTE*)tempKey.data(), tempKey.size());
		
	    CryptoPP::OFB_Mode< CryptoPP::TEA >::Encryption e;
	    e.SetKeyWithIV( key, key.size(), iv );

	    CryptoPP::FileSource ss(localFileName.c_str(), true, 
		                new CryptoPP::StreamTransformationFilter( e, 
					new CryptoPP::HexEncoder(
		                    		new CryptoPP::FileSink( tempName.c_str() )
					) // HexEncoder
		                ) // StreamTransformationFilter
		            ); // FileSource
	}
	catch( const CryptoPP::Exception& e )
	{
	    cerr << e.what() << endl;
	    exit(1);
	}
	
	if(ftpUpload(tempName, remoteFileName) == true)
		cout << "\nFile successfully uploaded" << endl;
	else {cout << ftp.lastErrorText() << endl;}

	//Remove the encrypt file after upload
	remove(tempName.c_str());
}


//Using TEA to decrypt the entire file for download
void teaDecryptFile(string strTeaKey3, string localFileName, string remoteFileName)
{
	string tempIv, tempKey, tempName;
	
	tempName = "e" + remoteFileName;
	
	if(ftpDownload(remoteFileName, tempName) == true)
		cout << "\nFile successfully downloaded" << endl;
	else {cout << "\nFile failed to downloaded." << endl; return;}

	try
	{
	    CryptoPP::StringSource ivDec(strIv, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(tempIv)));
	
	    CryptoPP::StringSource keyDec(strTeaKey3, true, 
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(tempKey)));

	    CryptoPP::SecByteBlock iv((const BYTE*)tempIv.data(), tempIv.size());
	    CryptoPP::SecByteBlock key((const BYTE*)tempKey.data(), tempKey.size());
		
	    CryptoPP::OFB_Mode< CryptoPP::TEA >::Decryption d;
	    d.SetKeyWithIV( key, key.size(), iv );

	    CryptoPP::FileSource ss(tempName.c_str(), true, 
	    			new CryptoPP::HexDecoder(
		                	new CryptoPP::StreamTransformationFilter( d, 
		                    		new CryptoPP::FileSink( localFileName.c_str() )
					) // HexEncoder
		                ) // StreamTransformationFilter
		            ); // FileSource
	}
	catch( const CryptoPP::Exception& e )
	{
	    cerr << e.what() << endl;
	    exit(1);
	}
	
	//Remove the encrypt file after download
	remove(tempName.c_str());
}


//SHA1 hashing
string sha1Hash(string message)
{
    string hashedPassword;

    CryptoPP::SHA1 sha1;	

    CryptoPP::StringSource fs(message, true /* PumpAll */,
        new CryptoPP::HashFilter(sha1,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hashedPassword))));
                
    return hashedPassword;
}

string teaDecryptCipher(string cipher)
{

	string tempIv, tempKey, msg;
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
		
	    CryptoPP::OFB_Mode< CryptoPP::TEA >::Decryption d;
	    d.SetKeyWithIV( key, key.size(), iv );
	    CryptoPP::StringSource ss(cipher.c_str(), true, 
	    			new CryptoPP::HexDecoder(
		                	new CryptoPP::StreamTransformationFilter( d, 
		                    		new CryptoPP::StringSink( msg )
					) // HexEncoder
		                ) // StreamTransformationFilter
		            ); // FileSource
	}
	catch( const CryptoPP::Exception& e )
	{
	    cerr << e.what() << endl;
	    exit(1);
	}

	return msg;

}


//Client side
int main(int argc, char *argv[])
{
    //we need 2 things: ip address and port number, in that order
    if(argc != 3)
    {
        cerr << "Usage: ip_address port" << endl; exit(0); 
    } //grab the IP address and port number 
    char *serverIp = argv[1]; int port = atoi(argv[2]); 
    //create a message buffer 
    char msg[3000]; 
    //setup a socket and connection tools 
    struct hostent* host = gethostbyname(serverIp); 
    sockaddr_in sendSockAddr;   
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); 
    sendSockAddr.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = 
        inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);
    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
    //try to connect...
    int status = connect(clientSd,
                         (sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
    if(status < 0)
    {
        cout<<"Error connecting to socket!"<<endl;
    }
    cout << "\nClient connected to the server!" << endl;
    int bytesRead, bytesWritten = 0;
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);

    string input; //user input

    while(1)
    {
	while(input != "login" || input != "exit" || input != "register" || input != "change")
	{
		cout << "\n| login | register | change | exit |" << endl;
		cout << ">";
		cin >> input;
		if(input == "exit")
			break;
		else if(input == "login")
		{
			string username, password;
			cout << "\nusername: ";
			cin >> username;
			
			cout << "password: ";
			cin >> password;
			
			password = sha1Hash(password);
			
			input = "l||" + username + "||" + password;
			
			memset(&msg, 0, sizeof(msg));//clear the buffer
       			strcpy(msg, input.c_str());
       			bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
       			
			cout << "\nAwaiting server response..." << endl;
			memset(&msg, 0, sizeof(msg));//clear the buffer
			bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
			
			string strMsg = msg;
			
			if(strMsg.substr(0,3) != "i||")
			{
				cout << "Server: " << msg << endl;
			}
			else
			{
			string sentence, hostname, ftpusername, ftppassword, teaKey, dir;
				sentence = msg;
				
				//remove i||
				sentence.erase(0, sentence.find("||") + 2);
				cout << "\nCipher: "<< sentence << endl;
				sentence = teaDecryptCipher(sentence);
				cout << "\nCipher succesfully decrypted!" << endl;

				hostname = sentence.substr(0, sentence.find("||"));
				sentence.erase(0, sentence.find("||") + 2);

				ftpusername = sentence.substr(0, sentence.find("||"));
				sentence.erase(0, sentence.find("||") + 2);
				
				ftppassword = sentence.substr(0, sentence.find("||"));
				sentence.erase(0, sentence.find("||") + 2);
				
				teaKey = sentence.substr(0, sentence.find("||"));
				sentence.erase(0, sentence.find("||") + 2);
				
				dir = sentence.substr(0, sentence.find("||"));
				
				reverse(teaKey.begin(),teaKey.end());
				
				if(checkftp(hostname, ftpusername, ftppassword, dir) == true)
				{
					cout << "\nConnected to FTP server." << endl;
					string option;
					cout << "1 - Upload a file" << endl;
					cout << "2 - List all the files" << endl;
					cout << "3 - Download a file" << endl;
					cout << "4 - Quit" << endl;
					while(option != "4")
					{
						cout << "\n>";
						cin >> option;
						if (option == "1")
						{
							string localFileName, remoteFileName;
							cout << "Please enter the local file name: ";
							cin >> localFileName;
							cout << "Please enter the remote file name: ";
							cin >> remoteFileName;
							
							teaEncryptFile(teaKey, localFileName, remoteFileName);
						}
						else if(option == "2")
						{
							ftpList(dir);
						}
						else if(option == "3")
						{
							string localFileName, remoteFileName;
							cout << "Please enter the remote file name: ";
							cin >> remoteFileName;
							cout << "Please enter the local file name: ";
							cin >> localFileName;
							
							teaDecryptFile(teaKey, localFileName, remoteFileName);	
						}
						else if(option == "4")
						{
							input = "exit";
							ftp.Disconnect();
							break;
						}
						else { cout << "\nInvalid option !!! Please try again." << endl;}
					}
			
				}
				else { cout << "\nError occur" << endl;}
			}
		}
		else if(input == "register")
		{
			string username, password;
			cout << "\nPlease enter your username: ";
			cin >> username;
			
			cout << "Please enter your password (8-12 characters): ";
			cin >> password;
			
			//Error handling, reprompt user to enter the password if not 8 - 12 character
			while(password.length() < 8 || password.length() > 12)
			{
				cout << "\nError >> Password should be between 8 - 12 characters." << endl;
				cin.clear();
				cin.ignore(256, '\n');
				cout << "Please enter your password (8-12 characters): ";
				cin >> password;
			}
			
			password = sha1Hash(password);
			
			input = "r||" + username + "||" + password;
			break;
		}
		else if(input == "change")
		{
			string username, password, newPassword;

			cout << "\nusername: ";
			cin >> username;
			
			cout << "password: ";
			cin >> password;
			
			password = sha1Hash(password);
			
			input = "c||" + username + "||" + password;
			
			memset(&msg, 0, sizeof(msg));//clear the buffer
       			strcpy(msg, input.c_str());
       			bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
			cout << "\nAwaiting server response..." << endl;
			memset(&msg, 0, sizeof(msg));//clear the buffer
			bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
			cout << "Server: " << msg << endl;
			string ans = msg;
			if (ans == "Verified")
			{
			
				cout << "Please enter your new password (8-12 characters): ";
				cin >> newPassword;
				//Error handling, reprompt user to enter the password if not 8 - 12 character
				while(newPassword.length() < 8 || newPassword.length() > 12)
				{
					cout << "\nError >> New password should be between 8 - 12 characters." << endl;
					cin.clear();
					cin.ignore(256, '\n');
					cout << "Please enter your new password (8-12 characters): ";
					cin >> newPassword;
				}
				newPassword = sha1Hash(newPassword);
				
				input = newPassword;
				break;
			} 
			
		}
		else {
			cout << "Error >> Please enter valid input." << endl;
		}
	}
        memset(&msg, 0, sizeof(msg));//clear the buffer
        strcpy(msg, input.c_str());
        if(input == "exit")
        {
            send(clientSd, (char*)&msg, strlen(msg), 0);
            break;
        }
        bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
        cout << "\nAwaiting server response..." << endl;
        memset(&msg, 0, sizeof(msg));//clear the buffer
        bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
        if(!strcmp(msg, "exit"))
        {
            cout << "Server has quit the session" << endl;
            break;
        }
        cout << "Server: " << msg << endl;
    }
    gettimeofday(&end1, NULL);
    close(clientSd);
    cout << "\n\n********Session********" << endl;
    cout << "Bytes written: " << bytesWritten << 
    " Bytes read: " << bytesRead << endl;
    cout << "Elapsed time: " << (end1.tv_sec- start1.tv_sec) 
      << " secs" << endl;
    cout << "Connection closed" << endl;
    return 0;   
}

//g++ -o client client.cpp chilkat/lib/libchilkat-9.5.0.so -lresolv -lpthread cryptopp/libcryptopp.a

#include "Utility.h"
#include "Log.h"
#include "BitStream.h"
#include "StringCompressor.h"
#include "RakPeerInterface.h"
#include "RakNetworkFactory.h"
#include "RakSleep.h"
#include "MessageIdentifiers.h"
#include "NatTypeDetectionServer.h"
#include "SocketLayer.h"
#include "PacketLogger.h"
#include <stdarg.h>

#ifdef WIN32
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <signal.h>
#include <winsock2.h>
#else
#include <string>
#include <iostream>
#include <signal.h>
#endif
#include <map>
#include <stdlib.h>

RakPeerInterface *peer;
RakNet::NatTypeDetectionServer *natTypeDetection;
bool quit;

char* logfile = "conntester.log";
const int fileBufSize = 1024;
char pidFile[fileBufSize];

void shutdown(int sig)
{
	quit = true;
}

bool validate_ip(char* ip)
{
	bool valid = true;
	int i = 0;
	int dotCount = 0;
	while (ip[i] != 0)
	{
		if (ip[i++] == '.')
			dotCount++;
	}
	if (dotCount != 3)
		valid = false;
	
#ifdef WIN32
	unsigned long ulAddr = INADDR_NONE;
	ulAddr = inet_addr(ip);
    if (valid && ulAddr != INADDR_NONE)
		return true;
#else
	struct in_addr ia;
	if(valid && inet_aton(ip,&ia) == 1)
		return true;
#endif
	printf("IP address '%s' is invalid\n", ip);
	return false;
}

void cleanup()
{
	if (pidFile)
	{
		if (remove(pidFile) != 0)
			fprintf(stderr, "Failed to remove PID file at %s\n", pidFile);
	}
	peer->Shutdown(100,0);
	peer->DetachPlugin(natTypeDetection);
	delete natTypeDetection;
	natTypeDetection=NULL;
	RakNetworkFactory::DestroyRakPeerInterface(peer);
	Log::print_log("Quitting\n");
}

void usage()
{
	printf("\nAccepted parameters are:\n\t"
		   "-p\tListen port (1-65535)\n\t"
		   "-d\tDaemon mode, run in the background\n\t"
		   "-l\tUse given log file\n\t"
		   "-e\tDebug level (0=OnlyErrors, 1=Warnings, 2=Informational(default), 2=FullDebug)\n\t"
		   "-c\tConnection count\n\t"
		   "-h\tBind to listen address\n\t"
		   "-b\tBind to three external test addresses\n\n"
		   "A total of 4 public IP addresses is needed for the connection tester to work. "
		   "Specify the main listen address and the three test addresses with the -h, and -b parameters, "
		   "If they are not specified they will be autodetected (first one detected will be the listen address.\n\n"
		   "If any parameter is omitted the default value is used.\n");
}

int main(int argc, char *argv[])
{ 
	// Default settings
	time_t reconnectTime = 0;
	quit = false;
	int connectionCount = 1000;
	char *bindToIP1 = NULL;
	char *bindToIP2 = NULL;
	char *bindToIP3 = NULL;
	char *bindToIP4 = NULL;
	bool enablePacketLogger = false;
	PacketLogger packetLogger;
	
	int listenPort = 10737;
	bool useLogFile = false;
	bool daemonMode = false;

	// Setup phase
#ifndef WIN32
	setlinebuf(stdout);
#endif
	std::map<SystemAddress, SystemAddress> addresses;
	peer = RakNetworkFactory::GetRakPeerInterface();
	natTypeDetection = new RakNet::NatTypeDetectionServer;
	
	// Process command line arguments
	for (int i = 1; i < argc; i++)
	{
		if (strlen(argv[i]) == 2 && argc>=i+1)
		{
			switch (argv[i][1]) 
			{
				case 'd':
				{
					daemonMode = true;
					break;
				}					
				case 'p':
				{
					listenPort = atoi(argv[i+1]);
					i++;
					if (listenPort < 1 || listenPort > 65535)
					{
						fprintf(stderr, "Listen port is invalid, should be between 0 and 65535.\nIt is also advisable to use a number above well known ports (>1024).\n");
						return 1;
					}
					break;
				}
				case 'c':
				{
					connectionCount = atoi(argv[i+1]);
					i++;
					if (connectionCount < 0)
					{
						fprintf(stderr, "Connection count must be higher than 0.\n");
						return 1;
					}
					break;
				}
				case 'l':
				{				
					useLogFile = Log::EnableFileLogging(logfile);
					break;
				}
				case 'e':
				{
					Log::sDebugLevel = atoi(argv[i+1]);
					break;
				}
				case 'h':
				{
					bindToIP1 = argv[i+1];
					i++;
					if (!validate_ip(bindToIP1))
					{
						fprintf(stderr, "Invalid IP address given in -h parameter.\n");
						return 1;
					}
					break;
				}
				case 'b':
				{
					if (argc-i < 4)
					{
						fprintf(stderr, "Must provide three IP addresses with -b parameter.\n");
						return 1;
					}
					
					bindToIP2 = argv[i+1];
					bindToIP3 = argv[i+2];
					bindToIP4 = argv[i+3];
					if (!(validate_ip(bindToIP2) && validate_ip(bindToIP3) && validate_ip(bindToIP4)))
					{
						fprintf(stderr, "Invalid IP address with -b paramter. Must be in dot notation.\n");
						return 1;
					}
					i=i+3;
					break;
				}
				case 'n':
				{
					enablePacketLogger = true;
					i=i-1;
					break;
				}
				case '?':
					usage();
					return 0;
				default:
					printf("Parsing error, unknown parameter\n\n");
					usage();
					return 1;
			}
		}
		else
		{
			printf("Parsing error, incorrect parameters, choked while parsing %s\n\n", argv[i]);
			usage();
			return 1;
		}
	}
	
#ifndef WIN32
	if (daemonMode)
	{
		printf("Running in daemon mode, file logging enabled...\n");
		if (!useLogFile)
			useLogFile = Log::EnableFileLogging(logfile);
		// Don't change cwd to /
		// Beware that log/pid files are placed wherever this was launched from
		daemon(1, 0);
	}
	
	if (!WriteProcessID(argv[0], &pidFile[0], fileBufSize))
		perror("Warning, failed to write own PID value to PID file\n");
#endif
		
	Log::print_log("Connection Tester version 2.0.0\n");
	Log::print_log("Listen port set to %d\n", listenPort);
	Log::print_log("Max connection count set to %d\n", connectionCount);
	
	if (enablePacketLogger)
	{
		Log::print_log("Packet logger enabled\n");
	}
	
	char ipList[ MAXIMUM_NUMBER_OF_INTERNAL_IDS ][ 16 ];
	unsigned int binaryAddresses[MAXIMUM_NUMBER_OF_INTERNAL_IDS];
	SocketLayer::Instance()->GetMyIP( ipList, binaryAddresses );
	int ipCount = 0;
	int i = 0;
	while (i < MAXIMUM_NUMBER_OF_INTERNAL_IDS)
	{
		if (ipList[i][0] != 0 && strcmp(ipList[i], "127.0.0.1") != 0)
			ipCount++;
		i++;
	}
	if (ipCount < 4)
	{
		Log::error_log("Not enough IP addresses to bind to.\n");
		Log::error_log("To run the connection tester you need four public IP addresses available.\n\n");
		cleanup();
		return 1;
	}
	
	if (!bindToIP1)
		bindToIP1 = ipList[0];
	
	SocketDescriptor sd(listenPort,0);
	Log::print_log("Binding to %s\n", bindToIP1);
	strcpy(sd.hostAddress, bindToIP1); 
	if (!peer->Startup(connectionCount, 10, &sd, 1))
	{
		Log::print_log("Failed. Could not start peer interface\n");
		cleanup();
		return 1;
	}

	peer->SetMaximumIncomingConnections(connectionCount);
	peer->AttachPlugin(natTypeDetection);
	if (enablePacketLogger)
	{
		peer->AttachPlugin(&packetLogger);
		packetLogger.LogHeader();
	}
	
	if (!bindToIP2 && !bindToIP3 && !bindToIP4)
	{
		bindToIP2 = ipList[1];
		bindToIP3 = ipList[2];
		bindToIP4 = ipList[3];
	}
		
	Log::print_log("NAT detection on %s - %s - %s\n", bindToIP2, bindToIP3, bindToIP4);
	natTypeDetection->Startup(bindToIP2, bindToIP3, bindToIP4);	
		
	// Register signal handler
	if (signal(SIGINT, shutdown) == SIG_ERR || signal(SIGTERM, shutdown) == SIG_ERR)
		perror("Problem setting up signal handler");
	else
		Log::print_log("To exit the tester press Ctrl-C\n----------------------------------------------------\n");
	
	reconnectTime = time(0) + 30;
	Packet *packet;
	while (!quit)
	{
		packet=peer->Receive();
		while (packet)
		{
			switch (packet->data[0])
			{
				case ID_DISCONNECTION_NOTIFICATION:
					Log::info_log("%s has diconnected\n", packet->systemAddress.ToString());
					break;
				case ID_CONNECTION_LOST:
					Log::print_log("Connection to %s lost\n", packet->systemAddress.ToString());
					break;
				case ID_NEW_INCOMING_CONNECTION:
					Log::info_log("New connection established to %s\n", packet->systemAddress.ToString());
					break;
				case ID_CONNECTION_REQUEST_ACCEPTED:
					Log::print_log("Connected to %s\n", packet->systemAddress.ToString());
					break;
				case ID_CONNECTION_ATTEMPT_FAILED:
				{
					if (addresses.count(packet->systemAddress) > 0)
					{
						RakNet::BitStream bitStream;
						bitStream.Write((unsigned char)254);
						peer->Send(&bitStream, HIGH_PRIORITY, RELIABLE, 0, addresses[packet->systemAddress], false);
						addresses.erase(packet->systemAddress);
					}
					else
					{
						Log::error_log("Failed to connect to %s\n", packet->systemAddress.ToString());
					}
					break;
				}
				case ID_ALREADY_CONNECTED:
				{
					// Ignore, probably means we just did a fast reconnect (quit then restart).
					// Connection might be dropped but the reconnect code should fix any problems.
					break;
				}
				case ID_NAT_TARGET_NOT_CONNECTED:
				{
					SystemAddress systemAddress;
					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...
					bitStream.Read(systemAddress);
					Log::warn_log("NAT target %s is not connected to the facilitator\n", systemAddress.ToString());
					break;
				}
				case ID_NAT_CONNECTION_TO_TARGET_LOST:
				{
					SystemAddress systemAddress;
					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...
					bitStream.Read(systemAddress);
					Log::warn_log("NAT connection to %s lost\n", systemAddress.ToString());
					break;
				}
				case 253:
				{
					int remotePort;
					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...
					bitStream.Read(remotePort);

					// Add system to address list so it can be told if the test failed
					SystemAddress remoteTarget;
					remoteTarget.binaryAddress = packet->systemAddress.binaryAddress;
					remoteTarget.port = remotePort;
					addresses[remoteTarget] = packet->systemAddress;
					char remote[32];
					strcpy(remote, remoteTarget.ToString());
					Log::info_log("Adding %s to %s in map\n", packet->systemAddress.ToString(), remote);

					Log::info_log("Attempting connection test to %s:%d\n", packet->systemAddress.ToString(false), remotePort);
					if (!peer->Connect(packet->systemAddress.ToString(false), remotePort, 0, 0))
						Log::info_log("Failed to connect to %s:%d\n", packet->systemAddress.ToString(false), remotePort);					
					break;
				}
				default:
					Log::warn_log("Unknown ID %d from %s\n", packet->data[0], packet->systemAddress.ToString());
			}
			peer->DeallocatePacket(packet);
			packet=peer->Receive();
		}
			
		RakSleep(30);
	}
	
	cleanup();
			
	return 0;
}

#pragma comment(lib,"-lws2_32.lib")
#include <winsock2.h>
#include <winsock.h>
#include<sys/types.h>
#include<mstcpip.h>
#include<stdio.h>
#include<stdlib.h>
#include<conio.h>
#include<windows.h>
int count=0,t1=0;
struct sockaddr_in source,dest;

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

int capture(SOCKET);

void analysepacket(char*,int);
 
int sock,i,j;
int main(){
    char hostname[100];
    struct hostent *local;
    struct in_addr addr;
    int in;
    WSADATA wsaData;
    WORD dllversion=MAKEWORD(2,1);
    if(( i=WSAStartup(dllversion,&wsaData))!=0)printf("wsa startup error %d",i), ExitProcess(EXIT_FAILURE);

    sock=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
    if(sock<=0)printf("sock error %d",sock),ExitProcess(EXIT_FAILURE);

    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d",WSAGetLastError());
		return 1;
	}
	printf("\nHost name : %s \n",hostname);

    local =gethostbyname(hostname);

   if (local == NULL)
	{
		printf("Error : %d.\n",WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d Address : %s\n",i,inet_ntoa(addr));
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d",&in);

    memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr,local->h_addr_list[in],sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

    if (bind(sock,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}

    j=1;
	if (WSAIoctl(sock, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}

    capture((SOCKET) sock);



    closesocket(sock);
	WSACleanup();

	return 0;
}


int capture(SOCKET sock)
{
	char *Buffer = (char *)malloc(65536); //Its Big!
	int packetsize;
	

	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return 0;
	}

	do
	{
		
		packetsize = recvfrom(sock , Buffer , 65536 , 0 , 0 , 0); //Eat as much as u can
		

		if(packetsize > 0)
		{
            t1++;
			//analysepacket(Buffer, packetsize);
            printf("\r packet no %d",t1);
		}
		else
		{
			printf( "recvfrom() failed.\n");
		}
	}
	while (packetsize > 0);

	free(Buffer);
}
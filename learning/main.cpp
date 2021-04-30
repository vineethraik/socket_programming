
#include"network.h"


int count=0;
struct sockaddr_in source,dest;

data d;
 
int i,j;
SOCKET sock;
int main(){
    char hostname[100];
    struct hostent *local;
    struct in_addr addr;

    int in;

    //wsa startup mandatary step for opening socket
    WSADATA wsaData;
    WORD dllversion=MAKEWORD(2,1);
    if(( i=WSAStartup(dllversion,&wsaData))!=0)printf("wsa startup error %d",i), ExitProcess(EXIT_FAILURE);

    //opening a socket
    sock=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
    if(sock<=0)printf("sock error %d",sock),ExitProcess(EXIT_FAILURE);

    //reading hostname and gathering ip of interfaces
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

    //binding to chosed interface
    memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr,local->h_addr_list[in],sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

    if (bind(sock,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}

    //setting the socket to sniffing mode(recive all trafic in the interface)
    j=1;
	if (WSAIoctl(sock, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}

    //capturing and processing packets one by one
    capture_data c_d;
    capture_info c_info;
    data d;
    memcpy(&d.host.s_addr,local->h_addr_list[in],sizeof(d.host.s_addr));
    j=0;
    while(j<10000){
        j++;
        c_d=capture(sock);

        int protocol=get_protocol(c_d);
        c_info.total++;

        switch(protocol){
        case 1:
        c_info.icmp++;
        break;
        case 2:
        c_info.igmp++;
        case 6:
        c_info.tcp++;
        gettcpdata(c_d,d);
        break;
        case 17:
        c_info.udp++;
        getudpdata(c_d,d);
        break;
        default:
        c_info.other++;
        break;
        }
        c_info.print();
    }
    


    closesocket(sock);
	WSACleanup();

	return 0;
}



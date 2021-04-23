#pragma comment(lib,"-lws2_32.lib")
#include <winsock2.h>
#include <winsock.h>
#include<sys/types.h>
#include<stdio.h>
#include<stdlib.h>
#include<conio.h>
#include<windows.h>
int count=0,t1=0;

 
int sock,i;
int main(){
    WSADATA wsaData;
    WORD dllversion=MAKEWORD(2,1);
    if(( i=WSAStartup(dllversion,&wsaData))!=0)printf("wsa startup error %d",i), ExitProcess(EXIT_FAILURE);

    sock=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(sock<=0)printf("sock error %d",sock),ExitProcess(EXIT_FAILURE);
    
    char *buffer = (unsigned char *) malloc(65536); //to receive data
    memset(buffer,0,65536);
    struct sockaddr saddr;
    
    
    
    int saddr_len = sizeof (saddr);
    //Receive a network packet and copy in to buffer
    while(1){
    int buflen=recvfrom(sock,buffer,65536,0,(struct sockaddr *)&saddr,&saddr_len);
    if(buflen<0)
    {
         printf("\rerror in reading recvfrom function %d",buflen);
        //return -1;
    }
    else{
        count++;
        printf("\n%dand%d\n",count,buflen);
    }

    }
    printf("hi boss");
    ExitProcess(EXIT_SUCCESS);
}

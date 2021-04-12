#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib,"-lws2_32.lib")
# include <winsock2.h>
#include<sys/types.h>
#include<stdio.h>
#include<stdlib.h>
#include<conio.h>
#include<windows.h>

#define PORT 80

const char schost[]="www.google.com";

int main(){

  WSADATA wsaData;
  WORD dllversion=MAKEWORD(2,1);
  if(WSAStartup(dllversion,&wsaData)!=0) ExitProcess(EXIT_FAILURE);

  int sock=socket(AF_INET,SOCK_STREAM,0);
  if(sock<0) printf("sock error"),ExitProcess(EXIT_FAILURE);

  HOSTENT *host=gethostbyname(schost);
  if(host == NULL)printf("host  error"),ExitProcess(EXIT_FAILURE);

  SOCKADDR_IN sin;
  ZeroMemory(&sin,sizeof(sin));
  sin.sin_port=htons(PORT);
  sin.sin_family=AF_INET;
  memcpy(&sin.sin_addr.S_un.S_addr,host->h_addr_list[0],sizeof(sin.sin_addr.S_un.S_addr));

  if(connect(sock,(const struct sockaddr *)&sin,sizeof(sin))!=0)
    printf("connect error"),ExitProcess(EXIT_FAILURE);

  const char scmsg[]="HEAD/HTTP/1.0\r\n\r\n";
  if(send(sock,scmsg,sizeof(scmsg),0)>sizeof(scmsg))
    printf("send error%d",sizeof(scmsg)),ExitProcess(EXIT_FAILURE);

  char scbuffer[100000];
  char sctemp[4096];
  while(recv(sock,sctemp,4096,0))
    strcat(scbuffer,sctemp);

  printf("%s\n",scbuffer);

  getch();


  ExitProcess(EXIT_SUCCESS);
}

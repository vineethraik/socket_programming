#pragma comment(lib,"-lws2_32.lib")
#include <winsock2.h>
#include<stdio.h>
#include<iostream>
#include<stdlib.h>
#include<stdexcept>
#include<conio.h>
#include<vector>
#include<string>



#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

int t1=0,i;

using namespace std;


string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

/*******************************class and function declaration**************************************/


class addr;
class store;
class data;
class capture_data;

capture_data capture(SOCKET);
int get_protocol(capture_data);
void gettcpdata(capture_data,data*);
void getudpdata(capture_data,data*);
string getservicebyport(int);
string get_service_by_port(int,int);


/*******************************IP headder**************************************/


typedef struct ip_hdr
{
	unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version :4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset :5; // Fragment offset field

	unsigned char ip_more_fragment :1;
	unsigned char ip_dont_fragment :1;
	unsigned char ip_reserved_zero :1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;


/*******************************TCP headder**************************************/


typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1:3; //according to rfc
	unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin :1; //Finish Flag
	unsigned char syn :1; //Synchronise Flag
	unsigned char rst :1; //Reset Flag
	unsigned char psh :1; //Push Flag
	unsigned char ack :1; //Acknowledgement Flag
	unsigned char urg :1; //Urgent Flag

	unsigned char ecn :1; //ECN-Echo Flag
	unsigned char cwr :1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;



/*******************************UDP headder**************************************/


typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;


/*******************************class declaration**************************************/
/*******************************class capture_info**************************************/
class capture_info{
    public:
    int total;
    int icmp;
    int igmp;
    int tcp;
    int udp;
    int other;
    capture_info();
    void print();
};

capture_info::capture_info(){
    total=0;
    icmp=0;
    igmp=0;
    tcp=0;
    udp=0;
    other=0;
}

void capture_info::print(){
printf("\r|TCP : %d |UDP : %d |ICMP : %d |IGMP : %d |OTHER %d |TOTAL %d",tcp,udp,icmp,igmp,other,total);
}

/*******************************class capture_data**************************************/

class capture_data{
    public:
    char *buffer;
    int packet_size;
    capture_data(){buffer=(char *)malloc(65536);packet_size=0;}
};

/*******************************CLASS  addr**************************************/

class addr{
    private:
    in_addr src;
    in_addr dest;
    int ports;
    int portd;
    int packet_size;
    string servicename;
    public:
    
    friend class store;
    friend class data;
};

/*******************************CLASS  store**************************************/

class store{
    private:
    int len;
    int port;
    vector<addr> adr;
    public:
    store(){len=0;adr.clear();}
    

    friend class data;
};

/*******************************CLASS  data**************************************/

class data{
    private:
    int len;
    int packet_count;
    vector<store> stores;
    public:
    in_addr host;
    data(){len=0;packet_count=0;stores.clear();}
    void copy(data d){len=d.len;stores=d.stores;packet_count=d.packet_count;}
    void add(int,int,in_addr,in_addr,int);
    void print();
    void sort();
    void save_to_file(string);
} ;

void data::add(int ports,int portd,in_addr adr_s,in_addr adr_d,int packetsize){
    packet_count++;
    store st;
    addr adrs;
    if(len==0){
        
        if(ports>portd){
            st.port=ports;
        }
        else{
            st.port=portd;
        }
        adrs.dest=adr_d;
        adrs.src=adr_s;
        adrs.packet_size=packetsize;
        adrs.portd=portd;
        adrs.ports=ports;
        adrs.servicename=get_service_by_port(ports,portd);
        //adrs.servicename=(inet_ntoa(host)==inet_ntoa(adr_s))?getservicebyport(ports):getservicebyport(portd);
        st.adr.push_back(adrs);
        st.len++;
        len++;
        stores.push_back(st);
        
    }else{
        int port=(portd>ports)?portd:ports;
        for(i=0;i<len;i++){
            if(port==stores.at(i).port){
                adrs.dest=adr_d;
                adrs.src=adr_s;
                adrs.packet_size=packetsize;
                adrs.portd=portd;
                adrs.ports=ports;
                adrs.servicename=get_service_by_port(ports,portd);
                //adrs.servicename=(inet_ntoa(host)==inet_ntoa(adr_s))?getservicebyport(ports):getservicebyport(portd);
                stores.at(i).adr.push_back(adrs);
                stores.at(i).len++;
                i=0;
                break;

            }
        }
        if(i!=0){
            st.port=port;
            adrs.dest=adr_d;
            adrs.src=adr_s;
            adrs.packet_size=packetsize;
            adrs.portd=portd;
            adrs.ports=ports;
            adrs.servicename=get_service_by_port(ports,portd);
            //adrs.servicename=(inet_ntoa(host)==inet_ntoa(adr_s))?getservicebyport(ports):getservicebyport(portd);
            st.adr.push_back(adrs);
            st.len++;
            len++;
            stores.push_back(st);

        }
    }
    

    

}

void  data::print(){
    for(int i=0;i<stores.size();i++){
        cout<<"************************************************************************\n";
        cout<<stores.at(i).port<<":\n";
        for(int j=0;j<stores.at(i).len;j++){
            cout<<"|source:"<<inet_ntoa(stores.at(i).adr.at(j).src);
            cout<<" |destination:"<<inet_ntoa(stores.at(i).adr.at(j).dest);
            cout<<" |source port:"<<stores.at(i).adr.at(j).ports;
            cout<<" |destination port:"<<stores.at(i).adr.at(j).portd;
            cout<<" |packet size:"<<stores.at(i).adr.at(j).packet_size;
            cout<<" |service :"<<stores.at(i).adr.at(j).servicename;
            cout<<"\n";
        }
        cout<<"\n";
    }
}

void data::sort(){
    vector<store> st;
    st=stores;
    stores.clear();
    for(int i=0;i<100000;i++){
        for(int j=0;j<st.size();j++){
            if(i==st.at(j).port){
                stores.push_back(st.at(j));
                st.erase(st.begin()+j);
            }
        }
        if(st.size()==0){break;}
    }
    
}

void data::save_to_file(string filename){
    FILE *file;

    file=fopen(filename.c_str(),"w");
	if(file == NULL)
	{
		printf("Unable to create file.");
	}
    else{
        for(int i=0;i<stores.size();i++){
            fprintf(file,"************************************************************************\n");
            fprintf(file,"%d:\n",stores.at(i).port);
            for(int j=0;j<stores.at(i).len;j++){
            fprintf(file," |source:%s",inet_ntoa(stores.at(i).adr.at(j).src));
            fprintf(file," |destination:%s",inet_ntoa(stores.at(i).adr.at(j).dest));
            fprintf(file," |source port:%d",stores.at(i).adr.at(j).ports);
            fprintf(file," |destination port:%d",stores.at(i).adr.at(j).portd);
            fprintf(file," |packet size:%d",stores.at(i).adr.at(j).packet_size);
            fprintf(file," |service:%s\n",stores.at(i).adr.at(j).servicename.c_str());
            }
            fprintf(file,"\n\n");
        }

    }
    fclose(file);
}

/*******************************function capture**************************************/

capture_data capture(SOCKET sock)
{
	capture_data c_d;
	

	if (c_d.buffer == NULL)
	{
		printf("malloc() failed.\n");
		exit(0);
	}

	
	
		while(1){
		c_d.packet_size = recvfrom(sock , c_d.buffer , 65536 , 0 , 0 , 0); //Eat as much as u can
		

		if(c_d.packet_size > 0)
		{
            
            return c_d;
		}
		else
		{
			printf( "recvfrom() failed.\n");
            
		}
        }
	
	
}

/*******************************function get_protocol**************************************/


int get_protocol(capture_data d){
    IPV4_HDR *iphdr;
    iphdr=(IPV4_HDR *)d.buffer;

    return iphdr->ip_protocol;

}


/*******************************function gettcpdata**************************************/

void gettcpdata(capture_data c_d,data *d){
    IPV4_HDR *iphdr;
    TCP_HDR *tcphdr;

    unsigned short iphdrlen;

    in_addr source,dest;

	iphdr = (IPV4_HDR *)c_d.buffer;
	iphdrlen = iphdr->ip_header_len*4;
    tcphdr=(TCP_HDR*)(c_d.buffer+iphdrlen);
    source.S_un.S_addr=iphdr->ip_srcaddr;
    dest.S_un.S_addr=iphdr->ip_destaddr;
    
    
    d->add(
    ntohs(tcphdr->source_port),
    ntohs(tcphdr->dest_port),
    source,
    dest,
    c_d.packet_size
    );

}

/*******************************function getudpdata**************************************/

void getudpdata(capture_data c_d,data *d){
    IPV4_HDR *iphdr;
    UDP_HDR *udphdr;

    unsigned short iphdrlen;

    in_addr source,dest;

	iphdr = (IPV4_HDR *)c_d.buffer;
	iphdrlen = iphdr->ip_header_len*4;
    udphdr=(UDP_HDR*)(c_d.buffer+iphdrlen);

    source.S_un.S_addr=iphdr->ip_srcaddr;
    dest.S_un.S_addr=iphdr->ip_destaddr;
    
    
    d->add(
    ntohs(udphdr->source_port),
    ntohs(udphdr->dest_port),
    source,
    dest,
    c_d.packet_size
    );

}

/*******************************function getservicebyport**************************************/

string getservicebyport(int port){

    WSADATA wsaData;
    WORD dllversion=MAKEWORD(2,1);
    if(( i=WSAStartup(dllversion,&wsaData))!=0)printf("wsa startup error %d",i), ExitProcess(EXIT_FAILURE);

    char *buffer;
    buffer = getservbyport(htons(port),NULL)->s_name;
    return buffer;

}

/*******************************function get_service_by_port**************************************/

string get_service_by_port(int port1,int port2){
    string temp;
    temp="undefined";
    switch(port1){
        case 53:
        temp="DNS";
        break;
        case 80:
        temp="HTTP";
        break;
        case 137:
        temp="NetBIOS";
        break;
        case 443:
        temp="HTTPS";
        break;
        case 5353:
        temp="HTTPS";
        break;
    }
    switch(port2){
        case 53:
        temp="DNS";
        break;
        case 80:
        temp="HTTP";
        break;
        case 137:
        temp="NetBIOS";
        break;
        case 443:
        temp="HTTPS";
        break;
        case 5353:
        temp="HTTPS";
        break;
    }

    
    return temp;
}

/*******************************function get_service_by_port**************************************/

/*******************************function get_protocol**************************************/


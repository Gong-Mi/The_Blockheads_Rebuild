// Synthetic loopback server: tests transport, not original game behavior.
#include <enet/enet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(void){
 if(enet_initialize())return 1;
 ENetAddress a;a.port=0;enet_address_set_host_ip(&a,"127.0.0.1");
 ENetHost*h=enet_host_create(&a,4,2,0,0);if(!h)return 2;
 struct sockaddr_in actual;socklen_t len=sizeof(actual);
 if(getsockname(h->socket,(struct sockaddr*)&actual,&len))return 3;
 printf("READY %u\n",ntohs(actual.sin_port));fflush(stdout);
 enet_uint32 start=enet_time_get();ENetEvent e;
 const char msg[]="\x23\x26<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>worldID</key><string>synthetic-fixture</string></dict></plist>";
 while(enet_time_get()-start<15000){
  if(enet_host_service(h,&e,100)<=0)continue;
  if(e.type==ENET_EVENT_TYPE_CONNECT)enet_peer_send(e.peer,0,enet_packet_create(msg,sizeof(msg)-1,ENET_PACKET_FLAG_RELIABLE));
  if(e.type==ENET_EVENT_TYPE_RECEIVE)enet_packet_destroy(e.packet);
 }
 enet_host_destroy(h);enet_deinitialize();return 0;
}

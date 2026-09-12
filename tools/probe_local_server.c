#include <enet/enet.h>
#include <stdio.h>
#include <stdlib.h>
// Local-only original-server transport probe. Compression is opt-in for negative control.
int main(int argc,char**argv){
 if(argc<2||argc>3)return 1;
 char*end=NULL;long port=strtol(argv[1],&end,10);if(*end||port<1||port>65535)return 1;
 if(enet_initialize()!=0)return 2;
 ENetHost*h=enet_host_create(NULL,1,2,0,0);if(!h)return 2;
 if(argc==3&&enet_host_compress_with_range_coder(h)!=0)return 2;
 ENetAddress a;a.port=(enet_uint16)port;enet_address_set_host_ip(&a,"127.0.0.1");
 ENetPeer*p=enet_host_connect(h,&a,2,0);if(!p)return 3;
 int connected=0;ENetEvent e;enet_uint32 start=enet_time_get();
 while(enet_time_get()-start<4000){
  int r=enet_host_service(h,&e,100);if(r<0)break;if(!r)continue;
  printf("event=%d channel=%u\n",e.type,e.channelID);
  if(e.type==ENET_EVENT_TYPE_CONNECT)connected=1;
  if(e.type==ENET_EVENT_TYPE_RECEIVE){printf("packet_bytes=%zu hex=",e.packet->dataLength);for(size_t i=0;i<e.packet->dataLength;i++)printf("%02x",e.packet->data[i]);puts("");enet_packet_destroy(e.packet);}
 }
 enet_peer_disconnect_now(p,0);enet_host_destroy(h);enet_deinitialize();return connected?0:4;
}

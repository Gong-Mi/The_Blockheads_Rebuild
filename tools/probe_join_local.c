#include <enet/enet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Real first-join step probe against the ORIGINAL server 1.7.1.
 * CONNECT -> wait for the worldID announcement (first RECEIVE)
 *         -> send the player-information payload read from a file
 *            (0x1f + XML plist, built by tools/player_info_packet.py)
 *         -> keep listening and print every further server message.
 * Verified with the local qemu server: the server accepts the player
 * ("Player Connected probe | 127.0.0.1 | <md5>") and replies with the
 * compressed world-metadata plist (0x01 + gzip) and a 0x1e plist array.
 * Local-only, compression OFF (matches the server config that connects).
 */
static void hexdump(const unsigned char *b, size_t n){
    printf("packet_bytes=%zu hex=", n);
    for(size_t j=0;j<n;j++)printf("%02x",b[j]);
    puts("");
}
int main(int argc,char **argv){
    if(argc<3){fprintf(stderr,"usage: %s SERVER_PORT PAYLOAD_FILE [timeout_ms=8000]\n",argv[0]);return 1;}
    long port=strtol(argv[1],NULL,10); if(port<1||port>65535)return 1;
    long timeout=8000; if(argc>3)timeout=strtol(argv[3],NULL,10);
    FILE *f=fopen(argv[2],"rb"); if(!f){perror("payload");return 1;}
    fseek(f,0,SEEK_END); long plen=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char *payload=malloc((size_t)plen);
    if(!payload||fread(payload,1,(size_t)plen,f)!=(size_t)plen){perror("read");return 1;}
    fclose(f);
    printf("payload_bytes=%ld prefix=%02x\n",plen,payload[0]);fflush(stdout);

    if(enet_initialize()!=0)return 2;
    ENetHost *h=enet_host_create(NULL,1,2,0,0); if(!h)return 2;
    ENetAddress a; a.port=(enet_uint16)port; enet_address_set_host_ip(&a,"127.0.0.1");
    ENetPeer *p=enet_host_connect(h,&a,2,0); if(!p)return 3;
    ENetEvent e; int connected=0,announced=0,sent=0,replies=0;
    enet_uint32 start=enet_time_get();
    printf("library_version=%u\n",enet_linked_version());fflush(stdout);
    while(enet_time_get()-start<(enet_uint32)timeout){
        int r=enet_host_service(h,&e,100); if(r<0)break; if(!r)continue;
        printf("event=%d channel=%u data=%u\n",e.type,e.channelID,e.data);fflush(stdout);
        if(e.type==ENET_EVENT_TYPE_CONNECT){connected=1;continue;}
        if(e.type==ENET_EVENT_TYPE_RECEIVE){
            printf("dir=server_to_client ");hexdump(e.packet->data,e.packet->dataLength);
            if(!announced){
                announced=1;
                ENetPacket *pp=enet_packet_create(payload,(size_t)plen,ENET_PACKET_FLAG_RELIABLE);
                if(enet_peer_send(p,0,pp)!=0)printf("send failed\n");
                else{printf("dir=client_to_server player_info sent\n");sent=1;}
                fflush(stdout);
            } else {
                replies++;
                printf("dir=server_to_client post-join reply #%d\n",replies);fflush(stdout);
            }
            enet_packet_destroy(e.packet);
            continue;
        }
        if(e.type==ENET_EVENT_TYPE_DISCONNECT){printf("dir=server DISCONNECT\n");break;}
    }
    enet_peer_disconnect_now(p,0);enet_host_destroy(h);enet_deinitialize();
    free(payload);
    printf("RESULT connected=%d announced=%d player_info_sent=%d post_join_replies=%d\n",
           connected,announced,sent,replies);
    return (connected&&announced&&sent&&replies>0)?0:4;
}
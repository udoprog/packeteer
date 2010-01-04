#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>

#define PROGRAM "packeteer"

// example dns package
// captured using wireshark
char pkt9181[] = {
    0x00, 0x50, 0x56, 0x8f, 0x3c, 0x62, 0x00, 0x23, 
    0x68, 0x13, 0x06, 0xf1, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x4a, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 
    0xdd, 0x47, 0xac, 0x10, 0x04, 0x37, 0xac, 0x10, 
    0x01, 0x04, 0xa1, 0xae, 0x00, 0x35, 0x00, 0x36, 
    0x5d, 0xa3, 0xd3, 0xa6, 0x01, 0x00, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x5f, 
    0x68, 0x74, 0x74, 0x70, 0x73, 0x04, 0x5f, 0x74, 
    0x63, 0x70, 0x02, 0x66, 0x73, 0x09, 0x75, 0x62, 
    0x75, 0x6e, 0x74, 0x75, 0x6f, 0x6e, 0x65, 0x03, 
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0x21, 0x00, 0x01 };

int main(int argc, char *argv[]) {
    unsigned int devlen = 0;
    int s_id;
    void *buffer = NULL;
    
    size_t sent = 0, buffer_s = 0x2FF, a_bytes = 0;
    
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET,
        .sll_ifindex = 0x0,
    };
    
    struct ifreq ifreq = {
        .ifr_name = "",
    };
    
    if (argc != 2) 
        {
            fprintf( stderr, PROGRAM " usage: packeteer <device>\n" );
            fprintf( stderr, "    send raw buffer_s to if <if>\n" );
            return 1;
        }
    
    /* copy device name into the ioctl request */
    strncpy( ifreq.ifr_name, argv[1], IFNAMSIZ );
    
    /* create a raw socket */
    if ( (s_id = socket(PF_PACKET, SOCK_RAW, 0)) == -1)
        {
            fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
            return 1;
        }
    
    /* do the ioctl request to find out which device we want to bind to */
    if ( ioctl(s_id, SIOCGIFINDEX, &ifreq) == -1 )
        { 
            fprintf( stderr, PROGRAM ": %s - %s\n", strerror(errno), ifreq.ifr_name );
            return 1;
        }
    
    address.sll_ifindex = ifreq.ifr_ifindex;
    
    /* bind to specified address */
    if ( bind(s_id, (struct sockaddr *)&address, sizeof(struct sockaddr_ll) ) == -1 )
        {
            fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
            return 1;
        }
    
    while ( !feof(stdin) )
        {
            buffer_s *= 2;
            
            buffer = realloc( buffer, buffer_s ); 
            
            if ( buffer == NULL )
                {
                    fprintf( stderr, PROGRAM ": cannot allocate enough memory\n" );
                    return 1;
                }
            
            size_t r = fread(buffer, 1, buffer_s - a_bytes, stdin);
            
            if ( r == -1 )
                {
                    fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
                    return 1;
                }
            
            a_bytes += r;
        }
    
    // make sure the entire frame gets sent.
    while (sent != a_bytes)
        {
            size_t b = send( s_id, buffer, a_bytes - sent, 0 );
            
            if ( b == -1 )
                {
                    fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
                    return 1;
                }

            sent += b;
        }
    
    free( buffer );
    
    return 0;
}

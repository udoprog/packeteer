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

#define SEND_BUFFER_LIMIT 0xffffff

void *send_buffer = NULL;
size_t send_buffer_s = 0xff;
size_t send_buffer_r = 0x0;

int read_file_to_send_buffer(FILE *file)
{
    while ( !feof(stdin) )
      {
        send_buffer_s *= 2;

        if ( send_buffer_s >= SEND_BUFFER_LIMIT )
          {
            fprintf( stderr, PROGRAM ": buffer memory limit reached\n" );
            return -1;
          }
        
        send_buffer = realloc( send_buffer, send_buffer_s ); 
        
        if ( send_buffer == NULL )
          {
            fprintf( stderr, PROGRAM ": cannot allocate enough memory\n" );
            return -1;
          }
        
        size_t r = fread( send_buffer + send_buffer_r, 1, send_buffer_s - send_buffer_r, stdin );
        
        if ( r == -1 )
          {
            fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
            return -1;
          }
        
        send_buffer_r += r;
      }

    return 0;
}

int send_file( int socket_id )
{
    size_t send_buffer_sent = 0;
    
    // make sure the entire frame gets sent.
    while ( send_buffer_sent < send_buffer_s )
        {
            size_t b = send( socket_id, send_buffer + send_buffer_sent, send_buffer_s - send_buffer_sent, 0 );
            
            if ( b == -1 )
                {
                    fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
                    return 1;
                }
            
            send_buffer_sent += b;
        }

}

int open_raw_socket( const char *dev )
{
    int s_id;
    
    struct sockaddr_ll address = {
      .sll_family = AF_PACKET,
    };
    
    struct ifreq ifreq = {
      .ifr_name = "",
    };
    
    /* copy device name into the ioctl request */
    strncpy( ifreq.ifr_name, dev, IFNAMSIZ );
    
    /* create a raw socket */
    if ( (s_id = socket(PF_PACKET, SOCK_RAW, 0)) == -1)
      {
        fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
        return -1;
      }
    
    /* do the ioctl request to find out which device we want to bind to */
    if ( ioctl(s_id, SIOCGIFINDEX, &ifreq) == -1 )
      { 
        fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
        return -1;
      }
    
    address.sll_ifindex = ifreq.ifr_ifindex;
    
    /* bind to specified address */
    if ( bind(s_id, (struct sockaddr *)&address, sizeof(struct sockaddr_ll) ) == -1 )
      {
        fprintf( stderr, PROGRAM ": %s\n", strerror(errno) );
        return -1;
      }

    return s_id;
}

int main(int argc, char *argv[]) {
    if (argc != 2) 
      {
        fprintf( stderr, "usage: packeteer <device>\n" );
        fprintf( stderr, "\n" );
        fprintf( stderr, "    inject frame from stdin to if <device>\n" );
        return 1;
      }
    
    const char *dev = argv[1];
    
    int s_id;
    
    if ( (s_id = open_raw_socket( dev )) == -1 )
      {
        fprintf( stderr, PROGRAM ": failed to open raw socket to device '%s'\n", dev );
        return 1;
      }
    
    if ( read_file_to_send_buffer(stdin) == -1 )
      {
        return 1;
      }
    
    if ( send_file( s_id ) == -1 )
      {
        return 1;
      }
    
    return 0;
}

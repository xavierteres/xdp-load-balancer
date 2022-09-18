from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct

flags = 0
def usage():
    print("Usage: {0} <clients ifdev> <backends ifdev>".format(sys.argv[0]))
    print("e.g.: {0} eth0 eth1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 3:
    usage()

# Clients interface
cli_if = sys.argv[1]
# Backends interface
back_if = sys.argv[2]

# Out interface id
ip = pyroute2.IPRoute()
cli_idx = ip.link_lookup(ifname=cli_if)[0]
back_idx = ip.link_lookup(ifname=back_if)[0]

# Load BPF program
b = BPF(text = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct client {
  u8 mac_addr[6];
  int backend;
};

BPF_DEVMAP(cli_port, 1);
BPF_DEVMAP(back_port, 1);
BPF_HASH(clients, u32, struct client, 256);
BPF_ARRAY(next_back, int, 1);

static inline unsigned short checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int xdp_load_balancer(struct xdp_md *ctx) {
    unsigned short old_daddr;
    unsigned long sum;

    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
  
    struct ethhdr *eth = data;

    nh_off = sizeof(*eth);
    if (data + nh_off  > data_end)
        return XDP_PASS;
    
    if(ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + nh_off;

    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcph = data + nh_off;
    nh_off += sizeof(struct tcphdr);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    old_daddr = ntohs(*(unsigned short *)&iph->daddr);

    int n_back = 0;
    // Store client's MAC
    struct client *cli = clients.lookup(&iph->saddr); 
    if (!cli) {
        struct client new_cli = {};
	new_cli.mac_addr[0] = eth->h_source[0];
        new_cli.mac_addr[1] = eth->h_source[1];
        new_cli.mac_addr[2] = eth->h_source[2];
        new_cli.mac_addr[3] = eth->h_source[3];
        new_cli.mac_addr[4] = eth->h_source[4];
        new_cli.mac_addr[5] = eth->h_source[5];

        int key = 0;
        int *next = next_back.lookup(&key);
        
        if (next && *next == 1) {
            n_back = 1;
        }
        else  {
            n_back = 0;
        }

        new_cli.backend = n_back;

        clients.insert(&iph->saddr, &new_cli); 
    } else {
        n_back = cli->backend;
    }

    int new_back = 1; 
    if(n_back == 0) {
        // Rewrite MAC
	eth->h_dest[0]=8;
	eth->h_dest[1]=0;
	eth->h_dest[2]=39;
	eth->h_dest[3]=57;
	eth->h_dest[4]=195;
	eth->h_dest[5]=67;
	
	// Update IP checksum
	iph->daddr = htonl(167772161);
    }
    else {
        // Rewrite MAC
        eth->h_dest[0]=8;
        eth->h_dest[1]=0;
        eth->h_dest[2]=39;
        eth->h_dest[3]=233;
        eth->h_dest[4]=4;
	eth->h_dest[5]=69;
	
	// Update IP checksum
	iph->daddr = htonl(167772162);
        
        new_back = 0;
    }
    
    int key = 0;
    next_back.update(&key, &new_back);

    iph->check = 0;
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // Update TCP checksum
    sum = old_daddr + (~ntohs(*(unsigned short *)&iph->daddr) & 0xffff);
    sum += ntohs(tcph->check);
    sum = (sum & 0xffff) + (sum>>16);
    tcph->check = htons(sum + (sum>>16) + 256 + 1 - n_back);

    return back_port.redirect_map(0, 0);
}

int xdp_redirect_client(struct xdp_md *ctx) {
    unsigned short old_saddr;
    unsigned long sum;

    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
  
    struct ethhdr *eth = data;

    nh_off = sizeof(*eth);
    if (data + nh_off  > data_end)
        return XDP_PASS;
    
    if(ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + nh_off;

    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcph = data + nh_off;
    nh_off += sizeof(struct tcphdr);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    u32 cli_addr = iph->daddr;

    old_saddr = ntohs(*(unsigned short *)&iph->saddr);

    int b = 0;
    // Rewrite clients MAC
    struct client *cli = clients.lookup(&iph->daddr);
    if (cli) {
	eth->h_dest[0]= cli->mac_addr[0];
        eth->h_dest[1]= cli->mac_addr[1];
        eth->h_dest[2]= cli->mac_addr[2];
        eth->h_dest[3]= cli->mac_addr[3];
        eth->h_dest[4]= cli->mac_addr[4];
        eth->h_dest[5]= cli->mac_addr[5];
        b = cli->backend;
    }

    // Update IP checksum
    iph->saddr = htonl(167772418);
    iph->check = 0;
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // Update TCP checksum
    sum = old_saddr + (~ntohs(*(unsigned short *)&iph->saddr) & 0xffff);
    sum += ntohs(tcph->check);
    sum = (sum & 0xffff) + (sum>>16);
    
    tcph->check = htons(sum + (sum>>16) - 257 + b);
    return cli_port.redirect_map(0, 0);
}
""", cflags=["-w"])

cli_port = b.get_table("cli_port")
cli_port[0] = ct.c_int(cli_idx)
back_port = b.get_table("back_port")
back_port[0] = ct.c_int(back_idx)
next_back = b.get_table("next_back")
next_back[0] = ct.c_int(0)

cli_fn = b.load_func("xdp_load_balancer", BPF.XDP)
back_fn = b.load_func("xdp_redirect_client", BPF.XDP)

b.attach_xdp(cli_if, cli_fn, flags)
b.attach_xdp(back_if, back_fn, flags)

print("Filter attached")
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(cli_if, flags)
b.remove_xdp(back_if, flags)

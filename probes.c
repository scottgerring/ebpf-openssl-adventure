//go:build ignore

#include "common.h"
#include "bpf_tracing.h"

// You actually need this!
char __license[] SEC("license") = "Dual MIT/GPL";

// Record we write back in our ringbuff to user space
#define MAX_BUFF_SIZE 80
struct ssl_data_event_t {
	u32 pid; 
	u32 len;
	char is_outgoing; // 1 if outgoing, 0 if incoming
	u8 buf[MAX_BUFF_SIZE];
};

// Force emitting struct event into the ELF.
//const struct event *unused __attribute__((unused));
const struct ssl_data_event_t *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);

} ssl_data_event_map SEC(".maps");




// Record we use to share the user's buffer address
// between SSL_read uprobe and uretprobe probes
struct ssl_read_data{
	u32 len;
	u64 buf;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ssl_read_data);
} ssl_read_data_map SEC(".maps");



// https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html
// This one is pretty easy - we are given the unencrypted data
// by the caller / application.
SEC("uprobe/libssl_write")
int uprobe_libssl_write(struct pt_regs *ctx) {

	// 2nd arg - buffer
	// 3rd arg - length
	void* buf = (void *) PT_REGS_PARM2(ctx); // RSI 'x /s $rsi'
	u64 size =  PT_REGS_PARM3(ctx); // RDX // 'p /d $rdx'

	// We need our per-CPU map to read this into
	u32 map_id = 0;
	struct ssl_data_event_t* map_value = bpf_ringbuf_reserve(&ssl_data_event_map, sizeof(struct ssl_data_event_t), 0);
	if (!map_value) {
		return 0; 
	}

	// Store the PID and payload size
	map_value->pid = bpf_get_current_pid_tgid() >> 32;
	map_value->len = size;
	map_value->is_outgoing = 1;

	// If we think there's nothing in the buffer, then we can bail out
	if (size == 0) { 
		bpf_ringbuf_discard(map_value, 0);
		return 0;
	}
	
	// How much do we need to copy?
	u32 buf_size = MAX_BUFF_SIZE;
	if (size < buf_size) {
		buf_size = size;
	}

	// Read it, and give up if it doesn't work
	if (bpf_probe_read_user(map_value->buf, buf_size, buf) != 0) {
		bpf_ringbuf_discard(map_value, 0);
		return 0;
	}

	char fmt[] = "decoded:%sn";
	bpf_trace_printk(fmt, sizeof(fmt), map_value->buf);

	bpf_ringbuf_submit(map_value, 0);

	return 0;
}


// For the libssl_read call, we need a uprobe to capture
// the user-provided buffer that the decoded result will 
// be read into.
SEC("uprobe/libssl_read")
int uprobe_libssl_read(struct pt_regs *ctx) {
	
	// Get a map element we can store the user's data pointer in
	u32 zero = 0;
	struct ssl_read_data *data = bpf_map_lookup_elem(&ssl_read_data_map, &zero);
    if (!data)
        return 0;
	
	// Store the address and size of the user-supplied buffer
	// that we will read the decrypted data back out of.
	data->buf = PT_REGS_PARM2(ctx);
	data->len = PT_REGS_PARM3(ctx);

	return 0;
}

// Once we libssl_read is complete, we can grab the buffer
// again, and read the decrypted results back out of it.
SEC("uretprobe/libssl_read")
int uretprobe_libssl_read(struct pt_regs *ctx) {

	// Get the data from the uprobe for read back
	u32 zero = 0;
	struct ssl_read_data *data = bpf_map_lookup_elem(&ssl_read_data_map, &zero);
    if (!data)
        return 0;	

	// We can read out the arguments passed to SSL_read by the user's code
	// by pulling the value stashed in our uprobe (above).
	u32 map_id = 0;
	struct ssl_data_event_t* map_value = bpf_ringbuf_reserve(&ssl_data_event_map, sizeof(struct ssl_data_event_t), 0);
	if (!map_value) {
		return 0; 
	}

	// Store the PID and indicate this is an incoming message
	map_value->pid = bpf_get_current_pid_tgid() >> 32;
	map_value->is_outgoing = 0;
	
	// Return code of SSL_read is the number of bytes decrypted
	// If we got none, we can bail out.
	u64 size = PT_REGS_RC(ctx);
	if (size == 0) { 
		bpf_ringbuf_discard(map_value, 0);
		return 0;
	}
	
	// How much do we need to copy?
	u32 buf_size = MAX_BUFF_SIZE;
	if (size < buf_size) {
		buf_size = size;
	}

	// Write the buffer size back so userspace can find it
	map_value->len = buf_size;

	// Read it, and give up if it doesn't work
	if (bpf_probe_read_user(map_value->buf, buf_size, (char*)data->buf) != 0) {
		bpf_ringbuf_discard(map_value, 0);
		return 0;
	}

	bpf_ringbuf_submit(map_value, 0);

	return 0;
}

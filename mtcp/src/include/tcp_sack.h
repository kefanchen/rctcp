#ifndef __TCP_SACK_H
#define __TCP_SACK_H

#inlcude "tcp_stream.h"


void
UpdateSACKBlks(tcp_stream* cur_stream,uint32_t rcv_start,uint32_t rcv_end);

void
CleanSACKBlks(tcp_stream* cur_stream);

int 
UpdateScoreBoard(tcp_stream* cur_stream,uint32_t ack_seq);

void
FreeScoreBoard(tcp_stream* cur_stream);

struct sackhole*
NextUnSackSeg(tcp_stream* cur_stream,int *sack_bytes_rexmit);

//void
//tcp_sack_adjust(tcp_stream * cur_stream);

#endif //__TCP_SACK_H
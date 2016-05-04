#include <unistd.h>
#include "tcp_out.h"
#include "mtcp.h"
#include "ip_out.h"
#include "tcp_in.h"
#include "tcp_stream.h"
#include "eventpoll.h"
#include "timer.h"
#include "debug.h"

#define TCP_CALCULATE_CHECKSUM      TRUE
#define ACK_PIGGYBACK				TRUE
#define TRY_SEND_BEFORE_QUEUE		FALSE

#define TCP_MAX_WINDOW 65535

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

/*----------------------------------------------------------------------------*/
static inline uint16_t
CalculateOptionLength(uint8_t flags)
{
	uint16_t optlen = 0;

	if (flags & TCP_FLAG_SYN) {
		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK) {
			optlen += TCP_OPT_SACK_LEN + 2;
		}
#endif
	}

	assert(optlen % 4 == 0);

	return optlen;
}

//ckf add
//only called by sendTCPPackets to send ack with sack
static inline uint16_t
CalculateOptionSACKLength(tcp_stream* cur_stream,uint8_t flags)
{
	uint16_t optlen = 0;

	if (flags & TCP_FLAG_SYN) {
		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK &&
			!TAILQ_EMPTY(cur_stream->rcvvar->batched_sackoptions)) {
			struct sackoption* sackopt = TAILQ_FIRST(cur_stream->rcvva->batched_sackoptions);
			switch(sackopt->sackblk_num){
				case 1:
					optlen += TCP_OPT_SACK_LEN1 + 2;
					break;
				case 2:
					optlen += TCP_OPT_SACK_LEN2 + 2;
					break;
				case 3:
					optlen += TCP_OPT_SACK_LEN3 + 2;
					break;

			}

		}
#endif
	}

	assert(optlen % 4 == 0);

	return optlen;
}



/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPTimestamp(tcp_stream *cur_stream, uint8_t *tcpopt, uint32_t cur_ts)
{
	uint32_t *ts = (uint32_t *)(tcpopt + 2);

	tcpopt[0] = TCP_OPT_TIMESTAMP;
	tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(cur_stream->rcvvar->ts_recent);
}

//ckf add
static inline int 
GenerateSACKOption(tcp_stream* cur_stream,uint8_t* tcpopt){

	if(cur_stream->rcvvar->batched_sackoption_num > 0&&
		!TAILQ_EMPTY(&cur_stream->rcvvar->batched_sackoptions)){
		struct sackoption* sackopt = TAILQ_FIRST(&cur_stream->rcvvar->batched_sackoptions);	
		uint32_t* edge = (uint32_t*)(tcpopt + 2);
		int i = 0;
		tcpopt[0] = TCP_OPT_SACK;
		tcpopt[1] = TCP_OPT_SACK_LEN;
		while(i < sackopt->sackblk_num){
			edge[0 + (i << 1)] = htonl(sack->sackblks[i].start);
			edge[1 + (i << 1)] = htonl(sack->sackblks[i].end);

			i++;
		}

		TAILQ_REMOVE(&cur_stream->rcvvar->batched_sackoptions,sackopt,solink);
		free(sack);
		sack = 0;
		cur_stream->rcvvar->batched_sackoption_num -- ;
		switch(i){
			case 1:
				return TCP_OPT_SACK_LEN1 + 2;
			case 2:
				return TCP_OPT_SACK_LEN2 + 2;
			case 3:
				return TCP_OPT_SACK_LEN3 + 2;

		}
	}
	return 0;
}

/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPOptions(tcp_stream *cur_stream, uint32_t cur_ts, 
		uint8_t flags, uint8_t *tcpopt, uint16_t optlen)
{
	int i = 0;

	if (flags & TCP_FLAG_SYN) {
		uint16_t mss;

		/* MSS option */
		mss = cur_stream->sndvar->mss;
		tcpopt[i++] = TCP_OPT_MSS;
		tcpopt[i++] = TCP_OPT_MSS_LEN;
		tcpopt[i++] = mss >> 8;
		tcpopt[i++] = mss % 256;

		/* SACK permit */
#if TCP_OPT_SACK_ENABLED
#if !TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
		tcpopt[i++] = TCP_OPT_SACK_PERMIT;
		tcpopt[i++] = TCP_OPT_SACK_PERMIT_LEN;
		TRACE_SACK("Local SACK permited.\n");
#endif /* TCP_OPT_SACK_ENABLED */

		/* Timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		/* Window scale */
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_WSCALE;
		tcpopt[i++] = TCP_OPT_WSCALE_LEN;
		tcpopt[i++] = cur_stream->sndvar->wscale;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_OPT_SACK) {
			// TODO: implement SACK support
			//ckf mod
			tcpopt[i++] = TCP_OPT_NOP;
			tcpopt[i++] = TCP_OPT_NOP;
			i += GenerateSACKOption(cur_stream,tcpopt+i);
		}
#endif
	}

	assert (i == optlen);
}
/*----------------------------------------------------------------------------*/
int
SendTCPPacketStandalone(struct mtcp_manager *mtcp, 
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
		uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
		uint8_t *payload, uint16_t payloadlen, 
		uint32_t cur_ts, uint32_t echo_ts)
{
	struct tcphdr *tcph;
	uint8_t *tcpopt;
	uint32_t *ts;
	uint16_t optlen;

	optlen = CalculateOptionLength(flags);
	if (payloadlen > TCP_DEFAULT_MSS + optlen) {
		TRACE_ERROR("Payload size exceeds MSS.\n");
		assert(0);
		return ERROR;
	}

	tcph = (struct tcphdr *)IPOutputStandalone(mtcp, 0, 
			saddr, daddr, TCP_HEADER_LEN + optlen + payloadlen);
	if (tcph == NULL) {
		return ERROR;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = sport;
	tcph->dest = dport;

	if (flags & TCP_FLAG_SYN)
		tcph->syn = TRUE;
	if (flags & TCP_FLAG_FIN)
		tcph->fin = TRUE;
	if (flags & TCP_FLAG_RST)
		tcph->rst = TRUE;
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	tcph->seq = htonl(seq);
	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(ack_seq);
	}

	tcph->window = htons(MIN(window, TCP_MAX_WINDOW));

	tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;
	ts = (uint32_t *)(tcpopt + 4);

	tcpopt[0] = TCP_OPT_NOP;
	tcpopt[1] = TCP_OPT_NOP;
	tcpopt[2] = TCP_OPT_TIMESTAMP;
	tcpopt[3] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(echo_ts);

	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
	}

#if TCP_CALCULATE_CHECKSUM
	tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
			TCP_HEADER_LEN + optlen + payloadlen, saddr, daddr);
#endif

	if (tcph->syn || tcph->fin) {
		payloadlen++;
	}

	return payloadlen;
}
/*----------------------------------------------------------------------------*/
int
SendTCPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;

	//ckf mod
	if(flags & TCP_FLAG_SACK)
		optlen = CalculateOptionSACKLength(cur_stream,flags);
	else
		optlen = CalculateOptionLength(flags);

	if (payloadlen > cur_stream->sndvar->mss + optlen) {
		TRACE_ERROR("Payload size exceeds MSS\n");
		return ERROR;
	}

	tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + payloadlen);
	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons(MIN((uint16_t)window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
	}

#if TCP_CALCULATE_CHECKSUM
	tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
			TCP_HEADER_LEN + optlen + payloadlen, 
			cur_stream->saddr, cur_stream->daddr);
#endif

	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}

		/* update retransmission timer if have payload */
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n", 
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
		AddtoRTOList(mtcp, cur_stream);
	}

	return payloadlen;
}
/*----------------------------------------------------------------------------*/
// static int
// FlushTCPSendingBuffer(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
// {
// 	struct tcp_send_vars *sndvar = cur_stream->sndvar;
// 	const uint32_t maxlen = sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK);
// 	uint8_t *data;
// 	uint32_t buffered_len;
// 	uint32_t seq;
// 	uint16_t len;
// 	int16_t sndlen;
// 	uint32_t window;
// 	int packets = 0;

// 	if (!sndvar->sndbuf) {
// 		TRACE_ERROR("Stream %d: No send buffer available.\n", cur_stream->id);
// 		assert(0);
// 		return 0;
// 	}

// 	SBUF_LOCK(&sndvar->write_lock);

// 	if (sndvar->sndbuf->len == 0) {
// 		packets = 0;
// 		goto out;
// 	}

// 	window = MIN(sndvar->cwnd, sndvar->peer_wnd);

// 	while (1) {
// 		seq = cur_stream->snd_nxt;

// 		if (TCP_SEQ_LT(seq, sndvar->sndbuf->head_seq)) {
// 			TRACE_ERROR("Stream %d: Invalid sequence to send. "
// 					"state: %s, seq: %u, head_seq: %u.\n", 
// 					cur_stream->id, TCPStateToString(cur_stream), 
// 					seq, sndvar->sndbuf->head_seq);
// 			assert(0);
// 			break;
// 		}
// 		buffered_len = sndvar->sndbuf->head_seq + sndvar->sndbuf->len - seq;
// 		if (cur_stream->state > TCP_ST_ESTABLISHED) {
// 			TRACE_FIN("head_seq: %u, len: %u, seq: %u, "
// 					"buffered_len: %u\n", sndvar->sndbuf->head_seq, 
// 					sndvar->sndbuf->len, seq, buffered_len);
// 		}
// 		if (buffered_len == 0)
// 			break;

// 		data = sndvar->sndbuf->head + 
// 				(seq - sndvar->sndbuf->head_seq);

// 		if (buffered_len > maxlen) {
// 			len = maxlen;
// 		} else {
// 			len = buffered_len;
// 		}
		
// 		if (len <= 0)
// 			break;

// 		if (cur_stream->state > TCP_ST_ESTABLISHED) {
// 			TRACE_FIN("Flushing after ESTABLISHED: seq: %u, len: %u, "
// 					"buffered_len: %u\n", seq, len, buffered_len);
// 		}

// 		if (seq - sndvar->snd_una + len > window) {
// 			/* Ask for new window advertisement to peer */
// 			if (seq - sndvar->snd_una + len > sndvar->peer_wnd) {
// #if 0
// 				TRACE_CLWND("Full peer window. "
// 						"peer_wnd: %u, (snd_nxt-snd_una): %u\n", 
// 						sndvar->peer_wnd, seq - sndvar->snd_una);
// #endif
// 				if (TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500) {
// 					EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
// 				}
// 			}
// 			packets = -3;
// 			goto out;
// 		}
	
// 		sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts, 
// 				TCP_FLAG_ACK, data, len);
// 		if (sndlen < 0) {
// 			packets = sndlen;
// 			goto out;
// 		}
// 		packets++;
// 	}

//  out:
// 	SBUF_UNLOCK(&sndvar->write_lock);
// 	return packets;
// }
/*----------------------------------------------------------------------------*/

//ckf mod
static int
FlushTCPSendingBuffer(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	const uint32_t maxlen = sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK);
	uint8_t *data;
	uint32_t buffered_len;
	uint32_t seq;
	uint16_t len;
	int16_t sndlen;
	uint32_t window;
	int packets = 0;
	//ckf mod
	struct sackhole* p;
	int sack_bytes_rexmit = 0;
	int awnd = 0;

	if (!sndvar->sndbuf) {
		TRACE_ERROR("Stream %d: No send buffer available.\n", cur_stream->id);
		assert(0);
		return 0;
	}

	SBUF_LOCK(&sndvar->write_lock);

	if (sndvar->sndbuf->len == 0) {
		packets = 0;
		goto out;
	}

	window = MIN(sndvar->cwnd, sndvar->peer_wnd);

	if(sndvar->in_fast_recovery ==1){
		while(1){
			// if(sndvar->isFR_ackset_rx == 0 ){
			// 	seq = cur_stream->snd_nxt;
			// 	sndvar->isFR_ackset_rx = 1;
			// 	len = maxlen;
			// }
///////////// gurantee that first segment should be retransmitted in FR(aka snd_una) is the head of hole,so 
			//no need to test
			
			if(p = NextUnSackSeg(cur_stream,&sack_bytes_rexmit)){
				if(TCP_SEQ_GT(p->end,sndvar->recovery_end)){

					//the hole beyond recovery point,cant not retransmit
					if(TCP_SEQ_GEQ(p->rxmit, sndvar->recovery_end)){
						break;
					}
					else{//can rexmit part of the hole
						seq = p->rxmit;
						//////////
						 len = sndvar->recovery_end - p->rxmit;
					}
				}
				else{
					seq = p->rxmit;
					len = p->end - p->rxmit;
				}
			}
			else// no hole to send , can trasmit new data
				break;
			

			if (TCP_SEQ_LT(seq, sndvar->sndbuf->head_seq)) {
			TRACE_ERROR("Stream %d: Invalid sequence to send. "
					"state: %s, seq: %u, head_seq: %u.\n", 
					cur_stream->id, TCPStateToString(cur_stream), 
					seq, sndvar->sndbuf->head_seq);
			assert(0);
			break;
			}
			buffered_len = sndvar->sndbuf->head_seq + sndvar->sndbuf->len - seq;
			if (cur_stream->state > TCP_ST_ESTABLISHED) {
				TRACE_FIN("head_seq: %u, len: %u, seq: %u, "
						"buffered_len: %u\n", sndvar->sndbuf->head_seq, 
						sndvar->sndbuf->len, seq, buffered_len);
			}
			if (buffered_len == 0)
				break;

			data = sndvar->sndbuf->head + 
					(seq - sndvar->sndbuf->head_seq);

			len = len > maxlen ? maxlen : len;
			len = len > buffered_len ? buffered_len : len;

			if (len <= 0)
				break;

			f (cur_stream->state > TCP_ST_ESTABLISHED) {
				TRACE_FIN("Flushing after ESTABLISHED: seq: %u, len: %u, "
						"buffered_len: %u\n", seq, len, buffered_len);
			}

			awnd = SetPipe(cur_stream);
			if (awnd + len > window) {
				/* Ask for new window advertisement to peer */
				if (seq - sndvar->snd_una + len > sndvar->peer_wnd) {
					if (TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500) {
						EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
					}
				}
				packets = -3;
				goto out;	//can not transmit anything
			}
	
		sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts, 
				TCP_FLAG_ACK, data, len);
		if (sndlen < 0) {
			packets = sndlen;
			goto out;
		}
		
		packets++;
		p->rxmit += len;
		sndvar->sackhint.sack_bytes_rexmit += len;
		}

	}

	//trasmit new data

	while (1) {
		seq = cur_stream->snd_nxt;

		if(sndvar->in_fast_recovery ==1){
			if(sndvar->isFR_ackset_rx == 0){
				seq = cur_stream->snd_nxt;
				sndvar->isFR_ackset_rx = 1;
			}
			else
			{
				if((p = NextUnSackSeg(cur_stream,&sack_bytes_rexmit)));
					seq = p->rxmit;
			}
		}

		if (TCP_SEQ_LT(seq, sndvar->sndbuf->head_seq)) {
			TRACE_ERROR("Stream %d: Invalid sequence to send. "
					"state: %s, seq: %u, head_seq: %u.\n", 
					cur_stream->id, TCPStateToString(cur_stream), 
					seq, sndvar->sndbuf->head_seq);
			assert(0);
			break;
		}
		buffered_len = sndvar->sndbuf->head_seq + sndvar->sndbuf->len - seq;
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("head_seq: %u, len: %u, seq: %u, "
					"buffered_len: %u\n", sndvar->sndbuf->head_seq, 
					sndvar->sndbuf->len, seq, buffered_len);
		}
		if (buffered_len == 0)
			break;

		data = sndvar->sndbuf->head + 
				(seq - sndvar->sndbuf->head_seq);

		if (buffered_len > maxlen) {
			len = maxlen;
		} else {
			len = buffered_len;
		}
		
		if (len <= 0)
			break;

		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Flushing after ESTABLISHED: seq: %u, len: %u, "
					"buffered_len: %u\n", seq, len, buffered_len);
		}

		if (seq - sndvar->snd_una + len > window) {
			/* Ask for new window advertisement to peer */
			if (seq - sndvar->snd_una + len > sndvar->peer_wnd) {
#if 0
				TRACE_CLWND("Full peer window. "
						"peer_wnd: %u, (snd_nxt-snd_una): %u\n", 
						sndvar->peer_wnd, seq - sndvar->snd_una);
#endif
				if (TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500) {
					EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
				}
			}
			packets = -3;
			goto out;
		}
	
		sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts, 
				TCP_FLAG_ACK, data, len);
		if (sndlen < 0) {
			packets = sndlen;
			goto out;
		}
		packets++;
	}

 out:
	SBUF_UNLOCK(&sndvar->write_lock);
	return packets;
}

static inline int 
SendControlPacket(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int ret = 0;

	if (cur_stream->state == TCP_ST_SYN_SENT) {
		/* Send SYN here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_SYN, NULL, 0);

	} else if (cur_stream->state == TCP_ST_SYN_RCVD) {
		/* Send SYN/ACK here */
		cur_stream->snd_nxt = sndvar->iss;
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
				TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_ESTABLISHED) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSE_WAIT) {
		/* Send ACK for the FIN here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_LAST_ACK) {
		/* if it is on ack_list, send it after sending ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			/* Send FIN/ACK here */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}
	} else if (cur_stream->state == TCP_ST_FIN_WAIT_1) {
		/* if it is on ack_list, send it after sending ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			/* Send FIN/ACK here */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}

	} else if (cur_stream->state == TCP_ST_FIN_WAIT_2) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSING) {
		if (sndvar->is_fin_sent) {
			/* if the sequence is for FIN, send FIN */
			if (cur_stream->snd_nxt == sndvar->fss) {
				ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
			} else {
				ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_ACK, NULL, 0);
			}
		} else {
			/* if FIN is not sent, send fin with ack */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}

	} else if (cur_stream->state == TCP_ST_TIME_WAIT) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSED) {
		/* Send RST here */
		TRACE_DBG("Stream %d: Try sending RST (TCP_ST_CLOSED)\n", 
				cur_stream->id);
		/* first flush the data and ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_RST, NULL, 0);
			if (ret >= 0) {
				DestroyTCPStream(mtcp, cur_stream);
			}
		}
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPControlList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	thresh = MIN(thresh, sender->control_list_cnt);

	/* Send TCP control messages */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->control_list);
	last = TAILQ_LAST(&sender->control_list, control_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside control loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->control_link);

		TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
		sender->control_list_cnt--;

		if (cur_stream->sndvar->on_control_list) {
			cur_stream->sndvar->on_control_list = FALSE;
			//TRACE_DBG("Stream %u: Sending control packet\n", cur_stream->id);
			ret = SendControlPacket(mtcp, cur_stream, cur_ts);
			if (ret < 0) {
				TAILQ_INSERT_HEAD(&sender->control_list, 
						cur_stream, sndvar->control_link);
				cur_stream->sndvar->on_control_list = TRUE;
				sender->control_list_cnt++;
				/* since there is no available write buffer, break */
				break;
			}
		} else {
			TRACE_ERROR("Stream %d: not on control list.\n", cur_stream->id);
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPDataList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	/* Send data */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->send_list);
	last = TAILQ_LAST(&sender->send_list, send_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside send loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->send_link);

		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		if (cur_stream->sndvar->on_send_list) {
			ret = 0;

			/* Send data here */
			/* Only can send data when ESTABLISHED or CLOSE_WAIT */
			if (cur_stream->state == TCP_ST_ESTABLISHED) {
				if (cur_stream->sndvar->on_control_list) {
					/* delay sending data after until on_control_list becomes off */
					//TRACE_DBG("Stream %u: delay sending data.\n", cur_stream->id);
					ret = -1;
				} else {
					ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
				}
			} else if (cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_LAST_ACK) {
				ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
			} else {
				TRACE_DBG("Stream %d: on_send_list at state %s\n", 
						cur_stream->id, TCPStateToString(cur_stream));
#if DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}

			if (ret < 0) {
				TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
				/* since there is no available write buffer, break */
				break;

			} else {
				cur_stream->sndvar->on_send_list = FALSE;
				sender->send_list_cnt--;
				/* the ret value is the number of packets sent. */
				/* decrease ack_cnt for the piggybacked acks */
#if ACK_PIGGYBACK
				if (cur_stream->sndvar->ack_cnt > 0) {
					if (cur_stream->sndvar->ack_cnt > ret) {
						cur_stream->sndvar->ack_cnt -= ret;//ckf attention
					} else {
						cur_stream->sndvar->ack_cnt = 0;
					}
				}
#endif
#if 1
				if (cur_stream->control_list_waiting) {
					if (!cur_stream->sndvar->on_ack_list) {
						cur_stream->control_list_waiting = FALSE;
						AddtoControlList(mtcp, cur_stream, cur_ts);
					}
				}
#endif
			}
		} else {
			TRACE_ERROR("Stream %d: not on send list.\n", cur_stream->id);
#ifdef DUMP_STREAM
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPACKList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int to_ack;
	int cnt = 0;
	int ret;

	/* Send aggregated acks */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->ack_list);
	last = TAILQ_LAST(&sender->ack_list, ack_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside ack loop. cnt: %u\n", cnt);
		next = TAILQ_NEXT(cur_stream, sndvar->ack_link);

		if (cur_stream->sndvar->on_ack_list) {
			/* this list is only to ack the data packets */
			/* if the ack is not data ack, then it will not process here */
			to_ack = FALSE;
			if (cur_stream->state == TCP_ST_ESTABLISHED || 
					cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_FIN_WAIT_2 || 
					cur_stream->state == TCP_ST_TIME_WAIT) {
				/* TIMEWAIT is possible since the ack is queued 
				   at FIN_WAIT_2 */
				if (cur_stream->rcvvar->rcvbuf) {
					if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, 
								cur_stream->rcvvar->rcvbuf->head_seq + 
								cur_stream->rcvvar->rcvbuf->merged_len)) {
						to_ack = TRUE;
					}
				}
			} else {
				TRACE_DBG("Stream %u (%s): "
						"Try sending ack at not proper state. "
						"seq: %u, ack_seq: %u, on_control_list: %u\n", 
						cur_stream->id, TCPStateToString(cur_stream), 
						cur_stream->snd_nxt, cur_stream->rcv_nxt, 
						cur_stream->sndvar->on_control_list);
#ifdef DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}

			if (to_ack) {
				/* send the queued ack packets */
				//ckf mod
				int i  = 0;
				while (i <  cur_stream->sndvar->ack_cnt ) {

					if(cur_stream->rcvvar->ack_cnt_to_sack_opt[i] == 1){
						ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK|TCP_FLAG_SACK), NULL, 0);
						cur_stream->rcvvar->ack_cnt_to_sack_opt[i] = 0;
					}
					else
						ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK, NULL, 0);

					
					if (ret < 0) {
						/* since there is no available write buffer, break */
						break;
					}
					i++;
				}
				cur_stream->sndvar->ack_cnt = 0;

				/* if is_wack is set, send packet to get window advertisement */
				if (cur_stream->sndvar->is_wack) {
					cur_stream->sndvar->is_wack = FALSE;
					ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK | TCP_FLAG_WACK, NULL, 0);
					if (ret < 0) {
						/* since there is no available write buffer, break */
						cur_stream->sndvar->is_wack = TRUE;
					}
				}

				if (!(cur_stream->sndvar->ack_cnt || cur_stream->sndvar->is_wack)) {
					cur_stream->sndvar->on_ack_list = FALSE;
					TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
					sender->ack_list_cnt--;
				}
			} else {
				cur_stream->sndvar->on_ack_list = FALSE;
				cur_stream->sndvar->ack_cnt = 0;
				cur_stream->sndvar->is_wack = 0;
				TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
				sender->ack_list_cnt--;
			}

			if (cur_stream->control_list_waiting) {
				if (!cur_stream->sndvar->on_send_list) {
					cur_stream->control_list_waiting = FALSE;
					AddtoControlList(mtcp, cur_stream, cur_ts);
				}
			}
		} else {
			TRACE_ERROR("Stream %d: not on ack list.\n", cur_stream->id);
			TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
			sender->ack_list_cnt--;
#ifdef DUMP_STREAM
			thread_printf(mtcp, mtcp->log_fp, 
					"Stream %u: not on ack list.\n", cur_stream->id);
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last)
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline struct mtcp_sender *
GetSender(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	if (cur_stream->sndvar->nif_out < 0) {
		return mtcp->g_sender;

	} else if (cur_stream->sndvar->nif_out >= CONFIG.eths_num) {
		TRACE_ERROR("(NEVER HAPPEN) Failed to find appropriate sender.\n");
		return NULL;

	} else {
		return mtcp->n_sender[cur_stream->sndvar->nif_out];
	}
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
#if TRY_SEND_BEFORE_QUEUE
	int ret;
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	ret = SendControlPacket(mtcp, cur_stream, cur_ts);
	if (ret < 0) {
#endif
		if (!cur_stream->sndvar->on_control_list) {
			struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
			assert(sender != NULL);

			cur_stream->sndvar->on_control_list = TRUE;
			TAILQ_INSERT_TAIL(&sender->control_list, cur_stream, sndvar->control_link);
			sender->control_list_cnt++;
			//TRACE_DBG("Stream %u: added to control list (cnt: %d)\n", 
			//		cur_stream->id, sender->control_list_cnt);
		}
#if TRY_SEND_BEFORE_QUEUE
	} else {
		if (cur_stream->sndvar->on_control_list) {
			cur_stream->sndvar->on_control_list = FALSE;
			TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
			sender->control_list_cnt--;
		}
	}
#endif
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if(!cur_stream->sndvar->sndbuf) {
		TRACE_ERROR("[%d] Stream %d: No send buffer available.\n", 
				mtcp->ctx->cpu,
				cur_stream->id);
		assert(0);
		return;
	}

	if (!cur_stream->sndvar->on_send_list) {
		cur_stream->sndvar->on_send_list = TRUE;
		TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
		sender->send_list_cnt++;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (!cur_stream->sndvar->on_ack_list) {
		cur_stream->sndvar->on_ack_list = TRUE;
		TAILQ_INSERT_TAIL(&sender->ack_list, cur_stream, sndvar->ack_link);
		sender->ack_list_cnt++;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_control_list) {
		cur_stream->sndvar->on_control_list = FALSE;
		TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
		sender->control_list_cnt--;
		//TRACE_DBG("Stream %u: Removed from control list (cnt: %d)\n", 
		//		cur_stream->id, sender->control_list_cnt);
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_send_list) {
		cur_stream->sndvar->on_send_list = FALSE;
		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		sender->send_list_cnt--;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_ack_list) {
		cur_stream->sndvar->on_ack_list = FALSE;
		TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
		sender->ack_list_cnt--;
	}
}
/*----------------------------------------------------------------------------*/

//ckf  add 
/*
when there is gap in rcv buffer,sack  options which describe 
the gaps must be generated(save from  sackblks)
*/
static inline void
RecordSACKOption(tcp_stream* cur_stream){
	if(cur_stream->rcvvar->sack_on ==1){
		struct sackoption* sackopt;
		if(batched_sackoption_num < MAX_BATCHED_SACKOPTION){
			cur_stream->rcvvar->sack_on = 0;
			sackopt = (struct sackoption*)malloc(sizeof(struct sackoption));
			if(sackopt){
				memcpy(sackopt,cur_stream->rcvvar->sackblks,
					sizeof(struct sackblk)*MAX_SACK_BLKS);
				sackopt->sackblk_num = cur_stream->rcvvar->sackblk_num;
				TAILQ_INSERT_TAIL(&cur_stream->rcvvar->batched_sackoptions,
					sackopt,solink);
				cur_stream->rcvvar->ack_cnt_to_sack_opt[cur_stream->sndvar->ack_cnt]
				=1;

			}
		}
		else
			//print  error

		cur_stream->rcvvar->sack_on = 0;
	}
}

inline void 
EnqueueACK(mtcp_manager_t mtcp, 
		tcp_stream *cur_stream, uint32_t cur_ts, uint8_t opt)
{
	if (!(cur_stream->state == TCP_ST_ESTABLISHED || 
			cur_stream->state == TCP_ST_CLOSE_WAIT || 
			cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2)) {
		TRACE_DBG("Stream %u: Enqueueing ack at state %s\n", 
				cur_stream->id, TCPStateToString(cur_stream));
	}

	if (opt == ACK_OPT_NOW) {
		if (cur_stream->sndvar->ack_cnt < cur_stream->sndvar->ack_cnt + 1) {
			//ckf mod
			RecordSACKOption(cur_stream);

			cur_stream->sndvar->ack_cnt++;
			
		}
	} else if (opt == ACK_OPT_AGGREGATE) {
		if (cur_stream->sndvar->ack_cnt == 0) {
			cur_stream->sndvar->ack_cnt = 1;
		}
	} else if (opt == ACK_OPT_WACK) {
		cur_stream->sndvar->is_wack = TRUE;
	}
	AddtoACKList(mtcp, cur_stream);
}
/*----------------------------------------------------------------------------*/
inline void 
DumpControlList(mtcp_manager_t mtcp, struct mtcp_sender *sender)
{
	tcp_stream *stream;

	TRACE_DBG("Dumping control list (count: %d):\n", sender->control_list_cnt);
	TAILQ_FOREACH(stream, &sender->control_list, sndvar->control_link) {
		TRACE_DBG("Stream id: %u in control list\n", stream->id);
	}
}

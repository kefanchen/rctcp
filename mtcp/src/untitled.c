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

	p = NULL;
	if(TCP_SEQ_GT(sndvar->snd_max,cur_stream->snd_nxt)) {
		
		while(1) {
			if(sndvar->in_fast_recovery == 0) {  //in RTO recovery

				if(cur_stream->snd_nxt == cur_stream->snd_una) { // first rxmit in RTO recovery
					seq = cur_stream->snd_una;
					len = maxlen;
				}
				else { //non-first in RTO recovery

					if(p = NextUnSackSeg(cur_stream,&sack_bytes_rexmit)){	//after RTO,receive sack
						if(TCP_SEQ_GT(p->end,sndvar->recovery_end)){

							//the hole beyond recovery point,cant not retransmit
							if(TCP_SEQ_GEQ(p->rxmit, sndvar->recovery_end)){
								break;
							}
							else{//can rexmit part of the hole
								seq = p->rxmit;
								len = sndvar->recovery_end - p->rxmit;
							}
						}
						else{
							seq = p->rxmit;
							len = p->end - p->rxmit;
						}
					}
					else {
						//after RTO,recieve ack without SACK,either recovery is finished all the left segment all lost
						if(TCP_SEQ_LT(cur_stream->snd_nxt,sndvar->recovery_end)) {
							// no sack, the left segment all lost,still need to retransmit
							seq = cur_stream->snd_nxt;
							len = maxlen;
						}
						else	//retansmit is over
							break;


					}

				}
			}

			else { // in fast recovery

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
			}

			//todo retransmit seq

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

			if (cur_stream->state > TCP_ST_ESTABLISHED) {
				TRACE_FIN("Flushing after ESTABLISHED: seq: %u, len: %u, "
						"buffered_len: %u\n", seq, len, buffered_len);
			}

			awnd = SetPipe(cur_stream);
			if (awnd + len > window) {
				/* Ask for new window advertisement to peer */
				if (awnd + len > sndvar->peer_wnd) {
					if (TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500) {
						EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
					}
				}
				packets = -3;
				goto out;	//can not transmit anything
			}
		
			cur_stream->snd_nxt = seq;
			sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_ACK, data, len);
			if (sndlen < 0) {
				packets = sndlen;
				goto out;
			}
			
			packets++;
			//ckf 2016/5/16
			if(p) { //need modify
				p->rxmit += len;
				sndvar->sackhint.sack_bytes_rexmit += len;
			}

		}

	}



// transmit previously unsent data
	while(1){
		seq = 
	}







	if(sndvar->in_fast_recovery ==1){
		while(1){

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

			if (cur_stream->state > TCP_ST_ESTABLISHED) {
				TRACE_FIN("Flushing after ESTABLISHED: seq: %u, len: %u, "
						"buffered_len: %u\n", seq, len, buffered_len);
			}

			awnd = SetPipe(cur_stream);
			if (awnd + len > window) {
				/* Ask for new window advertisement to peer */
				if (awnd + len > sndvar->peer_wnd) {
					if (TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500) {
						EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
					}
				}
				packets = -3;
				goto out;	//can not transmit anything
			}
		
		cur_stream->snd_nxt = seq;
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
		//ckf mod
		seq = cur_stream->snd_max;

		
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

		awnd = SetPipe(cur_stream);
		if (awnd + len > window) {
			/* Ask for new window advertisement to peer */
			if (awnd + len > sndvar->peer_wnd) {
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
		
		cur_stream->snd_nxt = seq;
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

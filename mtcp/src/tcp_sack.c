#include"tcp_sttream.h"

/*
 * when receive non-contiguous segment,need to update sackblks
 * per RFC 2018
 */

void
UpdateSACKBlks(tcp_stream* cur_stream,uint32_t rcv_start,uint32_t rcv_end){
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	struct sackblk head_blk,saved_blks[MAX_SACK_BLKS];

	int num_head,num_saved,i;

	assert(TCP_SEQ_LT(rcv_start,rcv_end));

	head_blk.start = rcv_start;
	head_blk.end = rcv_end;

	/*
	 * merge sackblks into head_blk,and save unchanged sackblk into 
	 * saved[]
	 */
	num_saved = 0;
	for(i = 0;i<rcvvar->sackblk_num)
	{
		uint32_t start = rcvvar->sackblks[i].start;
		uint32_t end = rcvvar->sackblks[i].end;

		if(TCP_SEQ_GEQ(start,end) || TCP_SEQ_LEQ(start,cur_stream->rcv_nxt)){
			//discard
		}
		else if(TCP_SEQ_LEQ(head_blk.start,end)&&
				TCP_SEQ_GEQ(head_blk.end,start)){
			//headblk has something in common with sackblks[i]
			//merge they two
			if(TCP_SEQ_GT(head_blk.start,start))
				head_blk.start = start;

			if(TCP_SEQ_LT(head_blk.end,end))
				head_blk.end = end;
		} else{
			//nothing in common,just save
			saved_blks[num_saved].start = start;
			saved_blks[num_saved].end = end;
			num_saved ++ ;
		}

	}
	//update rcvvar->sackblks
	
	num_head = 0;
	if(TCP_SEQ_GT(head_blk.start,cur_stream->rcv_nxt)){
		//put head_blk in the head of sackblks
		rcvvar->sackblks[0] = head_blk;
		num_head = 1;

		//if saved sack blocks' number exceed its limit,
		//discard the last one
		if(num_saved >= MAX_SACK_BLKS)
			num_saved--;
	}

	if(num_saved > 0){
		//copy the saved SACK blk back
		memcopy(&rcvvar->sackblks[numhead],saved_blks,sizeof(struct sackblks)
				 * num_saved);	
	}

	rcvvar->sackblk_num = numhead + num_saved;

}

//delete all receiver-side SACK information,sackblks
void
CleanSACKBlks(tcp_stream* cur_stream){

	int i;
	struct tcp_recv_vars* rcvvar = cur_stream->rcvvar;
	rcvvar->sackblk_num = 0;
	for(i=0; i<MAX_SACK_BLKS; i++)
		rcvvar->sackblks[i].start = rcvvar->sackblks[i].end = 0;

}

static struct sackhole* 
AllocSACKHole(tcp_stream* cur_stream,uint32_t start,uint32_t end){
	struct sackhole* hole;
	struct tcp_send_vars* sndvar = cur_stream->sndvar;

	if (sndvar->snd_numholes  >= MAX_HOLES){
		//Debug report?
		return NULL;
	}

	hole = (struct  sackhole*)calloc(1,sizeof(struct sackhole));
	if(hole == NULL)
		return NULL;

	hole->start = start;
	hole->end = end;
	hole->rxmit = start;

	sndvar->snd_numholes ++ ;
	
	return hole;
}

static void
FreeSACKHole(tcp_stream* cur_stream,struct sackhole* hole){

	free(hole);
	hole = 0;

	cur_stream->sndvar->snd_numholes -- ;
	assert(cur_stream->sndvar->snd_numholes>=0);
}


static struct sackhole*
InsertSACKHole(tcp_stream* cur_stream,uint32_t start,uint32_t end,
		struct sackhole* after){
	
	struct sackhole* hole;
	struct tcp_send_vars* sndvar = cur_stream->sndvar;

	hole = AllocSACKHole(cur_stream,start,end);
	if(hole == NULL)
		return NULL;

	if(after != NULL)
		TAILQ_INSERT_AFTER(&sndvar->snd_holes,after,hole,scblink);
	else
		TAILQ_INSERT_TAIL(&sndvar->snd_holes,hole,scblink);

	if(sndvar->sackhint.nexthole == NULL)
		sndvar->sackhint.nexthole = hole;

	return hole;
}

static void
RemoveSACKHole(tcp_stream* cur_stream,struct sackhole* hole){
	
	struct tcp_send_vars* sndvar = cur_stream->sndvar;

	if(sndvar->sackhint.nexthole == hole)
		sndvar->sackhint.nexthole = TAILQ_NEXT(hole,scblink);

	TAILQ_REMOVE(&sndvar->snd_holes,hole,scblink);
	FreeSACKHole(cur_stream,hole);
}

/* update scoreboard--snd_holes(sorted list) when receive sack
 * return 1 if incoming ack has previously unknown sack information
 * 0 otherwise
 * Note: We treat (snd_una, ack_seq) as a sack block so any changes
 * to that (i.e. left edge moving) would also be considered a change in SACK
 * information which is slightly different than rfc6675.
 */
int 
UpdateScoreBoard(tcp_stream* cur_stream,uint32_t ack_seq) {
	
	struct sackhole* cur,* temp;
	struct sackblk,sack_blocks[MAX_SACK_BLKS+1] *sblkp;
	struct tcp_send_vars* sndvar = cur_stream->sndvar;
	struct tcp_recv_vars* rcvvar = cur_stream->rcvvar;
	int i, j, num_sack_blks, sack_changed;

	num_sack_blks = 0;
	sack_changed = 0;

	/*if snd.una will be advanced by ack_seq,and if sack holes exist,
	 * treat (snd_una,ack_seq) as if it is a sack blocks
	 */

	 if(TCP_SEQ_LT(sndvar->snd_una,ack_seq)&&
			 !TAILQ_EMPTY(&sndvar->snd_holes)){//ckf attention,snd_una when to update?
		sack_blocks[num_sack_blks].start = sndvar->snd_una;
		sack_blocks[num_sack_blks++].end = ack_seq;/////attention
	}

	/*append received sack blocks which is non-contiguous
	 * and above snd_nua
	 * to sack_blocks[]
	 */

	 sndvar->sackhint.sacked_bytes = 0; //reset
	 for(i=0; i<rcvvar->sackblk_num_peer; i++){
		sack = rcvvar->sackblks_from_peer[i];

		if(TCP_SEQ_GT(sack.end,sack.start)&&
				TCP_SEQ_GT(sack.start,sndvar->snd_una)&&
				TCP_SEQ_GT(sack.start,ack_seq)&&
				TCP_SEQ_LT(sack.start,sndvar->snd_max)&&
				TCP_SEQ_GT(sack.end,sndvar->snd_una)&&
				TCP_SEQ_LEQ(sack.end,sndvar->snd_max)&&
				){
			sack_blocks[num_sack_blks++] = sack;
		sndvar->sackhint.sacked_bytes += (sack.end - sack.start);

	 	}
	}
	/*return if snd.una is not andvanced and no valid 
	 * SACK received
	 */

	 if(num_sack_blks == 0)
		 return (sack_changed);

	 /*sort the sack blocks so we can merge it with snd_holes
	 */

	for(i=0; i<num_sack_blks;i++){
		for(j=i+1;j<num_sack_blks;j++){
			if(TCP_SEQ_GT(sack_blocks[i].end,sack_blocks[j].end)){
				sack = sack_blocks[i];
				sack_blocks[i] = sack_blocks[j];
				sack_blocks[j] = sack;
			}

		}
	}

	if(TAILQ_EMPTY(&sndvar->snd_holes))
		sndvar->snd_fack = TCP_SEQ_MAX(sndvar->snd_una,ack_seq);

	/*use incoming SACK to update/merge snd_holes
	 */
	sblkp = &sack_blocks[num_sack_blks-1];
	sndvar->sackhint.last_sack_ack = sblkp->end;

	//decide the last sack in sack_blocks

	//the highest SACK block is beyond fack,apped new sack hole at tail
	if(TCP_SEQ_LT(sndvar->snd_fack,sblkp->start)){
		temp = InsertSACKHole(cur_stream,sndvar->snd_fack,sblkp->start,NULL);
		if(temp != NULL){
			sndvar->snd_fack = sblkp->end;
			sblkp -- ;
			sack_changed = 1;
		}
		else{
			/*failed to add a new hole
			 * skip sack blocks in the right 
			 * of snd_fack,use remaing sack 
			 * to update
			 */
			while(sblkp >= sack_blocks &&
					TCP_SEQ_LT(sndvar->snd_fack,sblkp->start))
				sblkp -- ;

			if(sblkp >= sack_blocks &&
					TCP_SEQ_LT(sndvar->snd_fack,sblkp->end))
				sndvar->snd_fack = sblkp->end;
		}
	}

	else if(TCP_SEQ_LT(sndvar->snd_fack,sblkp->end)){
		//fack is in the middle of sblkp,adance fack
		sndvar->snd_fack = sblkp->end;
		sack_changed = 1;
	}

	assert(!TAILQ_EMPTY(&sndvar->snd_holes));

	cur = TAILQ_LAST(&sndvar->snd_holes,sackhole_head);

	//finaly, update the scoreboard
	
	while(sblkp >= sack_blocks && cur != NULL){
		
		if(TCP_SEQ_GEQ(sblkp->start,cur->end)){
			sblkp--;
			continue;
		}

		if(TCP_SEQ_LEQ(sblkp->end,cur->start)){
			cur = TAILQ_PREV(cur,sackhole_head,scblink);
			continue;
		}

		sndvar->sackhint.sack_bytes_rexmit -= (cur->rxmit - cur->start);
		assert(sndvar->sackhint.sack_bytes_rexmit >= 0);

		sack_changed = 1;

		if(TCP_SEQ_LEQ(sblkp->start,cur->start)) {
			
			if(TCP_SEQ_GEQ(sblkp->end,cur->end)){
			//sack the hole ,delete the hole
			temp = cur;
			cur = TAILQ_PREV(cur,sackhole_head,scblink);
			RemoveSACKHole(cur_stream,temp);
			
			//the sack block may sack another hole
			continue;
			}
			else{
				cur->start = sblkp->end;
				cur->rxmit = TCP_SEQ_MAX(cur->rxmit,cur->start);
			}
			
		}
		else {
			
			if(TCP_SEQ_GEQ(sblkp->end,cur->end)){

				cur->end = sblkp->start;
				cur->rxmit = TCP_SEQ_MIN(cur->rxmit,cur->end);
			}
			else{
				
				/* sack some data in the middle
				 * of a hole,need to split the 
				 * current hole
				 */
				temp = InsertSACKHole(cur_stream,sblkp->end,cur->end,cur);
				if(temp != NULL){

					if(TCP_SEQ_GT(cur->rxmit,temp->rxmit)){
						temp->rxmit = cur->rxmit;
						sndvar->sackhint.sack_bytes_rexmit +=
							(temp->rxmit - temp->start);
					}
					cur->end = sblkp->start;
					cur->rxmit = TCP_SEQ_MIN(cur->rxmit,cur->end);
				}
			}
		}
		
		//for those who was rexmitted and just got sacked,exclude!
		//they are no longer in flight
		sndvar->sackhint.sack_bytes_rexmit += (cur->rxmit - cur=>start);

		if(TCP_SEQ_LEQ(sblkp->start, cur->start))
			cur = TAILQ_PREV(cur,sackhole_head,scblink);
		else
			sblkp -- ;

	}

	return (sack_changed);
}

// free all sack holes to clear scoreboard
void
FreeScoreBoard(tcp_stream* cur_stream){
	struct sackhole* q;
	struct tcp_send_vars* sndvar = cur_stream->sndvar;

	while((q = TAILQ_FIRST(&sndvar->sndholes))!=NULL)
		RemoveSACKHole(cur_stream,q);

	assert(sndvar->snd_numholes == 0);
	assert(sndvar->sackhint.nexthole == NULL);
}

//ckf  to do?
/* partial ACK ?
 */


/*
 * Returns the next hole to retransmit and the number of retransmitted bytes
 * from the scoreboard.  We store both the next hole and the number of
 * retransmitted bytes as hints (and recompute these on the fly upon SACK/ACK
 * reception).  This avoids scoreboard traversals completely.
 *
 * The loop here will traverse *at most* one link.  Here's the argument.  For
 * the loop to traverse more than 1 link before finding the next hole to
 * retransmit, we would need to have at least 1 node following the current
 * hint with (rxmit == end).  But, for all holes following the current hint,
 * (start == rxmit), since we have not yet retransmitted from them.
 * Therefore, in order to traverse more 1 link in the loop below, we need to
 * have at least one node following the current hint with (start == rxmit ==
 * end).  But that can't happen, (start == end) means that all the data in
 * that hole has been sacked, in which case, the hole would have been removed
 * from the scoreboard.
 */

struct sackhole*
NextUnSackSeg(tcp_stream* cur_stream,int *sack_bytes_rexmit){

	struct sackhole* hole = NULL;
	struct tcp_send_vars* sndvar = cur_stream->sndvar;

	*sack_bytes_rexmit = sndvar->sackhint.sack_bytes_rexmit;
	hole = sndvar->sackhint.nexthole;

	if(hole == NULL || TCP_SEQ_LT(hole->rxmit,hole->end))
		goto out;

	while((hole = TAILQ_NEXT(hole,scblink))!= NULL){
		if(TCP_SEQ_LT(hoel->rxmit,hole->end)){

			sndvar->sackhint.nexthole = hole;
			break;
		}
	}

out:
	return (hole);
}


/*
 * After a timeout, the SACK list may be rebuilt.  This SACK information
 * should be used to 
 *
 * avoid retransmitting SACKed data.
 *
 * This function 
 * traverses the SACK list to see if snd_nxt should be moved forward.
 */
//ckf need reconsideration
void
tcp_sack_adjust(tcp_stream * cur_stream){
	
	struct tcp_send_vars* sndvar = cur_stream->sndvar;
	struct sackhole* p,* cur = TAILQ_FIRST(&sndvar->snd_holes);

	if(cur == NULL)
		return;
	if(TCP_SEQ_GEQ(cur_stream->snd_nxt,sndvar->snd_fack))
		return ;

	/*-
	 * Two cases for which we want to advance snd_nxt:
	 * i) snd_nxt lies between end of one hole and beginning of another
	 * ii) snd_nxt lies between end of last hole and snd_fack
	 */
	while((p = TAILQ_NEXT(cur,scblink))!=NULL){
		
		if(TCP_SEQ_LT(cur_stream->snd_nxt,cur->end))
			return;

		if(TCP_SEQ_GEQ(cur_stream->snd_nxt,p->start))
			cur = p;
		else{
			cur_stream->snd_nxt = p->start;
			return ;
		}
	}

	if(TCP_SEQ_LT(cur_stream->snd_nxt,cur->end))
		return;
	cur_stream->snd_nxt = sndvar->snd_fack;

}

int
SetPipe(tcp_stream* cur_stream){
	struct tcp_send_vars* sndvar = cur_stream->sndvar;
	return (sndvar->snd_max - sndvar->snd_una +
		sndvar->sackhint.sack_bytes_rexmit -
		sndvar->sackhint.sacked_bytes);
}
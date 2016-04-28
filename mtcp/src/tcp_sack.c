#include"tcp_sttream.h"

/*
 * when receive non-contiguous segment,need to update sackblks
 * per RFC 2018
 */

void
UpdateSACKBlks(tcp_stream* cur_stream,uint32_t rcv_start,uint32_t rcv_end){
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	struct head_blk,saved_blks[MAX_SACK_BLKS];

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
CleanSACKBlks(struct tcp_stream* cur_stream){

	int i;
	struct tcp_recv_vars* rcvvar = cur_stream->rcvvar;
	rcvvar->sackblk_num = 0;
	for(i=0; i<MAX_SACK_BLKS; i++)
		rcvvar->sackblks[i].start = rcvvar->sackblks[i].end = 0;

}

static struct sackhole* 
AllocSACKHole(struct tcp_stream* cur_stream,uint32_t start,uint32_t end){
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
FreeSACKHole(struct tcp_stream* cur_stream,struct sackhole* hole){

	free(hole);
	hole = 0;

	cur_stream->sndvar->snd_numholes -- ;
	assert(cur_stream->sndvar->snd_numholes>=0);
}


static struct sackhole*
InsertSACKHole(struct tcp_stream* cur_stream,uint32_t start,uint32_t end,
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
RemoveSACKHole(struct tcp_stream* cur_stream,struct sackhole* hole){
	
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
UpdateScoreBoard(struct tcp_stream* cur_stream,uint32_t ack_seq) {
	
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

	 sndvar->sackhint.sacked_bytes = 0; //reset
	 for(i=0; i<sackblk_num_peer; i++){
		 
	 }

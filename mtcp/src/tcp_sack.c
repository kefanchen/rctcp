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

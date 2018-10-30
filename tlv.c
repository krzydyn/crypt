/*!
	\file
	\author Krzysztof Dynowski
	\brief Manipulations on tags (TLV)
*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "tlv.h"

/*
 TLV stands for Tag Length Value

 Tag Coding
  byte 0 of tag is coded:
    bit
    7 6 5 4 3 2 1 0
    0 0              universal class
    0 1              application class
    1 0              context-specific class
    1 1              private class
        0            primitive data object
        1            constructed data object
          1 1 1 1 1  see subsequent bytes
          x x x x x  tag number

  subsequent bytes of tag is coded:
    bit
    7 6 5 4 3 2 1 0
    0                last byte of tag
    1                another byte follows
      x x x x x x x  (part of) tag number

Length Coding
  byte 0
    bit7   0  length is coded on bits 6-0
           1  length is coded on subsequent (bits 6-0) bytes

Examples of tag coding:
	0x81: context class,primitive (EMV, Amount Binary)
0x9f02: context class,primitive,subsequent (EMV, Amount Numeric)

generally:
0x00-0x1e:      (30 tags) universal class, primitive
0x1f00-0x1f7f: (127 tags) universal class, primitive
0x20-0x3e:      (30 tags) universal class, constructed
0x3f00-0x3f7f: (127 tags) universal class, constructed
0x40-0x5e:      (30 tags) application class, primitive
0x5f00-0x5f7f: (127 tags) application class, primitive
0x60-0x7e:      (30 tags) application class, constructed
0x7f00-0x7f7f: (127 tags) application class, constructed
0x80-0x9e:      (30 tags) context-specific class, primitive
0x9f00-0x9f7f: (127 tags) context-specific class, primitive
0xa0-0xbe:      (30 tags) context-specific class, constructed
0xbf00-0xbf7f: (127 tags) context-specific class, constructed
0xc0-0xde:      (30 tags) private class, primitive
0xdf00-0xdf7f: (127 tags) private class, primitive
0xe0-0xfe:      (30 tags) private class, constructed
0xff00-0xff7f: (127 tags) private class, constructed

Implementation Note:
  1. tags 0x00... and 0xff... are invalid (caused by EMV filling method, 0x00 on begin and 0xff on the end)
  2. tag length 0 is invalid
  3. tags spectrum:
  	when coded on 2 bytes:
  		primitive:    (127+30)*4 = 628
  		constructed:  (127+30)*4 = 628
  	otherwise infinite
*/

/*!
    \brief get "tag zero" byte from tag
    \param tag tag ID
    \return "tag zero" byte
*/
int tlv_tag0(ushort tag)
{
  if (tag > 0xff) tag>>=8;
  return tag;
}

/*!
    \brief parse binary buffer into tag
    \param rbuf binary buffer
    \param rlen binary buffer length
    \param tag pointer to tag ID
    \return -1 negative rlen, 0 no data in rbuf, otherwise number of parsed bytes
*/
int tlv_tag(const uchar xdata *rbuf, int rlen, ushort xdata *tag)
{
  int i=0,j;
  if (rlen<0) return -1;

  while (i < rlen && rbuf[i]==0x00) i++;
  if (i == rlen) return 0;

  *tag=rbuf[j=i];
  if ((rbuf[i]&TAG_SEQ) == TAG_SEQ)
  {
    do
      { i++; *tag <<= 8; *tag |= rbuf[i]; }
    while(i < rlen && (rbuf[i]&TAG_NEXT) != 0);
    if (i >= rlen || (rbuf[i]&TAG_NEXT) != 0)
    {
      DEBUG1(dbgprn("tag=%x short buf, i=%d >= rlen=%d\n",*tag,i,rlen);)
      return -1;
    }
  }
  i++;
  if (i-j > 2) { DEBUG1(dbgprn("tag=%02x.. bytes %d\n",*tag,i-j);) *tag=0; }
  return i;
}

/*!
    \brief parse binary buffer into tag,length,value
    \param rbuf binary buffer
    \param rlen binary buffer length
    \param tlv pointer to tlv structure
    \return -1 negative rlen, 0 no data in rbuf, 1 success
*/
int tlv_tlv0(const uchar xdata *rbuf, int rlen, TLV xdata *tlv)
{
  int i;
  if ((i=tlv_tag(rbuf,rlen,&tlv->t)) <= 0) return i;
  rlen -= i; rbuf+=i;
  if (rlen <= 0)
    { DEBUG1(dbgprn("tag=%x short buf, rlen=%d\n",tlv->t,rlen);) return -1; }

  tlv->l=i=*rbuf;
  rbuf++; rlen--;
  if (i&LEN_BYTES)
  {
    i&=0x7f;
    if (i > rlen)
      { DEBUG1(dbgprn("tag=%x short buf, i=%d > rlen=%d\n",tlv->t,i,rlen);) return -1; }
    if (i > 2)
      { DEBUG1(dbgprn("tag=%x length bytes %d\n",tlv->t,i);) return -2; }
    rlen -= i;
    for (tlv->l=0; i > 0; i--)
      { tlv->l <<= 8; tlv->l |= *rbuf++; }
  }
  tlv->v = (uchar*)rbuf;
  return 1;
}

/*!
    \brief parse binary buffer into tag,length,value (with checking length)
    \param rbuf binary buffer
    \param rlen binary buffer length
    \param tlv pointer to tlv structure
    \return -1 or 0 failure, 1 success
*/
int tlv_parseTLV(const uchar xdata *rbuf, int rlen, TLV xdata *tlv)
{
  int i;
  if ((i=tlv_tlv0(rbuf,rlen,tlv)) <= 0) return i;
  rlen -= tlv->v-rbuf;
  if (tlv->l > rlen)
  {
    DEBUG1(dbgprn("tag=%x len=%d > rlen=%d\n",tlv->t,tlv->l,rlen);)
    return -1;
  }
  return 1;
}

/*!
    \brief parse ascii buffer into length,tag,value (with checking length)
    \param rbuf binary buffer
    \param rlen binary buffer length
    \param tlv pointer to tlv structure
    \return -1 failure, 1 success
*/
int tlv_parseLTV(const uchar xdata *rbuf, int rlen, TLV xdata *tlv)
{
	unsigned x;
  if (rlen < 6) return -1;
  if (sscanf(castptr(char*,rbuf),"%04u",&x)!=1) return -1;
	tlv->l=x;
  if (sscanf(castptr(char*,rbuf),"%02u",&x)!=1) return -1;
	tlv->t=x;
  if (tlv->l < 2) return -1;
  tlv->v=(uchar*)rbuf+6; tlv->l-=2;
  rlen -= tlv->v-rbuf;
  if (tlv->l > rlen)
  {
    DEBUG1(dbgprn("tag=%x len=%d > rlen=%d\n",tlv->t,tlv->l,rlen);)
    return -1;
  }
  return 1;
}

/*!
    \brief build tag into buffer
    \param rbuf binary buffer
    \param rlen binary buffer length
    \param tag tag ID
    \return 0 wrong tag, otherwise number of parsed bytes
*/
int tlv_buildT(uchar xdata *rbuf, int rlen, ushort tag)
{
	uchar *b;
  if ((tag <= 0xff && (tlv_tag0(tag)&TAG_SEQ)==TAG_SEQ) ||
      (tag > 0xff && (tag&TAG_NEXT)!=0) || tag==0)
    { DEBUG1(dbgprn("tag=%02x WRONG\n",tag);) return 0; }
  b=rbuf;
  if (tag > 0xff) *b++=tag>>8;
  *b++=tag;
  return b-rbuf;
}

/*!
    \brief find tag in binary buffer (TLV structured)
    \param b buffer to search
    \param l buffer length
    \param tag requested tag ID
    \param tlv pointer to output TLV structure
    \return 0 there is no tag in buffer, tlv filled with 0; 1 tag found
*/
int tlv_find(const uchar xdata *b, int l, ushort tag, TLV xdata *tlv)
{
  TLV t;
  if (tag==0) return 0;
  while (tlv_parseTLV(b, l, &t) > 0)
  {
    if (t.t == tag)
      { if (tlv!=NULL) memcpy((char*)tlv,(char*)(&t),sizeof(TLV)); return 1; }
    t.v += t.l;
    l -= t.v - b; b = t.v;
  }
  if (tlv!=NULL) { memset((char*)tlv,0,sizeof(TLV)); tlv->t=tag; }
  return 0;
}

/*!
    \brief find tag in binary buffer (LTV structured)
    \param b buffer to search
    \param l buffer size
    \param tag requested tag identifier
    \param tlv output tlvbuf to fill
    \return 1 on succes, else 0

    If tlv param is NULL, then this function doesn't copy any data to it.
*/
int ltv_find(const uchar xdata *b, int l, ushort tag, TLV xdata *tlv)
{
  TLV t;
  while (tlv_parseLTV(b, l, &t) > 0)
  {
    if (t.t == tag)
      { if (tlv!=NULL) memcpy((char*)tlv,(char*)(&t),sizeof(TLV)); return 1; }
    t.v += t.l;
    l -= t.v - b; b = t.v;
  }
  if (tlv!=NULL) { memset((char*)tlv,0,sizeof(TLV)); tlv->t=tag; }
  return 0;
}

/*!
    \brief print TLV information (for debug purposes)
    \param tlv pointer to TLV structure to print
*/
void tlv_print(TLV xdata *tlv)
{
  int i,t=0;
  uchar xdata *b=tlv->v;
  if (tlv->l&0x8000) {printf("%4x[%2u]: too long",tlv->t,tlv->l);return;}
  printf("%4x[%2u]: ",tlv->t,tlv->l);
  if (tlv->l <= 1) t+=tlv->l;
  else for (i=0; i < tlv->l; i++) { if (b[i]<0x20||b[i]>=0x7f) t++; }
  //if (2*t<tlv->l) pprintvisn(b,tlv->l); else pprinthexn(b,tlv->l);
  printf("\n");
}

/*!
    \brief find tag on TLVbuf buffer
    \param tb TLVbuf to search
    \param tag requested tag identifier
    \param tlv output tlvbuf to fill
    \return 1 on succes, else 0

    If tlv param is NULL, then this function doesn't copy any data to it.
*/
int tb_find(const TLVbuf xdata *tb, ushort tag, TLV xdata *tlv)
{
  return tlv_find(tb->buf,tb->len,tag,tlv);
}

/*!
    \brief delete tag from TLVbuf buffer
    \param tb pointer to TLVbuf structure
    \param t tag to delete
    \return 0 - there is no t, 1 - success
*/
int tb_del(TLVbuf xdata *tb, ushort t)
{
  TLV tlv;
  DEBUG2(dbgprn("tb_del(%x)\n",t);)
  if (!tb_find(tb,t,&tlv)) { DEBUG2(dbgprintf("not found\n");) return 0; }
  DEBUG2(dbgprintf("found, deleting\n");)
  if (tlv.l > 0x7f) { tlv.l++; tlv.v--; }
  if (tlv.l > 0xff) { tlv.l++; tlv.v--; }
  tlv.l+=2; tlv.v-=2;
  if (tlv.t > 0xff) { tlv.l++; tlv.v--; }
  memcpy(tlv.v,tlv.v+tlv.l,tb->buf+tb->len-(tlv.v+tlv.l));
  tb->len -= tlv.l;
  return 1;
}

/*!
    \brief append tag to TLVbuf buffer
    \param tb pointer to TLVbuf structure
    \param tlv pointer to TLV structure to add
    \param ovr 0=don't overwrite(return -EEXIST), 1=do overwrite,
               2=don't overwrite(return 0), 3=append
    \return
    \retval 0 - success, but tag not added to collection (if ovr=2)
    \retval 1 - success, tag added to collection
    \retval -EEXIST - tag already exists in cllection
    \retval -EINVAL - invalid tag definition
*/
int tb_add(TLVbuf xdata *tb, TLV xdata *tlv,uchar ovr)
{
	TLV t;
  uchar xdata *b;

  if (tlv->l==0) { DEBUG1(dbgprn("tag=%02x len=0\n",tlv->t);) return -EINVAL; }
  if ((tlv->t <= 0xff && (tlv_tag0(tlv->t)&TAG_SEQ)==TAG_SEQ) ||
      (tlv->t > 0xff && (tlv->t&TAG_NEXT)!=0) || tlv->t==0)
    { DEBUG1(dbgprn("tag=%02x WRONG\n",tlv->t);) return -EINVAL; }

	if (ovr<3 && tb_find(tb,tlv->t,&t))
	{
		if (ovr==0) { DEBUG1(dbgprn("tag=%02x duplicated\n",tlv->t);) return -EEXIST; }
		else if (ovr==2) return 0;
		if (tlv->l==t.l)
		{
			if (tlv->v) memcpy(t.v,tlv->v,t.l); else memset(t.v,0,t.l);
			tlv->v=t.v; return 1;
		}
		tb_del(tb,tlv->t);
	}

  if (tb->len+tlv->l+2 >= tb->mlen)
    { DEBUG1(dbgprn("tag=%02x short buf, l=%d+%d >= len=%d\n",tlv->t,tb->len,tlv->l,tb->mlen);) return -EPIPE; }

  b = tb->buf+tb->len;
  if (tlv->t > 0xff) *b++=tlv->t>>8;
  *b++=tlv->t;

  if (tlv->l > 0xff) { *b++=0x82; *b++=tlv->l>>8; }
  else if (tlv->l > 0x7f) *b++=0x81;
  *b++=tlv->l;
  if (tlv->v) memcpy(b,tlv->v,tlv->l); else memset(b,0,tlv->l);
	tlv->v=b; b+=tlv->l; tb->len=b-tb->buf;
  return 1;
}

/*!
    \brief append binary buffer (TLV structured) to TLVbuf buffer
    \param tb pointer to TLVbuf structure
    \param b binary buffer with data to append
    \param l binary buffer length
    \param ovr 0=don't overwrite(error), 1=do overwrite, 2=don't overwrite(ok), 3=append
    \return negative - failure, number of append tlv structures
*/
int tb_addbuf(TLVbuf xdata *tb,const uchar xdata *b,int l,uchar ovr)
{
  TLV t;
  int i;
  while ((i=tlv_parseTLV(b,l,&t)) > 0)
  {
    t.v += t.l;
    l -= t.v - b; b = t.v;
    t.v -= t.l;
    if ((i=tb_add(tb,&t,ovr)) < 0) break;
  }
  if (i < 0) return i;
  return 0;
}

void tb_addtags(TLVbuf *dst,TLVbuf *src,uchar *buf,ushort len)
{
	TLV tlv;
	int i,r;
	for (i=0; i<len; i+=r)
	{
		if ((r=tlv_tag(buf+i,len-i,&tlv.t))<0) break;
		if (tb_find(src,tlv.t,&tlv)) tb_add(dst,&tlv,2);
	}
}

/*!
    \brief print all tags information from binary buffer (TLV structured) (for debug purposes)
    \param b pointer to binary buffer
    \param l binary buffer length
    \param n
*/
void priv_printtags(const uchar xdata *b, int l, int n) reentrant
{
  int i;
  TLV t;
  while (tlv_parseTLV(b,l,&t) > 0)
  {
    for (i=0; i < n; i++) printf("  ");
    if (tlv_tag0(t.t) & TAG_CONSTR)
    {
      printf("%02x[%u]: (constr)\n",t.t,t.l);
      #if ARCH == ARCH_ELITE
      DEBUG1(dbgprintf("priv_printtags: Warning;not tested region\n");)
      //priv_printtags(t.v,t.l,n+1);
      #else
      priv_printtags(t.v,t.l,n+1);
      #endif
    }
    else tlv_print(&t);
    t.v += t.l;
    l -= t.v - b; b = t.v;
  }
}

/*!
    \brief print all tags information from binary buffer (TLV structured) (for debug purposes)
    \param b pointer to binary buffer
    \param l binary buffer length
    \param n
*/
int priv_findr(const uchar xdata *b, int l,ushort tag,TLV *tlv) reentrant
{
  TLV t;
  while (tlv_parseTLV(b,l,&t) > 0)
  {
		if (t.t == tag)
			{ if (tlv!=NULL) memcpy((char*)tlv,(char*)(&t),sizeof(TLV)); return 1; }
    if (tlv_tag0(t.t) & TAG_CONSTR)
      if (priv_findr(t.v,t.l,tag,tlv)) return 1;
    t.v += t.l;
    l -= t.v - b; b = t.v;
  }
  return 0;
}

/*!
    \brief check consistency of binary buffer (TLV structured)
    \param b pointer to binary buffer to check
    \param l binary buffer length
    \return 0 - buffer is not consistent, 1 - buffer is consistent
*/
int tlv_check(const uchar xdata *b, int l) reentrant
{
  int i;
  TLV t;
  while ((i=tlv_parseTLV(b,l,&t)) > 0)
  {
    if (tlv_tag0(t.t) & TAG_CONSTR)
    {
      if (!tlv_check(t.v,t.l)) return 0;
    }
    t.v += t.l;
    l -= t.v - b; b = t.v;
  }
  return i==0;
}

/*!
    \brief find tag on TLVbuf buffer
    \param tb TLVbuf to search
    \param tag requested tag identifier
    \param tlv output tlvbuf to fill
    \return 1 on succes, else 0

    If tlv param is NULL, then this function doesn't copy any data to it.
*/
int tb_findr(TLVbuf xdata *tb,ushort tag,TLV *tlv)
{
	return priv_findr(tb->buf,tb->len,tag,tlv);
}

/*!
    \brief print all tags information from binary TLVbuf (for debug purposes)
    \param tb TLVbuf to print
*/
void tb_print(TLVbuf xdata *tb)
{
  priv_printtags(tb->buf,tb->len,0);
}

/*!
    \brief initialize fields of TLVbuf
    \param tb pointer to TLVbuf structure
    \param buf pointer to data buffer
    \param size data buffer length
*/
void tb_init(TLVbuf xdata *tb,uchar xdata *buf,ushort size)
{
	memset(tb,0,sizeof(TLVbuf));
	tb->buf=buf; tb->mlen=size;
}

/*!
    \brief allocate dynamic buffer to TLVbuf
    \param tb pointer to TLVbuf structure
    \param s buffer length
*/
void tb_alloc(TLVbuf xdata *tb,ushort s)
{
	memset(tb,0,sizeof(TLVbuf));
	tb->buf=(uchar*)malloc(s); tb->mlen=tb->buf?s:0;
}

#ifdef CONFIG_DEBUG_HEAP
/*!
    \brief free dynamic TLVbuf previously allocated with tb_alloc()
    \param tb pointer to TLVbuf structure
*/
#undef tb_free
void tb_free(TLVbuf xdata *tb,const char *f,unsigned ln)
{
	if (tb->buf) my_free(tb->buf,f,ln);
	memset(tb,0,sizeof(TLVbuf));
}
#else
void tb_free(TLVbuf xdata *tb)
{
	if (tb->buf) free(tb->buf);
	memset(tb,0,sizeof(TLVbuf));
}
#endif


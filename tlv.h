#ifndef __COMMON_TLV_H
#define __COMMON_TLV_H
/*!
  \file
  \author Krzysztof Dynowski
	\brief Manipulations on TLV tags (header)
*/

typedef unsigned short ushort;
typedef unsigned char uchar;

#define xdata
#define EXPORT
#define reentrant
#define DEBUG1(a)
#define DEBUG2(a)

#define castptr(type,ptr) ((type)(void*)ptr)

#define TAG_SEQ     0x1f /*!< \brief subsequence indicator tag byte for t[0] */
#define TAG_NEXT    0x80 /*!< \brief subsequence indicator tag byte for t[>0] */
#define TAG_CONSTR  0x20 /*!< \brief constructed tag */
#define LEN_BYTES   0x80 /*!< \brief length coded on l[0]&7F bytes */

/*!
   \struct TLV
   \brief Tag-Value-Length structure
*/
typedef struct
{
  ushort t;   /*!< \brief Tag ID (assume tag are max 2 bytes) */
  ushort l;   /*!< \brief Length of data (pointed by v) */
  uchar *v;   /*!< \brief Pointer to the value */
} TLV;

/*!
	\struct TLVbuf
	\brief TLV buffer - keep a number of TLVs
*/
typedef struct
{
  ushort mlen;        /*!< \brief max data length */
  ushort len;         /*!< \brief buffer data length */
  uchar xdata *buf;   /*!< \brief data buffer */
} TLVbuf;


/* on other systems must be compiled into project */
__BEGIN_DECLS
EXPORT int tlv_tag0(ushort tag);
EXPORT int tlv_tag(const uchar xdata *rbuf, int rlen, ushort xdata *tag);
EXPORT int tlv_tlv0(const uchar xdata *rbuf, int rlen, TLV xdata *tlv);
EXPORT int tlv_parseTLV(const uchar xdata *rbuf, int rlen, TLV xdata *tlv);
EXPORT int tlv_parseLTV(const uchar xdata *rbuf, int rlen, TLV xdata *tlv);
EXPORT int tlv_buildT(uchar xdata *rbuf, int rlen, ushort tag);
EXPORT int tlv_find(const uchar xdata *b, int l, ushort t, TLV xdata *tlv);
EXPORT int ltv_find(const uchar xdata *b, int l, ushort t, TLV xdata *tlv);
EXPORT int tlv_check(const uchar xdata *b, int l) reentrant;
EXPORT void tlv_print(TLV xdata *tlv);
EXPORT int tb_find(const TLVbuf xdata *tb, ushort t, TLV xdata *tlv);
EXPORT int tb_findr(TLVbuf xdata *tb,ushort tag,TLV *tlv) reentrant;
EXPORT int tb_add(TLVbuf xdata *tb, TLV xdata *tlv, uchar ovr);
EXPORT int tb_del(TLVbuf xdata *tb, ushort t);
EXPORT int tb_addbuf(TLVbuf xdata *tb,const uchar xdata *rbuf,int rlen,uchar ovr);
EXPORT void tb_addtags(TLVbuf *dst,TLVbuf *src,uchar *buf,ushort len);
EXPORT void tb_print(TLVbuf xdata *tb);
EXPORT void tb_init(TLVbuf xdata *tb,uchar xdata *buf,ushort size);
EXPORT void tb_alloc(TLVbuf xdata *tb,ushort size);
#ifdef CONFIG_DEBUG_HEAP
void tb_free(TLVbuf xdata *tb,const char *f,unsigned ln);
#define tb_free(tb) tb_free(tb,__FILE__,__LINE__)
#else
EXPORT void tb_free(TLVbuf xdata *tb);
#endif
__END_DECLS

#define tlv_init(tlv,xt,xl,xv) (tlv)->t=(xt),(tlv)->v=(uchar*)(xv),(tlv)->l=(xl)

#endif

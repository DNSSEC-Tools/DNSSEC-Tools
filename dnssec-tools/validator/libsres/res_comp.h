
#ifndef _RES_COMP_H_
#define _RES_COMP_H_

int
dn_comp(const char *src, u_char * dst, int dstsiz,
        u_char ** dnptrs, u_char ** lastdnptr);

int
dn_skipname(const u_char * ptr, const u_char * eom);

int
dn_expand(const u_char * msg, const u_char * eom, const u_char * src,
          char *dst, int dstsiz);

#endif

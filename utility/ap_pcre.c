/*************************************************
 *      Perl-Compatible Regular Expressions       *
 *************************************************/

/*
 This is a library of functions to support regular expressions whose syntax
 and semantics are as close as possible to those of the Perl 5 language. See
 the file Tech.Notes for some information on the internals.

 This module is a wrapper that provides a POSIX API to the underlying PCRE
 functions.

 Written by: Philip Hazel <ph10@cam.ac.uk>

 Copyright (c) 1997-2004 University of Cambridge

 -----------------------------------------------------------------------------
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 * Neither the name of the University of Cambridge nor the names of its
 contributors may be used to endorse or promote products derived from
 this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
 -----------------------------------------------------------------------------
 */

#include "apr_lib.h"
#include "apr_strings.h"
#include "ap_pcre.h"
#include "pcre.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif

/* Table of error strings corresponding to POSIX error codes; must be
 * kept in synch with include/ap_regex.h's AP_REG_E* definitions. */

static const char *const pstring[] = {
    "", /* Dummy for value 0 */
    "internal error", /* AP_REG_ASSERT */
    "failed to get memory", /* AP_REG_ESPACE */
    "bad argument", /* AP_REG_INVARG */
    "match failed" /* AP_REG_NOMATCH */
};

apr_size_t ap_regerror(int errcode, const ap_regex_t *preg, char *errbuf,
        apr_size_t errbuf_size)
{
    const char *message, *addmessage;
    apr_size_t length, addlength;

    message
            = (errcode >= (int)(sizeof(pstring)/sizeof(char *))) ? "unknown error code"
                    : pstring[errcode];
    length = strlen(message) + 1;

    addmessage = " at offset ";
    addlength
            = (preg != NULL && (int)preg->re_erroffset != -1) ? strlen(addmessage)
                    + 6
                    : 0;

    if (errbuf_size > 0) {
        if (addlength > 0 && errbuf_size >= length + addlength)
            apr_snprintf(errbuf, sizeof errbuf, "%s%s%-6d", message,
                    addmessage, (int)preg->re_erroffset);
        else {
            strncpy(errbuf, message, errbuf_size - 1);
            errbuf[errbuf_size-1] = 0;
        }
    }

    return length + addlength;
}

/*************************************************
 *           Free store held by a regex           *
 *************************************************/

void ap_regfree(ap_regex_t *preg)
{
    (pcre_free)(preg->re_pcre);
}

/*************************************************
 *            Compile a regular expression        *
 *************************************************/

/*
 Arguments:
 preg        points to a structure for recording the compiled expression
 pattern     the pattern to compile
 cflags      compilation flags

 Returns:      0 on success
 various non-zero codes on failure
 */

int ap_regcomp(ap_regex_t *preg, const char *pattern, int cflags)
{
    const char *errorptr;
    int erroffset;
    int options = 0;

    if ((cflags & AP_REG_ICASE) != 0)
        options |= PCRE_CASELESS;
    if ((cflags & AP_REG_NEWLINE) != 0)
        options |= PCRE_MULTILINE;

    preg->re_pcre = pcre_compile(pattern, options, &errorptr, &erroffset, NULL);
    preg->re_erroffset = erroffset;

    if (preg->re_pcre == NULL)
        return AP_REG_INVARG;

    preg->re_nsub = pcre_info((const pcre *)preg->re_pcre, NULL, NULL);
    return 0;
}

/*************************************************
 *              Match a regular expression        *
 *************************************************/

/* Unfortunately, PCRE requires 3 ints of working space for each captured
 substring, so we have to get and release working store instead of just using
 the POSIX structures as was done in earlier releases when PCRE needed only 2
 ints. However, if the number of possible capturing brackets is small, use a
 block of store on the stack, to reduce the use of malloc/free. The threshold is
 in a macro that can be changed at configure time. */

int ap_regexec(const ap_regex_t *preg, const char *string, apr_size_t nmatch,
        ap_regmatch_t pmatch[], int eflags)
{
    int rc;
    int options = 0;
    int *ovector= NULL;
    int small_ovector[POSIX_MALLOC_THRESHOLD * 3];
    int allocated_ovector = 0;

    if ((eflags & AP_REG_NOTBOL) != 0)
        options |= PCRE_NOTBOL;
    if ((eflags & AP_REG_NOTEOL) != 0)
        options |= PCRE_NOTEOL;

    ((ap_regex_t *)preg)->re_erroffset = (apr_size_t)(-1); /* Only has meaning after compile */

    if (nmatch > 0) {
        if (nmatch <= POSIX_MALLOC_THRESHOLD) {
            ovector = &(small_ovector[0]);
        } else {
            ovector = (int *)malloc(sizeof(int) * nmatch * 3);
            if (ovector == NULL)
                return AP_REG_ESPACE;
            allocated_ovector = 1;
        }
    }

    rc = pcre_exec((const pcre *)preg->re_pcre, NULL, string,
            (int)strlen(string), 0, options, ovector, nmatch * 3);

    if (rc == 0)
        rc = nmatch; /* All captured slots were filled in */

    if (rc >= 0) {
        apr_size_t i;
        for (i = 0; i < (apr_size_t)rc; i++) {
            pmatch[i].rm_so = ovector[i*2];
            pmatch[i].rm_eo = ovector[i*2+1];
        }
        if (allocated_ovector)
            free(ovector);
        for (; i < nmatch; i++)
            pmatch[i].rm_so = pmatch[i].rm_eo = -1;
        return 0;
    }

    else {
        if (allocated_ovector)
            free(ovector);
        switch (rc) {
        case PCRE_ERROR_NOMATCH:
            return AP_REG_NOMATCH;
        case PCRE_ERROR_NULL:
            return AP_REG_INVARG;
        case PCRE_ERROR_BADOPTION:
            return AP_REG_INVARG;
        case PCRE_ERROR_BADMAGIC:
            return AP_REG_INVARG;
        case PCRE_ERROR_UNKNOWN_NODE:
            return AP_REG_ASSERT;
        case PCRE_ERROR_NOMEMORY:
            return AP_REG_ESPACE;
#ifdef PCRE_ERROR_MATCHLIMIT
            case PCRE_ERROR_MATCHLIMIT: return AP_REG_ESPACE;
#endif
#ifdef PCRE_ERROR_BADUTF8
            case PCRE_ERROR_BADUTF8: return AP_REG_INVARG;
#endif
#ifdef PCRE_ERROR_BADUTF8_OFFSET
            case PCRE_ERROR_BADUTF8_OFFSET: return AP_REG_INVARG;
#endif
        default:
            return AP_REG_ASSERT;
        }
    }
}

/*
 * Here's a pool-based interface to the POSIX-esque ap_regcomp().
 * Note that we return ap_regex_t instead of being passed one.
 * The reason is that if you use an already-used ap_regex_t structure,
 * the memory that you've already allocated gets forgotten, and
 * regfree() doesn't clear it. So we don't allow it.
 */

static apr_status_t regex_cleanup(void *preg)
{
    ap_regfree((ap_regex_t *) preg);
    return APR_SUCCESS;
}

ap_regex_t *ap_pregcomp(apr_pool_t *p, const char *pattern, int cflags)
{
    ap_regex_t *preg = apr_palloc(p, sizeof *preg);

    if (ap_regcomp(preg, pattern, cflags)) {
        return NULL;
    }

    apr_pool_cleanup_register(p, (void *) preg, regex_cleanup,
            apr_pool_cleanup_null);

    return preg;
}

void ap_pregfree(apr_pool_t *p, ap_regex_t *reg)
{
    ap_regfree(reg);
    apr_pool_cleanup_kill(p, (void *) reg, regex_cleanup);
}

/* This function substitutes for $0-$9, filling in regular expression
 * submatches. Pass it the same nmatch and pmatch arguments that you
 * passed ap_regexec(). pmatch should not be greater than the maximum number
 * of subexpressions - i.e. one more than the re_nsub member of ap_regex_t.
 *
 * input should be the string with the $-expressions, source should be the
 * string that was matched against.
 *
 * It returns the substituted string, or NULL on error.
 *
 * Parts of this code are based on Henry Spencer's regsub(), from his
 * AT&T V8 regexp package.
 */

char * ap_pregsub(apr_pool_t *p, const char *input, const char *source,
        size_t nmatch, ap_regmatch_t pmatch[])
{
    const char *src = input;
    char *dest, *dst;
    char c;
    size_t no;
    int len;

    if (!source)
        return NULL;
    if (!nmatch)
        return apr_pstrdup(p, src);

    /* First pass, find the size */

    len = 0;

    while ((c = *src++) != '\0') {
        if (c == '&')
            no = 0;
        else if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else
            no = 10;

        if (no> 9) { /* Ordinary character. */
            if (c == '\\' && (*src == '$' || *src == '&'))
                c = *src++;
            len++;
        } else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            len += pmatch[no].rm_eo - pmatch[no].rm_so;
        }

    }

    dest = dst = apr_pcalloc(p, len + 1);

    /* Now actually fill in the string */

    src = input;

    while ((c = *src++) != '\0') {
        if (c == '&')
            no = 0;
        else if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else
            no = 10;

        if (no> 9) { /* Ordinary character. */
            if (c == '\\' && (*src == '$' || *src == '&'))
                c = *src++;
            *dst++ = c;
        } else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            len = pmatch[no].rm_eo - pmatch[no].rm_so;
            memcpy(dst, source + pmatch[no].rm_so, len);
            dst += len;
        }

    }
    *dst = '\0';

    return dest;
}
/* End of pcreposix.c */

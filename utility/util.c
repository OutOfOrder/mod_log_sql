#include "util.h"
#include "apr_strings.h"
#include "apr_lib.h"


char *lowerstr(apr_pool_t *pool, const char *input)
{
    char *temp;
    char *itr;
    temp = apr_pstrdup(pool, input);
    for (itr=temp; *itr!='\0'; itr++) {
        *itr = apr_tolower(*itr);
    }
    return temp;
}

void line_chomp(char *str)
{
    int len;
    // chomp off newline
    len = strlen(str);
    if (len) {
        while (str[len-1] == '\r' || str[len-1] == '\n') {
            str[len-1] = '\0';
            len--;
        }
    }
}

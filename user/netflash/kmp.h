#ifndef KMP_H
#define KMP_H

/* Implementation of the Knuth-Morris-Pratt fast searching algorithm
 * from http://www-igm.univ-mlv.fr/~lecroq/string/node8.html
 */

typedef int getchar_function(void *cookie);

/**
 * Currently we don't support search strings greater than
 * this length.
 */
#define MAX_SEARCH_SIZE 256

/**
 * Searches for an exact string match for 'x' of length 'm' in a stream
 * Using the Knuth-Morris-Pratt algorith.
 *
 * 'getter' returns one character at a time from the stream
 * and EOF at end of file. 'cookie' is passed to 'getter'.
 *
 * If a match is found, returns the offset character JUST PAST THE END OF THE MATCH.
 * e.g. KMP("abc", "xxabcyy") will return 5.
 * The input stream will be read to this point.
 *
 * Returns -1 if the string is not found.
 */
int KMP(const char *x, int m, getchar_function *getter, void *cookie);

/**
 * Useful getter function for searching a null terminated string.
 * 'cookie' should be a pointer to a pointer to the start of the string.
 * This pointer is updated as the string is searched.
 */
int getter_string(void *cookie);

/**
 * A getter for a buffered file.
 * 
 * 'cookie' is a (FILE *)
 */
int getter_file(void *cookie);

/**
 * A getter for a file descriptor
 * 
 * 'cookie' is a file descriptor
 */
int getter_fd(void *cookie);

#endif

#ifndef _DEBUG_H_
#define _DEBUG_H_


#define debug(level, format...) _debug(__FILE__, __LINE__, level, format)


void _debug(char *filename, int line, int level, char *format, ...);

#endif /* _DEBUG_H_ */

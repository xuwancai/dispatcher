#ifndef _DIS_COMMON_H
#define _DIS_COMMON_H

#ifndef unlikely
#define unlikely(_x) _x
#define likely(_x) _x
#endif

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y; })

#endif

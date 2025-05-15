#ifndef __M_UTIL_INCLUDED__
#define __M_UTIL_INCLUDED__

//DISABLE_COPY macro
#ifndef DISABLE_COPY
#define DISABLE_COPY(T)                                                                         \
                        explicit T(const T&) = delete;                                  \
                        T& operator=(const T&) = delete;
#endif

//DISABLE_MOVE macro
#ifndef DISABLE_MOVE
#define DISABLE_MOVE(T)                                                                         \
                        explicit T(T&&) = delete;                                               \
                        T& operator=(T&&) = delete;
#endif

//DISABLE_COPY_AND_MOVE macro
#ifndef DISABLE_COPY_AND_MOVE
#define DISABLE_COPY_AND_MOVE(T) DISABLE_COPY(T) DISABLE_MOVE(T)
#endif

#endif
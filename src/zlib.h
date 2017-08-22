//
//  zlib.h
//  Part of Mine crypto library
//
//  You should not use this file, use include/mine.h
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright 2017 Muflihun Labs
//
//  https://github.com/muflihun/mine
//

#ifdef MINE_CRYPTO_H
#   error "Please use mine.h file. this file is only to aid the development"
#endif

#ifndef ZLib_H
#define ZLib_H

namespace mine {

///
/// \brief Provides Zlib functionality for inflate and deflate
///
class ZLib {
public:

private:
    ZLib() = delete;
    ZLib(const ZLib&) = delete;
    ZLib& operator=(const ZLib&) = delete;
};
} // end namespace mine

#endif // ZLib_H

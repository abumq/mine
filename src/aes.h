//
//  aes.h
//  Part of Mine crypto library
//
//  You should not use this file, use include/mine.h
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright (c) 2017 Muflihun Labs
//
//  This library is released under the Apache 2.0 license
//  https://github.com/muflihun/mine/blob/master/LICENSE
//
//  https://github.com/muflihun/mine
//

#ifdef MINE_CRYPTO_H
#   error "Please use mine.h file. this file is only to aid the development"
#endif

#ifndef AES_H
#define AES_H

namespace mine {

///
/// \brief Provides AES crypto functionalities
///
class AES {
public:

private:
    AES() = delete;
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;
};
} // end namespace mine

#endif // AES_H

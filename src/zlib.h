//
//  zlib.h
//  Part of Mine crypto library
//
//  You should not use this file, use mine.h
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright (c) 2017-2018 Muflihun Labs
//
//  This library is released under the Apache 2.0 license
//  https://github.com/muflihun/mine/blob/master/LICENSE
//
//  https://github.com/muflihun/mine
//

#ifdef MINE_CRYPTO_H
#   error "Please use mine.h file. this file is only to aid the development"
#endif

#include <string>

#ifndef ZLib_H
#define ZLib_H

namespace mine {

///
/// \brief Provides Zlib functionality for inflate and deflate
///
class ZLib {
public:

    ///
    /// \brief Size of buffer algorithm should operate under
    ///
    static const int kBufferSize = 32768;

    ///
    /// \brief Compress input file (path) and create new file
    /// \param gzFilename Output file path
    /// \param inputFile Input file path
    /// \return True if successful, otherwise false
    ///
    static bool compressFile(const std::string& gzFilename, const std::string& inputFile);

    ///
    /// @brief Compresses string using zlib (inflate)
    /// @param str Input plain text
    /// @return Raw output (binary)
    ///
    static std::string compressString(const std::string& str);

    ///
    /// @brief Decompresses string using zlib (deflate)
    /// @param str Raw input
    /// @return Plain output
    ///
    static std::string decompressString(const std::string& str);
private:
    ZLib() = delete;
    ZLib(const ZLib&) = delete;
    ZLib& operator=(const ZLib&) = delete;
};
} // end namespace mine

#endif // ZLib_H

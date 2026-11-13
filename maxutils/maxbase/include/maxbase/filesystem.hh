/*
 * Copyright (c) 2018 MariaDB Corporation Ab
 * Copyright (c) 2023 MariaDB plc, Finnish Branch
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2027-04-10
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#pragma once

#include <maxbase/ccdefs.hh>
#include <maxbase/format.hh>
#include <maxbase/string.hh>

#include <fstream>
#include <filesystem>
#include <sys/types.h>

namespace maxbase
{

struct SecureFileResult
{
    enum class Status
    {
        SUCCESS,
        NOT_FOUND,
        ERROR
    };

    Status      status {Status::ERROR};
    std::string contents;
    std::string error;
};

/**
 * Securely load a file from disk.
 *
 * The file is opened without following a leaf symlink, validated as a regular
 * file owned by the current effective user and group, repaired to the requested
 * mode through the open descriptor, and read through that same descriptor.
 *
 * @param file The path to load
 * @param mode The exact permissions to apply before reading
 *
 * @return The file status, contents on success, and an error on failure
 */
SecureFileResult load_file_secure(const std::string& file, mode_t mode);

/**
 * Load a file from disk
 *
 * @param file The path to the file to load
 *
 * @return The file contents if the file was loaded successfully or an error message if it wasn't
 */
template<class Container>
std::pair<Container, std::string> load_file(const std::string& file)
{
    static_assert(sizeof(typename Container::iterator::value_type) == sizeof(char));
    std::string err;
    Container data;
    std::error_code ec{};
    std::uintmax_t size = std::filesystem::file_size(file, ec);
    std::ifstream infile(file, std::ios_base::binary);

    if (size == static_cast<std::uintmax_t>(-1))
    {
        err = mxb::string_printf("Failed to get length of file '%s': %d, %s",
                                 file.c_str(), ec.value(), ec.message().c_str());
    }
    else if (infile)
    {
        data.resize(size);

        if (!infile.read(reinterpret_cast<char*>(data.data()), data.size()))
        {
            err = mxb::string_printf("Failed to read from file '%s': %d, %s",
                                     file.c_str(), errno, mxb_strerror(errno));
            data.clear();
        }
    }
    else
    {
        err = mxb::string_printf("Failed to open file '%s': %d, %s",
                                 file.c_str(), errno, mxb_strerror(errno));
    }

    return {std::move(data), std::move(err)};
}

/**
 * Atomically save a file on disk
 *
 * The atomicity is achieved by writing out the data into a temporary file and then renaming it.
 *
 * @param file The path where the file is saved
 * @param ptr  Pointer to data
 * @param size Size of the data
 *
 * @return An empty string if the file was saved successfully or an error message if it wasn't
 */
std::string save_file(std::string file, const void* ptr, size_t size);

/**
 * Atomically save a file on disk with explicit file permissions.
 *
 * @param file The path where the file is saved
 * @param ptr  Pointer to data
 * @param size Size of the data
 * @param mode File permissions to set
 *
 * @return An empty string if the file was saved successfully or an error message if it wasn't
 */
std::string save_file(std::string file, const void* ptr, size_t size, mode_t mode);

inline std::string save_file(std::string file, const std::string& str)
{
    return save_file(file, str.data(), str.size());
}

inline std::string save_file(std::string file, const std::string& str, mode_t mode)
{
    return save_file(file, str.data(), str.size(), mode);
}
}

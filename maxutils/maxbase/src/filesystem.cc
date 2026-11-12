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

#include <maxbase/filesystem.hh>

#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

namespace maxbase
{

SecureFileResult load_file_secure(const std::string& file, mode_t mode)
{
    SecureFileResult rval;
    int fd = open(file.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);

    if (fd == -1)
    {
        if (errno == ENOENT)
        {
            rval.status = SecureFileResult::Status::NOT_FOUND;
        }
        else
        {
            rval.error = mxb::string_printf("Failed to securely open file '%s': %d, %s",
                                            file.c_str(), errno, mxb_strerror(errno));
        }
        return rval;
    }

    struct stat file_info;
    if (fstat(fd, &file_info) != 0)
    {
        rval.error = mxb::string_printf("Failed to inspect file '%s': %d, %s",
                                        file.c_str(), errno, mxb_strerror(errno));
    }
    else if (!S_ISREG(file_info.st_mode))
    {
        rval.error = mxb::string_printf("File '%s' is not a regular file", file.c_str());
    }
    else if (file_info.st_uid != geteuid() || file_info.st_gid != getegid())
    {
        rval.error = mxb::string_printf(
            "File '%s' has unexpected ownership %u:%u, expected %u:%u",
            file.c_str(), file_info.st_uid, file_info.st_gid, geteuid(), getegid());
    }
    else if (fchmod(fd, mode) != 0)
    {
        rval.error = mxb::string_printf("Failed to set file permissions for '%s': %d, %s",
                                        file.c_str(), errno, mxb_strerror(errno));
    }
    else
    {
        if (file_info.st_size > 0)
        {
            rval.contents.reserve(file_info.st_size);
        }

        char buffer[4096];
        ssize_t nread = 0;
        while ((nread = read(fd, buffer, sizeof(buffer))) != 0)
        {
            if (nread > 0)
            {
                rval.contents.append(buffer, nread);
            }
            else if (errno != EINTR)
            {
                break;
            }
        }

        if (nread == 0)
        {
            rval.status = SecureFileResult::Status::SUCCESS;
        }
        else
        {
            rval.contents.clear();
            rval.error = mxb::string_printf("Failed to read file '%s': %d, %s",
                                            file.c_str(), errno, mxb_strerror(errno));
        }
    }

    close(fd);
    return rval;
}

std::string save_file(std::string file, const void* ptr, size_t size)
{
    return save_file(std::move(file), ptr, size, 0644);
}

std::string save_file(std::string file, const void* ptr, size_t size, mode_t mode)
{
    std::string err;
    std::string tmp = file + "XXXXXX";
    int fd = mkstemp(tmp.data());

    if (fd == -1)
    {
        err = mxb::string_printf("Failed to open temporary file '%s': %d, %s",
                                 tmp.c_str(), errno, mxb_strerror(errno));
    }
    else
    {
        if (write(fd, ptr, size) == -1)
        {
            err = mxb::string_printf("Write to file '%s' failed: %d, %s",
                                     tmp.c_str(), errno, mxb_strerror(errno));
        }
        else if (fchmod(fd, mode) == -1)
        {
            err = mxb::string_printf("Failed to set file permissions for file '%s': %d, %s",
                                     tmp.c_str(), errno, mxb_strerror(errno));
        }
        else if (rename(tmp.c_str(), file.c_str()) == -1)
        {
            err = mxb::string_printf("Failed to rename '%s' to '%s': %d, %s",
                                     tmp.c_str(), file.c_str(), errno, mxb_strerror(errno));
        }

        close(fd);

        if (!err.empty())
        {
            // Remove the temporary file in case we failed to write to it.
            remove(tmp.c_str());
        }
    }

    return err;
}
}

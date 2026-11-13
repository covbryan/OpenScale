/*
 * Copyright (c) 2016 MariaDB Corporation Ab
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

// To ensure that ss_info_assert asserts also when building in non-debug mode.
#if !defined (SS_DEBUG)
#define SS_DEBUG
#endif
#if defined (NDEBUG)
#undef NDEBUG
#endif

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>

#include <maxbase/log.hh>
#include <maxscale/paths.hh>
#include <maxscale/users.hh>
#include "../internal/adminusers.hh"

using mxs::USER_ACCOUNT_UNKNOWN;

namespace
{
int expect(bool condition, const char* message)
{
    if (!condition)
    {
        fprintf(stderr, "%s\n", message);
        return 1;
    }
    return 0;
}

bool default_login_works()
{
    return admin_verify_inet_user("admin", "mariadb") != USER_ACCOUNT_UNKNOWN;
}
}

int main(int argc, char** argv)
{
    mxs::Config::init(argc, argv);

    if (!mxb_log_init(MXB_LOG_TARGET_STDERR))
    {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }

    char test_dir[] = "/tmp/openscale-adminusers-XXXXXX";
    if (!mkdtemp(test_dir))
    {
        perror("mkdtemp");
        return 1;
    }

    mxs::set_datadir(test_dir);
    std::string passwd = std::string(test_dir) + "/passwd";
    std::string target = std::string(test_dir) + "/passwd-target";
    int result = 0;

    // A genuinely missing password file enables and persists the initial default.
    rest_users_init();
    result += expect(default_login_works(), "Default administrator was not created for missing state");

    struct stat info;
    result += expect(stat(passwd.c_str(), &info) == 0 && (info.st_mode & 0777) == 0600,
                     "Administrator password file was not created with mode 0600");

    // Existing weak permissions are repaired while loading the same file descriptor.
    chmod(passwd.c_str(), 0644);
    rest_users_init();
    result += expect(default_login_works(), "Valid administrator state failed to load");
    result += expect(stat(passwd.c_str(), &info) == 0 && (info.st_mode & 0777) == 0600,
                     "Weak administrator password-file permissions were not repaired");

    // An unsafe existing path must never be treated as missing default state.
    rename(passwd.c_str(), target.c_str());
    symlink(target.c_str(), passwd.c_str());
    rest_users_init();
    result += expect(!default_login_works(), "Symlinked administrator state enabled default credentials");

    unlink(passwd.c_str());
    mkdir(passwd.c_str(), 0700);
    rest_users_init();
    result += expect(!default_login_works(), "Non-file administrator state enabled default credentials");

    std::filesystem::remove_all(test_dir);
    mxb_log_finish();
    return result;
}

/*
 * Copyright (c) 2026 OpenScale contributors
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

#include "../mariadbmon.hh"

#include <array>
#include <iostream>
#include <string>

#include <maxbase/maxbase.hh>
#include <maxscale/mainworker.hh>

#include "../../../../core/test/test_utils.hh"

using std::cout;

class MariaDBMonitor::Test : public Monitor::Test
{
public:
    Test()
        : Monitor::Test(new MariaDBMonitor("TestMonitor", MXB_MODULE_NAME))
    {
    }

    int run_tests()
    {
        int errors = 0;

        errors += test_auto_failover_values();
        errors += test_missing_relay_log_events();

        return errors;
    }

private:
    MariaDBMonitor* monitor() const
    {
        return static_cast<MariaDBMonitor*>(m_monitor.get());
    }

    int test_auto_failover_values()
    {
        using Entry = std::pair<const char*, AutoFailover>;
        const std::array<Entry, 9> entries {{
            {"false", AutoFailover::NONE},
            {"off", AutoFailover::NONE},
            {"no", AutoFailover::NONE},
            {"0", AutoFailover::NONE},
            {"safe", AutoFailover::SAFE},
            {"true", AutoFailover::ALLOW_TRX_LOSS},
            {"on", AutoFailover::ALLOW_TRX_LOSS},
            {"yes", AutoFailover::ALLOW_TRX_LOSS},
            {"1", AutoFailover::ALLOW_TRX_LOSS},
        }};

        int errors = 0;
        for (const auto& entry : entries)
        {
            mxs::ConfigParameters params;
            params.set(CN_AUTO_FAILOVER, entry.first);

            if (!monitor()->m_settings.specification().validate(params))
            {
                cout << "Validation failed for auto_failover=" << entry.first << '\n';
                ++errors;
            }
            else if (!monitor()->m_settings.configure(params))
            {
                cout << "Configuration failed for auto_failover=" << entry.first << '\n';
                ++errors;
            }
            else if (monitor()->m_settings.auto_failover != entry.second)
            {
                cout << "Incorrect value for auto_failover=" << entry.first << '\n';
                ++errors;
            }
        }

        return errors;
    }

    int test_missing_relay_log_events()
    {
        int errors = 0;

        auto expect = [&errors](bool expected, const char* relay, const char* primary) {
            const auto relay_pos = GtidList::from_string(relay);
            const auto primary_pos = GtidList::from_string(primary);
            const bool actual = MariaDBServer::relay_log_missing_events(relay_pos, primary_pos);

            if (actual != expected)
            {
                cout << "Expected relay position '" << relay << "' to "
                     << (expected ? "miss" : "contain") << " primary position '" << primary << "'\n";
                ++errors;
            }
        };

        expect(false, "0-2-10", "0-1-10");
        expect(false, "0-2-11", "0-1-10");
        expect(true, "0-2-9", "0-1-10");
        expect(true, "0-2-10", "0-1-10,1-1-3");

        return errors;
    }
};

int main()
{
    int errors = 0;
    run_unit_test([&errors]() {
        MariaDBMonitor::Test test;
        errors = test.run_tests();
    });
    return errors;
}

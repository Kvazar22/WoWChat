/*
 * Copyright (C) 2008-2011 TrinityCore <http://www.trinitycore.org/>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/** \file
    \ingroup Trinityd
 */

#include "Common.h"
#include "Config.h"
#include "Log.h"
#include "SocketConnectorRunnable.h"
#include "World.h"

#include <ace/Reactor_Impl.h>
#include <ace/TP_Reactor.h>
#include <ace/Dev_Poll_Reactor.h>
#include <ace/Acceptor.h>
#include <ace/SOCK_Acceptor.h>

#include "SocketConnector.h"

SocketConnectorRunnable::SocketConnectorRunnable() : m_Reactor(NULL)
{
    ACE_Reactor_Impl* imp = 0;

#if defined (ACE_HAS_EVENT_POLL) || defined (ACE_HAS_DEV_POLL)

    imp = new ACE_Dev_Poll_Reactor();

    imp->max_notify_iterations (128);
    imp->restart (1);

#else

    imp = new ACE_TP_Reactor();
    imp->max_notify_iterations (128);

#endif

    m_Reactor = new ACE_Reactor (imp, 1);
}

SocketConnectorRunnable::~SocketConnectorRunnable()
{
    delete m_Reactor;
}

void SocketConnectorRunnable::run()
{
    if (!ConfigMgr::GetBoolDefault("SocketConnector.Enable", false))
        return;
    
    ACE_Acceptor<SocketConnector, ACE_SOCK_ACCEPTOR> acceptor;

    uint16 SocketConnectorPort = ConfigMgr::GetIntDefault("SocketConnector.Port", 3448);
    std::string stringip = ConfigMgr::GetStringDefault("SocketConnector.IP", "0.0.0.0");

    ACE_INET_Addr listen_addr(SocketConnectorPort, stringip.c_str());

    if (acceptor.open(listen_addr, m_Reactor) == -1)
    {
        sLog->outError(LOG_FILTER_WORLDSERVER, "Trinity Socket Connector can not bind to port %d on %s", SocketConnectorPort, stringip.c_str());
        return;
    }

    sLog->outInfo(LOG_FILTER_WORLDSERVER, "Starting Trinity Socket Connector on port %d on %s", SocketConnectorPort, stringip.c_str());

    while (!World::IsStopped())
    {
        // don't be too smart to move this outside the loop
        // the run_reactor_event_loop will modify interval
        ACE_Time_Value interval(0, 100000);

        if (m_Reactor->run_reactor_event_loop(interval) == -1)
            break;
    }

    sLog->outDebug(LOG_FILTER_WORLDSERVER, "Trinity Socket Connector thread exiting");
}

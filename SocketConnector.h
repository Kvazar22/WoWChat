/*
 * Copyright (C) 2008-2011 TrinityCore <http://www.trinitycore.org/>
 * Copyright (C) 2005-2009 MaNGOS <http://getmangos.com/>
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

/// \addtogroup Trinityd
/// @{
/// \file

#ifndef _SocketConnector_H
#define _SocketConnector_H

#include "Common.h"
#include "Player.h"

#include <ace/Synch_Traits.h>
#include <ace/Svc_Handler.h>
#include <ace/SOCK_Stream.h>
#include <ace/SOCK_Acceptor.h>
#include <map>
#include <list>


/// Remote chat socket
class SocketConnector: public ACE_Svc_Handler<ACE_SOCK_STREAM, ACE_MT_SYNCH>
{
    public:
        SocketConnector();
        virtual ~SocketConnector();

        virtual int svc(void);
        virtual int open(void * = 0);
        virtual int handle_close(ACE_HANDLE = ACE_INVALID_HANDLE, ACE_Reactor_Mask = ACE_Event_Handler::ALL_EVENTS_MASK);
        int sendMessage(const std::string& message);
        int send(const std::string& line);
        
        typedef std::list<SocketConnector*> Connections;
        static Connections *connections;

        std::string playerName;
        uint64 accountGuid;
        uint64 playerGuid;
        uint32 guildGuid;
        uint8 playerFaction;

    private:
        int recv_line(std::string& out_line);
        int recv_line(ACE_Message_Block& buffer);
        int authenticate();
        int fill_user_data(const std::string& user);
        int check_password(const std::string& user, const std::string& pass);
        int get_characters();
        int select_character();
        int sendToLFG(const std::string& message);
        int sendToPlayer(const std::string& message, std::string& receiverName);
        int sendToGuild(const std::string& message);
        typedef std::map<std::wstring, Channel*> ChannelMap;

    private:
};
#endif
/// @}
